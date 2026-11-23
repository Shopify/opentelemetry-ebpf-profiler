// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package heap implements a probe that discovers and attaches USDT heap
// profiling probes (alloc/free) on a per-process basis.
package heap // import "go.opentelemetry.io/ebpf-profiler/probes/heap"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/ebpf-profiler/usdt"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const (
	heapProbeProvider = "otel_memory"
	allocProgName     = "uprobe_heap_alloc"
	allocOriginVar    = "origin_id_heap_alloc"
	freeProgName      = "uprobe_heap_free"
	freeOriginVar     = "origin_id_heap_free"

	usdtSpecsMapName         = "usdt_specs"
	heapLivePidsMapName      = "heap_live_pids"
	heapPIDAllocCountMapName = "heap_pid_alloc_count"
	heapPIDAllocLimitMapName = "heap_pid_alloc_limit"
	heapAllocLiveMapName     = "heap_alloc_live"
)

// attachmentKey identifies one uprobe link within a single process. It is
// only unique within the per-PID attachments map and must not be used as a
// global key. It uses the on-disk identity rather than FileID because the
// kernel registers uprobes against an inode and file offset: separate inodes
// with identical contents share a FileID but each needs its own link.
type attachmentKey struct {
	odfi   util.OnDiskFileIdentifier
	name   string
	offset uint64
}

func attachmentKeyFor(mapping *process.RawMapping, name string, offset uint64) attachmentKey {
	return attachmentKey{
		odfi:   mapping.GetOnDiskFileIdentifier(),
		name:   name,
		offset: offset,
	}
}

type attachment struct {
	lnk       io.Closer
	specKeys  map[support.USDTSpecKey]libpf.Void
	detaching bool
}

// heapAllocKey mirrors the eBPF HeapAllocKey struct used as the key for
// the heap_alloc_live map.
type heapAllocKey struct {
	PID uint32
	_   uint32 // padding
	Ptr uint64
}

// Probe implements tracer.Probe, tracer.TraceHandlerHooks,
// samples.SnapshotSource, and processmanager.ProbeAttacher for USDT heap profiling.
type Probe struct {
	cfg         Config
	discoverer  *usdt.Discoverer
	programs    map[string]*cebpf.Program
	tracker     *Tracker
	processMeta func(libpf.PID) (process.Meta, attribute.Set)

	usdtSpecs         *cebpf.Map
	heapLivePids      *cebpf.Map
	heapAllocLive     *cebpf.Map
	heapPIDAllocCount *cebpf.Map
	heapPIDAllocLimit *cebpf.Map

	mu          sync.Mutex
	unloaded    bool
	attachments map[libpf.PID]map[attachmentKey]*attachment

	// originAlloc and originFree are the dynamically-assigned origin IDs.
	originAlloc uint16
	originFree  uint16

	// pendingAlloc* fields are stashed by PreHandleTrace for alloc events
	// and consumed by PostHandleTrace after symbolization. Safe because
	// trace processing is single-goroutine.
	pendingAllocPID   libpf.PID
	pendingAllocPtr   uint64
	pendingAllocValue int64
}

var (
	_ tracer.Probe             = (*Probe)(nil)
	_ tracer.TraceHandlerHooks = (*Probe)(nil)
	_ samples.SnapshotSource   = (*Probe)(nil)
)

// New creates a heap probe.
func New(cfg Config) (*Probe, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Probe{
		cfg:         cfg,
		attachments: make(map[libpf.PID]map[attachmentKey]*attachment),
	}, nil
}

// probeVirtualAddress translates a file offset to its runtime virtual address.
// The boolean reports whether the offset is contained in mapping. An address
// that would overflow is treated as not contained.
func probeVirtualAddress(mapping *process.RawMapping, fileOffset uint64) (uint64, bool) {
	if fileOffset < mapping.FileOffset {
		return 0, false
	}
	delta := fileOffset - mapping.FileOffset
	if delta >= mapping.Length || mapping.Vaddr > math.MaxUint64-delta {
		return 0, false
	}
	return mapping.Vaddr + delta, true
}

// Derive an unbiased object-count estimator from the
// byte-weighted values. Each event carries:
//
//	weighted_bytes = unbiased byte estimate (see ADR 00003)
//	size           = raw allocation size in bytes
//
// Object count = weighted_bytes / size. This is the standard
// convention used by tcmalloc, jemalloc, and Go's pprof.
//
// We compute this in userspace rather than eBPF to keep the
// kernel/userspace interface simple, preserve the raw size
// for potential future use (e.g. allocation-size histograms),
// and avoid the eBPF program needing to transform values.
//
// Fall back to 1 if size is unknown/zero rather than
// dividing by zero.
func allocObjectsValue(weightedBytes int64, rawSize uint64) int64 {
	size := int64(rawSize)
	if size <= 0 {
		return 1
	}
	return max(weightedBytes/size, 1)
}

func appendAllocValues(dst []int64, meta *samples.TraceEventMeta) []int64 {
	var weightedBytes int64
	var size uint64
	if len(meta.ContextValues) > 0 {
		weightedBytes = int64(meta.ContextValues[0])
	}
	if len(meta.ContextValues) > 2 {
		size = meta.ContextValues[2]
	}
	return append(dst, weightedBytes, allocObjectsValue(weightedBytes, size))
}

// Load implements tracer.Probe. It loads the heap eBPF programs and creates
// the USDT discoverer used during per-process attachment.
func (hp *Probe) Load(_ context.Context, reg tracer.ProbeRegistrar,
	pctx *tracer.ProbeContext,
) (err error) {
	var hooks tracer.TraceHandlerHooks
	if hp.cfg.LiveHeapProfiling {
		hp.tracker = NewTracker()
		hooks = hp
	}

	// Register origin IDs. The eBPF programs read these from RODATA.
	hp.originAlloc, err = reg.Register(&tracer.OriginEntry{
		Meta: &samples.TypeMetadata{
			SampleTypes: []samples.SampleType{
				{Type: "alloc_space", Unit: "bytes"},
				{Type: "alloc_objects", Unit: "count"},
			},
			ReportValues: true,
			AppendValues: appendAllocValues,
		},
		Hooks: hooks,
	})
	if err != nil {
		return fmt.Errorf("registering heap alloc origin: %w", err)
	}

	progNames := []string{allocProgName}
	extraVars := []string{allocOriginVar}
	if hp.cfg.LiveHeapProfiling {
		hp.originFree, err = reg.Register(&tracer.OriginEntry{
			Meta: &samples.TypeMetadata{
				SampleTypes:  []samples.SampleType{{Type: "heap_free", Unit: "count"}},
				AppendValues: samples.AppendFirstContextValue,
			},
			Hooks: hooks,
		})
		if err != nil {
			return fmt.Errorf("registering heap free origin: %w", err)
		}
		progNames = append(progNames, freeProgName)
		extraVars = append(extraVars, freeOriginVar)
	}

	probeMapNames := []string{
		usdtSpecsMapName,
		heapLivePidsMapName,
		heapPIDAllocCountMapName,
		heapPIDAllocLimitMapName,
		heapAllocLiveMapName,
	}

	// Load eBPF programs via ProbeContext.
	coll, err := pctx.CollectionSpecWith(probeMapNames, progNames, extraVars)
	if err != nil {
		return fmt.Errorf("building collection spec: %w", err)
	}
	// Probe-owned maps bypass the tracer's normal map-size adaptation.
	coll.Maps[usdtSpecsMapName].MaxEntries <<= uint32(hp.cfg.MapScaleFactor)
	if !hp.cfg.LiveHeapProfiling {
		// uprobe_heap_alloc still references these maps; shrink them to 1 entry
		// when live-heap tracking is disabled so they consume negligible memory.
		coll.Maps[heapLivePidsMapName].MaxEntries = 1
		coll.Maps[heapPIDAllocCountMapName].MaxEntries = 1
		coll.Maps[heapAllocLiveMapName].MaxEntries = 1
	}

	// Set origin IDs in RODATA so the eBPF programs emit the correct values.
	if v, ok := coll.Variables[allocOriginVar]; ok {
		if err := v.Set(hp.originAlloc); err != nil {
			return fmt.Errorf("setting %s: %w", allocOriginVar, err)
		}
	}
	if hp.cfg.LiveHeapProfiling {
		if v, ok := coll.Variables[freeOriginVar]; ok {
			if err := v.Set(hp.originFree); err != nil {
				return fmt.Errorf("setting %s: %w", freeOriginVar, err)
			}
		}
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("adjusting memlock rlimit: %w", err)
	}
	defer restoreRlimit()

	probeMaps := make(map[string]*cebpf.Map, len(probeMapNames))
	ebpfProgs := make(map[string]*cebpf.Program)
	// Everything created from here on is owned by Load until it returns
	// successfully, so release it on any error.
	defer func() {
		if err == nil {
			return
		}
		hp.usdtSpecs = nil
		hp.heapLivePids = nil
		hp.heapAllocLive = nil
		hp.heapPIDAllocCount = nil
		hp.heapPIDAllocLimit = nil
		hp.programs = nil
		hp.discoverer = nil
		hp.tracker = nil
		for _, p := range ebpfProgs {
			_ = p.Close()
		}
		for _, m := range probeMaps {
			_ = m.Close()
		}
	}()

	for _, name := range probeMapNames {
		m, mapErr := cebpf.NewMap(coll.Maps[name])
		if mapErr != nil {
			err = fmt.Errorf("creating %s map: %w", name, mapErr)
			return err
		}
		probeMaps[name] = m
	}

	if err = pctx.RewriteMaps(coll, probeMaps); err != nil {
		return fmt.Errorf("rewriting maps: %w", err)
	}

	progs := make([]tracer.ProgLoaderHelper, 0, len(progNames))
	for _, name := range progNames {
		progs = append(progs, tracer.ProgLoaderHelper{
			Name:             name,
			NoTailCallTarget: true,
			Enable:           true,
		})
	}
	if err = pctx.LoadProbeUnwinders(coll, ebpfProgs, progs, 0); err != nil {
		return fmt.Errorf("loading heap eBPF programs: %w", err)
	}

	hp.programs = make(map[string]*cebpf.Program, len(ebpfProgs))
	if p, ok := ebpfProgs[allocProgName]; ok {
		hp.programs["alloc"] = p
	}
	if p, ok := ebpfProgs[freeProgName]; ok {
		hp.programs["free"] = p
	}
	hp.discoverer, err = usdt.NewDiscoverer()
	if err != nil {
		return fmt.Errorf("creating USDT discoverer: %w", err)
	}

	// Write the per-PID alloc limit into the eBPF array map so the
	// kernel-side code enforces the cap.
	if hp.cfg.LiveHeapProfiling && hp.cfg.LiveHeapMaxEntriesPerPID > 0 {
		key := uint32(0)
		val := uint32(hp.cfg.LiveHeapMaxEntriesPerPID)
		if putErr := probeMaps[heapPIDAllocLimitMapName].Put(key, val); putErr != nil {
			log.Warnf("heap probe: failed to set %s: %v", heapPIDAllocLimitMapName, putErr)
		}
	}

	hp.usdtSpecs = probeMaps[usdtSpecsMapName]
	hp.heapLivePids = probeMaps[heapLivePidsMapName]
	hp.heapAllocLive = probeMaps[heapAllocLiveMapName]
	hp.heapPIDAllocCount = probeMaps[heapPIDAllocCountMapName]
	hp.heapPIDAllocLimit = probeMaps[heapPIDAllocLimitMapName]
	hp.processMeta = pctx.ProcessMeta

	// Register for per-process callbacks via ProbeAttacher.
	if err = pctx.AddAttacher(hp); err != nil {
		return err
	}
	return nil
}

// Match implements processmanager.ProbeAttacher. The heap probe matches all
// executable mappings because USDT notes can be in any ELF binary.
func (hp *Probe) Match(_ process.Process, _ *process.RawMapping) bool {
	return true
}

// Attach implements processmanager.ProbeAttacher.
func (hp *Probe) Attach(pr process.Process, mapping *process.RawMapping,
	fileID libpf.FileID, elfRef *pfelf.Reference,
) error {
	pid := pr.PID()

	// Discover USDT attachment points in this mapping. The discoverer
	// caches results by backing-file identity so repeated calls for the
	// same binary are cheap.
	points, err := hp.discoverer.Discover(elfRef, fileID)
	if err != nil {
		if len(points) == 0 {
			return fmt.Errorf("discovering USDT probes: %w", err)
		}
		log.Warnf("heap probe: skipped invalid USDT notes for PID %d mapping %s: %v",
			pid, mapping.Path, err)
	}

	// Filter to our provider and probe names, and to sites contained in this
	// mapping. Discovery returns every site in the backing ELF, while runtime
	// addresses are specific to each process mapping.
	type candidate struct {
		key     attachmentKey
		point   usdt.AttachmentPoint
		prog    *cebpf.Program
		specKey support.USDTSpecKey
		spec    support.USDTSpec
	}
	candidates := make([]candidate, 0, len(points))
	for _, point := range points {
		if point.Provider != heapProbeProvider {
			continue
		}
		prog, ok := hp.programs[point.Name]
		if !ok {
			continue
		}
		// USDT notes identify sites by file offset, while the spec map is keyed by
		// the runtime PC. Ignore sites that belong to another mapping of this ELF.
		virtualAddress, contained := probeVirtualAddress(mapping, point.Location)
		if !contained {
			continue
		}
		var spec support.USDTSpec
		switch point.Name {
		case "alloc":
			spec, err = parseAllocSpec(point)
		case "free":
			spec, err = parseFreeSpec(point)
		default:
			continue
		}
		if err != nil {
			log.Warnf("heap probe: invalid arguments for %s:%s at offset %#x: %v",
				point.Provider, point.Name, point.Location, err)
			continue
		}
		key := attachmentKeyFor(mapping, point.Name, point.Location)
		// ProcessManager PIDs originate from the translated pid_events path,
		// matching get_pid_tgid_leader() in the firing BPF program.
		specKey := support.USDTSpecKey{
			Pid:     uint32(pid),
			Address: virtualAddress,
		}
		// This pre-check avoids reopening an already registered site in the common
		// case. The locked check in the attachment loop remains authoritative.
		hp.mu.Lock()
		attached := hp.attachments[pid][key]
		registered := false
		if attached != nil {
			_, registered = attached.specKeys[specKey]
		}
		hp.mu.Unlock()
		if !registered {
			candidates = append(candidates, candidate{
				key: key, point: point, prog: prog, specKey: specKey, spec: spec,
			})
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Open the backing file to get an fd for the uprobe. We go through
	// OpenMappingFile (which uses /proc/<pid>/map_files) for deleted-file
	// and mount-namespace safety.
	mappingFile, err := pr.OpenMappingFile(mapping)
	if err != nil {
		return fmt.Errorf("open mapping %s: %w", mapping.Path, err)
	}
	defer mappingFile.Close()

	fdFile, ok := mappingFile.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("mapping %s has no file descriptor", mapping.Path)
	}
	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", fdFile.Fd()))
	if err != nil {
		return fmt.Errorf("open mapping %s as executable: %w", mapping.Path, err)
	}

	// Reserve each site and register its argument layout before attaching the
	// uprobe. Multiple mappings of the same file share one PID-scoped link but
	// each runtime address gets its own specification.
	attachedFree := false
	for _, candidate := range candidates {
		hp.mu.Lock()
		if hp.unloaded {
			hp.mu.Unlock()
			return nil
		}
		attached := hp.attachments[pid][candidate.key]
		if attached != nil {
			if attached.detaching {
				hp.mu.Unlock()
				log.Warnf("heap probe: skip mapping for detaching %s:%s PID %d at address %#x",
					candidate.point.Provider, candidate.point.Name, pid,
					candidate.specKey.Address)
				continue
			}
			if _, exists := attached.specKeys[candidate.specKey]; exists {
				hp.mu.Unlock()
				continue
			}
			if err := hp.usdtSpecs.Put(candidate.specKey, candidate.spec); err != nil {
				hp.mu.Unlock()
				metrics.Add(metrics.IDUSDTSpecsUpdate, 1)
				log.Warnf("heap probe: register arguments for %s:%s PID %d at address %#x: %v",
					candidate.point.Provider, candidate.point.Name, pid,
					candidate.specKey.Address, err)
				continue
			}
			attached.specKeys[candidate.specKey] = libpf.Void{}
			hp.mu.Unlock()
			attachedFree = attachedFree || candidate.point.Name == "free"
			// In some cases, e.g. with dlmopen, a library may be mapped in multiple
			// times. A PID-scoped uprobe is registered by inode and file offset, so
			// the existing link fires for every mapping of that site in this process.
			continue
		}
		if err := hp.usdtSpecs.Put(candidate.specKey, candidate.spec); err != nil {
			hp.mu.Unlock()
			metrics.Add(metrics.IDUSDTSpecsUpdate, 1)
			log.Warnf("heap probe: register arguments for %s:%s PID %d at address %#x: %v",
				candidate.point.Provider, candidate.point.Name, pid,
				candidate.specKey.Address, err)
			continue
		}
		if hp.attachments[pid] == nil {
			hp.attachments[pid] = make(map[attachmentKey]*attachment)
		}
		pending := &attachment{specKeys: map[support.USDTSpecKey]libpf.Void{
			candidate.specKey: {},
		}}
		hp.attachments[pid][candidate.key] = pending
		hp.mu.Unlock()

		lnk, err := ex.Uprobe("", candidate.prog, &link.UprobeOptions{
			PID:          int(pid),
			Address:      candidate.point.Location,
			RefCtrOffset: candidate.point.SemaphoreOffset,
		})
		if err != nil {
			hp.mu.Lock()
			if hp.attachments[pid][candidate.key] == pending {
				// A matching reservation means neither Detach nor Unload has removed
				// the attachment state or taken ownership of the spec map.
				delete(hp.attachments[pid], candidate.key)
				if len(hp.attachments[pid]) == 0 {
					delete(hp.attachments, pid)
				}
				for specKey := range pending.specKeys {
					if deleteErr := hp.usdtSpecs.Delete(specKey); deleteErr != nil &&
						!errors.Is(deleteErr, cebpf.ErrKeyNotExist) {
						log.Warnf("heap probe: roll back arguments for PID %d at address %#x: %v",
							pid, specKey.Address, deleteErr)
					}
				}
			}
			hp.mu.Unlock()
			log.Warnf("heap probe: attach %s:%s for PID %d at offset %#x: %v",
				candidate.point.Provider, candidate.point.Name, pid,
				candidate.point.Location, err)
			continue
		}

		hp.mu.Lock()
		if hp.unloaded || pending.detaching || hp.attachments[pid][candidate.key] != pending {
			// Detach or Unload claimed or removed the reservation while the
			// kernel attachment was being created. Its cleanup owns the specs;
			// only the unpublished link remains for this goroutine to close.
			hp.mu.Unlock()
			if closeErr := lnk.Close(); closeErr != nil {
				log.Errorf("heap probe: close unpublished %s:%s link for PID %d: %v",
					candidate.point.Provider, candidate.point.Name, pid, closeErr)
			}
			continue
		}
		pending.lnk = lnk
		hp.mu.Unlock()
		attachedFree = attachedFree || candidate.point.Name == "free"
	}

	if attachedFree && hp.cfg.LiveHeapProfiling {
		hp.mu.Lock()
		if !hp.unloaded && hp.heapLivePids != nil {
			hp.setHeapLivePID(hp.heapLivePids, pid, true)
		}
		hp.mu.Unlock()
	}
	return nil
}

// Detach implements processmanager.ProbeAttacher.
func (hp *Probe) Detach(pid libpf.PID) {
	type cleanup struct {
		key      attachmentKey
		attached *attachment
		lnk      io.Closer
	}

	hp.mu.Lock()
	cleanups := make([]cleanup, 0, len(hp.attachments[pid]))
	for key, attached := range hp.attachments[pid] {
		if attached.detaching {
			continue
		}
		attached.detaching = true
		cleanups = append(cleanups, cleanup{key: key, attached: attached, lnk: attached.lnk})
		// Unload may take ownership of the remaining state while Close runs, so
		// make it clear that this goroutine owns the link from this point.
		attached.lnk = nil
	}
	hp.mu.Unlock()

	for _, cleanup := range cleanups {
		if cleanup.lnk != nil {
			if err := cleanup.lnk.Close(); err != nil {
				log.Errorf("heap probe: detach PID %d probe %s at offset %#x: %v",
					pid, cleanup.key.name, cleanup.key.offset, err)
			}
		}
	}

	// Purge userspace live-heap state and collect pointers for eBPF cleanup.
	var ptrs []uint64
	if hp.tracker != nil {
		ptrs = hp.tracker.HandleProcessExit(pid)
	}

	hp.mu.Lock()
	defer hp.mu.Unlock()
	for _, cleanup := range cleanups {
		// Pointer identity prevents an old cleanup from deleting a replacement
		// attachment and its specs if the same PID and key are reused.
		if hp.attachments[pid][cleanup.key] != cleanup.attached {
			// Unload or another cleanup already removed this reservation and its specs.
			continue
		}
		if hp.usdtSpecs != nil {
			for specKey := range cleanup.attached.specKeys {
				if err := hp.usdtSpecs.Delete(specKey); err != nil &&
					!errors.Is(err, cebpf.ErrKeyNotExist) {
					log.Errorf("heap probe: delete USDT arguments for PID %d at address %#x: %v",
						pid, specKey.Address, err)
				}
			}
		}
		delete(hp.attachments[pid], cleanup.key)
	}
	if len(hp.attachments[pid]) == 0 {
		delete(hp.attachments, pid)
	}

	if !hp.unloaded {
		if hp.heapAllocLive != nil && len(ptrs) > 0 {
			for _, ptr := range ptrs {
				key := heapAllocKey{PID: uint32(pid), Ptr: ptr}
				_ = hp.heapAllocLive.Delete(key)
			}
		}
		if hp.heapPIDAllocCount != nil {
			pidKey := uint32(pid)
			_ = hp.heapPIDAllocCount.Delete(pidKey)
		}
		if hp.heapLivePids != nil {
			hp.setHeapLivePID(hp.heapLivePids, pid, false)
		}
	}
}

// Unload implements tracer.Probe. Uprobe links are fd-backed, so the runtime
// releases them automatically when the profiler exits; per-PID cleanup also
// happens via Detach. We close any remaining links, probe-owned maps, and
// programs explicitly here.
func (hp *Probe) Unload() error {
	hp.mu.Lock()
	if hp.unloaded {
		hp.mu.Unlock()
		return nil
	}
	hp.unloaded = true
	attachments := hp.attachments
	specMap := hp.usdtSpecs
	livePids := hp.heapLivePids
	allocLive := hp.heapAllocLive
	pidCount := hp.heapPIDAllocCount
	pidLimit := hp.heapPIDAllocLimit
	programs := hp.programs
	hp.attachments = make(map[libpf.PID]map[attachmentKey]*attachment)
	hp.usdtSpecs = nil
	hp.heapLivePids = nil
	hp.heapAllocLive = nil
	hp.heapPIDAllocCount = nil
	hp.heapPIDAllocLimit = nil
	hp.programs = nil
	hp.mu.Unlock()

	var errs error
	for pid, byKey := range attachments {
		for key, attached := range byKey {
			if attached.lnk != nil {
				if err := attached.lnk.Close(); err != nil {
					log.Errorf("heap probe: unload PID %d probe %s at offset %#x: %v",
						pid, key.name, key.offset, err)
					errs = errors.Join(errs, err)
				}
			}
			if specMap != nil {
				for specKey := range attached.specKeys {
					if err := specMap.Delete(specKey); err != nil &&
						!errors.Is(err, cebpf.ErrKeyNotExist) {
						errs = errors.Join(errs, err)
					}
				}
			}
		}
	}
	for _, p := range programs {
		if p != nil {
			errs = errors.Join(errs, p.Close())
		}
	}
	for _, m := range []*cebpf.Map{specMap, livePids, allocLive, pidCount, pidLimit} {
		if m != nil {
			errs = errors.Join(errs, m.Close())
		}
	}
	return errs
}

// PreHandleTrace implements tracer.TraceHandlerHooks.
// For free events: updates the tracker and consumes the trace.
// For alloc events: stashes raw eBPF fields for PostHandleTrace and
// continues with symbolization.
func (hp *Probe) PreHandleTrace(trace *libpf.EbpfTrace) bool {
	if trace.Origin == hp.originFree {
		if hp.tracker != nil && len(trace.ContextValues) > 1 {
			hp.tracker.HandleFree(trace.PID, trace.ContextValues[1])
		}
		return false // consumed
	}
	// Alloc event: stash raw fields for PostHandleTrace.
	hp.pendingAllocPID = trace.PID
	hp.pendingAllocPtr = 0
	hp.pendingAllocValue = 0
	if len(trace.ContextValues) > 0 {
		hp.pendingAllocValue = int64(trace.ContextValues[0])
	}
	if len(trace.ContextValues) > 1 {
		hp.pendingAllocPtr = trace.ContextValues[1]
	}
	return true
}

// PostHandleTrace implements tracer.TraceHandlerHooks. It feeds heap alloc
// events to the live heap tracker after symbolization.
func (hp *Probe) PostHandleTrace(trace *libpf.Trace) {
	if hp.tracker == nil {
		return
	}
	hp.tracker.HandleAlloc(
		hp.pendingAllocPID,
		hp.pendingAllocPtr,
		trace.Hash(),
		hp.pendingAllocValue,
		trace.Frames,
	)
}

// inuseProfileType describes the live-heap snapshot profile. The samples are
// produced by ProduceSnapshots rather than by trace events, so they carry no
// thread or CPU attribution.
var inuseProfileType = &samples.TypeMetadata{
	SampleTypes: []samples.SampleType{
		{Type: "inuse_space", Unit: "bytes"},
		{Type: "inuse_objects", Unit: "count"},
	},
	ReportValues:      true,
	AppendValues:      appendInuseValues,
	OmitThreadContext: true,
}

func appendInuseValues(dst []int64, meta *samples.TraceEventMeta) []int64 {
	var space, objects int64
	if len(meta.ContextValues) > 0 {
		space = int64(meta.ContextValues[0])
	}
	if len(meta.ContextValues) > 1 {
		objects = int64(meta.ContextValues[1])
	}
	return append(dst, space, objects)
}

// ProduceSnapshots implements samples.SnapshotSource. Returns inuse profiles
// from the live heap tracker snapshot, enriched with per-PID process metadata.
func (hp *Probe) ProduceSnapshots() []samples.SnapshotProfile {
	if hp.tracker == nil {
		return nil
	}
	entries := hp.tracker.Snapshot()
	if len(entries) == 0 {
		return nil
	}

	type cachedMeta struct {
		meta  process.Meta
		attrs attribute.Set
	}
	var metaByPID map[libpf.PID]cachedMeta
	if hp.processMeta != nil {
		metaByPID = make(map[libpf.PID]cachedMeta)
	}

	result := make([]samples.SnapshotSample, len(entries))
	for i, e := range entries {
		var procMeta process.Meta
		var resourceAttrs attribute.Set
		if metaByPID != nil {
			cached, ok := metaByPID[e.PID]
			if !ok {
				cached.meta, cached.attrs = hp.processMeta(e.PID)
				metaByPID[e.PID] = cached
			}
			procMeta = cached.meta
			resourceAttrs = cached.attrs
		}
		result[i] = samples.SnapshotSample{
			ResourceKey: samples.ResourceKey{
				PID:            int64(e.PID),
				ExecutablePath: procMeta.Executable,
				ContainerID:    procMeta.ContainerID,
			},
			EnvVars:       procMeta.EnvVariables,
			ExtraMeta:     procMeta.ExtraMeta,
			ResourceAttrs: resourceAttrs,
			TraceHash:     e.TraceHash,
			Frames:        e.Frames,
			ContextValues: []uint64{uint64(e.Space), uint64(e.Objects)},
		}
	}

	return []samples.SnapshotProfile{{
		ProfileType: inuseProfileType,
		Samples:     result,
	}}
}

// setHeapLivePID adds or removes a PID from the heap_live_pids eBPF map
// and notifies the userspace live heap tracker.
func (hp *Probe) setHeapLivePID(livePids *cebpf.Map, pid libpf.PID, enabled bool) {
	key := uint32(pid)
	if enabled {
		val := uint8(1)
		if err := livePids.Put(key, val); err != nil {
			log.Warnf("heap probe: set %s for PID %d: %v (map full?)", heapLivePidsMapName, pid, err)
		}
	} else {
		if err := livePids.Delete(key); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
			log.Debugf("heap probe: delete %s for PID %d: %v", heapLivePidsMapName, pid, err)
		}
	}

	// Notify the userspace tracker so it accepts/rejects alloc samples for this PID.
	if hp.tracker != nil {
		log.Debugf("heap probe: SetPIDLiveHeapSupport PID %d enabled=%v", pid, enabled)
		hp.tracker.SetPIDLiveHeapSupport(pid, enabled)
	}
}
