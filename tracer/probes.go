// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var dynamicProbeResources = struct {
	maps      []string
	programs  []string
	variables []string
}{
	maps: []string{
		"block_io_stacks_inflight",
		"block_io_stacks_scratch",
		"function_latency_starts",
		"lock_wait_metrics",
		"lock_wait_starts",
	},
	programs: []string{
		"block_io_stacks_issue",
		"block_io_stacks_start",
		"function_latency_entry",
		"function_latency_exit",
		"lock_wait_entry",
		"lock_wait_exit",
	},
	variables: []string{
		"block_io_stacks_min_ns",
		"block_io_stacks_origin",
		"block_io_stacks_sample_threshold",
		"function_latency_min_ns",
		"function_latency_origin",
		"function_latency_sample_threshold",
		"lock_wait_min_ns",
		"lock_wait_origin",
		"lock_wait_return_mode",
		"lock_wait_sample_threshold",
		"lock_wait_success_0",
		"lock_wait_success_1",
		"lock_wait_success_2",
		"lock_wait_success_3",
		"lock_wait_success_count",
	},
}

// removeDynamicProbeResources prevents private maps and unattached programs
// from consuming kernel memory in the main collection. Dynamic probes copy
// these resources from the original embedded specification when enabled.
func removeDynamicProbeResources(collection *cebpf.CollectionSpec) {
	for _, name := range dynamicProbeResources.maps {
		delete(collection.Maps, name)
	}
	for _, name := range dynamicProbeResources.programs {
		delete(collection.Programs, name)
	}
	for _, name := range dynamicProbeResources.variables {
		delete(collection.Variables, name)
	}
}

// ProbeContext bundles the tracer's shared state and provides helpers for building eBPF
// collections inside Probe.Load() implementations.
type ProbeContext struct {
	maps                     map[string]*cebpf.Map
	sysVars                  SysConfigVars
	subscribeProcessObserver func(pm.ProcessObserver) (io.Closer, error)
	registerMetrics          func(func() []metrics.Metric) (io.Closer, error)
}

// ProcessIdentity identifies one PID/address-space generation.
type ProcessIdentity = pm.ProcessIdentity

// ProcessEvent is an immutable process and executable-mapping snapshot.
type ProcessEvent = pm.ProcessEvent

// ReadProcessIdentity returns the identity of the process currently occupying
// pid. Dynamic probe attachment uses it to reject stale snapshots and PID reuse.
func ReadProcessIdentity(pid libpf.PID) (ProcessIdentity, error) {
	return pm.ReadProcessIdentity(pid)
}

// ProcessObserver receives process synchronization and exit events.
type ProcessObserver = pm.ProcessObserver

// ObserveProcesses subscribes observer to current and future process mapping
// updates. The returned closer unregisters it and waits for an in-flight
// callback to finish.
func (c *ProbeContext) ObserveProcesses(observer ProcessObserver) (io.Closer, error) {
	if c == nil || c.subscribeProcessObserver == nil {
		return nil, errors.New("process observation is unavailable")
	}
	return c.subscribeProcessObserver(observer)
}

// RegisterMetricsCollector registers a dynamic probe metrics callback. Metric
// values with the same ID are aggregated across all probe instances. Closing
// the registration waits for an in-flight callback; callback panics are logged
// and isolated from the metrics loop.
func (c *ProbeContext) RegisterMetricsCollector(
	collector func() []metrics.Metric,
) (io.Closer, error) {
	if c == nil || c.registerMetrics == nil {
		return nil, errors.New("probe metrics registration is unavailable")
	}
	return c.registerMetrics(collector)
}

type probeMetricCollector struct {
	mu       sync.Mutex
	callback func() []metrics.Metric
	closed   bool
}

func (collector *probeMetricCollector) collect() (result []metrics.Metric) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closed {
		return nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Errorf("Dynamic probe metrics collector panicked: %v", recovered)
			result = nil
		}
	}()
	return collector.callback()
}

func (collector *probeMetricCollector) close() {
	collector.mu.Lock()
	collector.closed = true
	collector.callback = nil
	collector.mu.Unlock()
}

type probeMetricSubscription struct {
	tracer    *Tracer
	collector *probeMetricCollector
	id        uint64
	once      sync.Once
}

func counterMetrics(input []metrics.Metric) []metrics.Metric {
	counterIDs := make(map[metrics.MetricID]struct{})
	for _, definition := range metrics.GetDefinitions() {
		if !definition.Obsolete && definition.Field != "" &&
			definition.Type == metrics.MetricTypeCounter {
			counterIDs[definition.ID] = struct{}{}
		}
	}
	result := make([]metrics.Metric, 0, len(input))
	for _, metric := range input {
		if _, isCounter := counterIDs[metric.ID]; isCounter && metric.Value != 0 {
			result = append(result, metric)
		}
	}
	return result
}

func (s *probeMetricSubscription) closeWithMetrics(final []metrics.Metric) {
	s.once.Do(func() {
		s.tracer.probeMetricsMu.Lock()
		delete(s.tracer.probeMetricCollectors, s.id)
		s.tracer.probeMetricsMu.Unlock()
		// Wait for a collection that already captured this registration. Once
		// Close returns the callback can no longer be running or start again.
		s.collector.close()

		final = counterMetrics(final)
		if len(final) == 0 {
			return
		}
		s.tracer.probeMetricsMu.Lock()
		if s.tracer.pendingProbeMetrics == nil {
			s.tracer.pendingProbeMetrics = make(metrics.Summary)
		}
		for _, metric := range final {
			s.tracer.pendingProbeMetrics[metric.ID] += metric.Value
		}
		s.tracer.probeMetricsMu.Unlock()
	})
}

// CloseWithMetrics unregisters the collector while retaining final counter
// deltas for the next tracer collection. Gauge values are intentionally
// discarded because the closed source no longer contributes to current state.
func (s *probeMetricSubscription) CloseWithMetrics(final []metrics.Metric) error {
	if s == nil || s.tracer == nil {
		return nil
	}
	s.closeWithMetrics(final)
	return nil
}

func (s *probeMetricSubscription) Close() error {
	return s.CloseWithMetrics(nil)
}

func (t *Tracer) registerProbeMetrics(
	collector func() []metrics.Metric,
) (io.Closer, error) {
	if collector == nil {
		return nil, errors.New("probe metrics collector is nil")
	}
	t.probeMetricsMu.Lock()
	defer t.probeMetricsMu.Unlock()
	if t.probeMetricCollectors == nil {
		t.probeMetricCollectors = make(map[uint64]*probeMetricCollector)
	}
	t.nextProbeMetricID++
	id := t.nextProbeMetricID
	registered := &probeMetricCollector{callback: collector}
	t.probeMetricCollectors[id] = registered
	return &probeMetricSubscription{tracer: t, collector: registered, id: id}, nil
}

func (t *Tracer) collectProbeMetrics() []metrics.Metric {
	t.probeMetricsMu.Lock()
	collectors := make([]*probeMetricCollector, 0, len(t.probeMetricCollectors))
	for _, collector := range t.probeMetricCollectors {
		collectors = append(collectors, collector)
	}
	summary := make(map[metrics.MetricID]metrics.MetricValue,
		len(t.pendingProbeMetrics))
	for id, value := range t.pendingProbeMetrics {
		summary[id] = value
	}
	clear(t.pendingProbeMetrics)
	t.probeMetricsMu.Unlock()

	for _, collector := range collectors {
		for _, metric := range collector.collect() {
			summary[metric.ID] += metric.Value
		}
	}
	ids := make([]int, 0, len(summary))
	for id := range summary {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	result := make([]metrics.Metric, 0, len(ids))
	for _, id := range ids {
		metricID := metrics.MetricID(id)
		result = append(result, metrics.Metric{ID: metricID, Value: summary[metricID]})
	}
	return result
}

// CollectionSpecWith returns a filtered CollectionSpec built from the tracer's embedded
// eBPF ELF. The returned spec contains only the maps, programs, and variables requested
// by the probe plus its private RODATA maps and the mandatory system variables (tpbase_offset,
// task_stack_offset, etc.), which are always included and pre-populated from the values
// determined at tracer startup.
//
// After receiving the spec the probe should:
//  1. Set its own RODATA variables (e.g. origin ID, thresholds).
//  2. Create any probe-specific maps from the returned MapSpecs.
//  3. Call RewriteMaps with those probe-owned maps.
//  4. Call LoadProbeUnwinders to load the programs into the kernel.
//     Variable-to-map syncing is handled automatically inside LoadProbeUnwinders.
func (c *ProbeContext) CollectionSpecWith(
	extraMaps []string,
	extraProgs []string,
	extraVars []string,
) (*cebpf.CollectionSpec, error) {
	full, err := support.LoadCollectionSpec()
	if err != nil {
		return nil, fmt.Errorf("loading collection spec: %w", err)
	}

	filtered := &cebpf.CollectionSpec{
		Maps:      make(map[string]*cebpf.MapSpec),
		Programs:  make(map[string]*cebpf.ProgramSpec),
		Variables: make(map[string]*cebpf.VariableSpec),
	}

	// Each probe gets isolated RODATA maps so its origin and thresholds cannot
	// clobber the main tracer or another instance of the same probe.
	for _, name := range []string{".rodata", ".rodata.var"} {
		if m, ok := full.Maps[name]; ok {
			filtered.Maps[name] = m.Copy()
		}
	}

	for _, name := range extraMaps {
		m, ok := full.Maps[name]
		if !ok {
			return nil, fmt.Errorf("map %q not found in collection spec", name)
		}
		filtered.Maps[name] = m.Copy()
	}

	for _, name := range extraProgs {
		p, ok := full.Programs[name]
		if !ok {
			return nil, fmt.Errorf("program %q not found in collection spec", name)
		}
		filtered.Programs[name] = p.Copy()
	}

	// Mandatory system variables must be present in the ELF on all supported arches.
	for _, s := range c.sysVarSetters() {
		v, ok := full.Variables[s.name]
		if !ok {
			return nil, fmt.Errorf("mandatory system variable %q not found in collection spec", s.name)
		}
		filtered.Variables[s.name] = v
	}
	for _, name := range extraVars {
		v, ok := full.Variables[name]
		if !ok {
			return nil, fmt.Errorf("variable %q not found in collection spec", name)
		}
		filtered.Variables[name] = v
	}

	if err := c.applySystemVars(filtered); err != nil {
		return nil, err
	}

	return filtered, nil
}

// sysVar pairs an eBPF variable name with its runtime value.
type sysVar struct {
	name string
	val  any
}

// sysVarSetters returns the name/value pairs for all system variables that every
// probe must apply to its CollectionSpec. It is the single source of truth for
// both the include list in CollectionSpecWith and the apply pass in applySystemVars.
func (c *ProbeContext) sysVarSetters() []sysVar {
	sv := c.sysVars
	return []sysVar{
		{"inverse_pac_mask", sv.inverse_pac_mask},
		{"tpbase_offset", sv.tpbase_offset},
		{"task_stack_offset", sv.task_stack_offset},
		{"stack_ptregs_offset", sv.stack_ptregs_offset},
		{"vma_lookup_enabled", sv.vma_lookup_enabled},
		{"vma_vm_file_offset", sv.vma_vm_file_offset},
		{"vma_vm_flags_offset", sv.vma_vm_flags_offset},
	}
}

// applySystemVars writes the system configuration values determined at tracer startup into
// coll's RODATA variables and patches programs that depend on VMA helper availability.
// All system variables must be present in coll; CollectionSpecWith guarantees this for
// specs built through the normal path.
func (c *ProbeContext) applySystemVars(coll *cebpf.CollectionSpec) error {
	for _, s := range c.sysVarSetters() {
		v, ok := coll.Variables[s.name]
		if !ok {
			return fmt.Errorf("system variable %q missing from collection spec", s.name)
		}
		if err := v.Set(s.val); err != nil {
			return fmt.Errorf("set %s: %w", s.name, err)
		}
	}
	if !c.sysVars.vma_lookup_enabled {
		disableVMAHelperCalls(coll)
	}
	return nil
}

// RewriteMaps rewrites program map references in coll. The tracer's shared maps are
// merged with probeMaps; probe map names must not shadow tracer-owned map names.
// Only maps actually referenced by the probe's programs are rewritten; tracer-internal
// maps that the probe does not use are silently skipped.
func (c *ProbeContext) RewriteMaps(coll *cebpf.CollectionSpec, probeMaps map[string]*cebpf.Map) error {
	// Build pool: shared tracer maps plus probe-specific maps.
	// RODATA maps are excluded: LoadProbeUnwinders creates isolated copies so
	// probe-specific variables aren't clobbered by the main tracer's copy.
	pool := make(map[string]*cebpf.Map, len(c.maps)+len(probeMaps))
	for k, v := range c.maps {
		if k == ".rodata" || k == ".rodata.var" {
			continue
		}
		pool[k] = v
	}
	for k, v := range probeMaps {
		if _, exists := pool[k]; exists {
			return fmt.Errorf("probe map %q conflicts with a tracer-owned map", k)
		}
		pool[k] = v
	}

	// Filter pool to only maps referenced by at least one probe program.
	// Scanning instruction references directly avoids calling AssociateMap before
	// rewriteMaps does its own pass, which would corrupt the reference metadata.
	toRewrite := make(map[string]*cebpf.Map, len(pool))
	for name, m := range pool {
	outer:
		for _, progSpec := range coll.Programs {
			for _, ins := range progSpec.Instructions {
				if ins.Reference() == name {
					toRewrite[name] = m
					break outer
				}
			}
		}
	}

	return rewriteMaps(coll, toRewrite)
}

func collectionReferencesMap(coll *cebpf.CollectionSpec, name string) bool {
	for _, progSpec := range coll.Programs {
		for _, ins := range progSpec.Instructions {
			if ins.Reference() == name {
				return true
			}
		}
	}
	return false
}

// LoadProbeUnwinders loads the eBPF programs described by progs into the kernel,
// wiring them into the tracer's kprobe tail-call map and the perf unwinder chain.
// It syncs all VariableSpec values into the .rodata.var MapSpec, creates that map,
// and closes it once the programs are loaded — the kernel holds its own reference
// at that point.
func (c *ProbeContext) LoadProbeUnwinders(
	coll *cebpf.CollectionSpec,
	ebpfProgs map[string]*cebpf.Program,
	progs []ProgLoaderHelper,
	bpfVerifierLogLevel uint32,
) error {
	if err := syncVariablesToMapSpecs(coll); err != nil {
		return err
	}
	for _, name := range []string{".rodata", ".rodata.var"} {
		rodataSpec, ok := coll.Maps[name]
		if !ok || !collectionReferencesMap(coll, name) {
			continue
		}
		rodataMap, err := cebpf.NewMap(rodataSpec)
		if err != nil {
			return fmt.Errorf("creating %s: %w", name, err)
		}
		defer rodataMap.Close()
		if err := rewriteMaps(coll, map[string]*cebpf.Map{name: rodataMap}); err != nil {
			return err
		}
	}
	kprobeProgs := c.maps["kprobe_progs"]
	if kprobeProgs == nil {
		return fmt.Errorf("kprobe_progs map not available; ensure the kprobe unwinder chain was loaded at startup")
	}
	perfProgs := c.maps["perf_progs"]
	if perfProgs == nil {
		return fmt.Errorf("perf_progs map not available")
	}
	perCPURecords := c.maps["per_cpu_records"]
	if perCPURecords == nil {
		return fmt.Errorf("per_cpu_records map not available")
	}
	perCPURecordsKp := c.maps["per_cpu_records_kp"]
	if perCPURecordsKp == nil {
		return fmt.Errorf("per_cpu_records_kp map not available")
	}
	return loadProbeUnwinders(coll, ebpfProgs, kprobeProgs, progs,
		bpfVerifierLogLevel, perfProgs.FD(), perCPURecords.FD(), perCPURecordsKp)
}

// Probe defines the interface that allows custom stack unwinding trigger points.
type Probe interface {
	// Load attaches a probe that triggers stack unwinding.
	// Returns the link that keeps the probe attached; the caller owns its lifetime.
	Load(originID uint16, ctx *ProbeContext) (link.Link, error)

	// ReportMetadata provides the necessary metadata to report
	// the events of the Probe.
	ReportMetadata() *samples.TypeMetadata
}

// Enable registers the probe's type metadata with the origin registry, builds a
// ProbeContext from the tracer's current state, and calls p.Load. The returned
// link is stored and closed when the tracer shuts down.
//
// Enable requires that the kprobe tail-call unwinder chain was loaded at tracer
// startup. Set LoadProbe: true in the Config passed to NewTracer (or enable
// off-CPU profiling or ProbeLinks, which also trigger the chain load).
// Without the chain the probe attaches successfully but its tail calls into
// kprobe_progs silently miss, producing no stack samples.
//
// The origin ID is registered before p.Load is called, so the reporter will always
// know about the probe's type metadata before any sample from it can arrive.
// If p.Load fails, the origin ID is permanently consumed and cannot be reclaimed.
// Enable must not be called concurrently with Close.
func (t *Tracer) Enable(p Probe) error {
	if p == nil {
		return errors.New("probe is nil")
	}
	if !t.kprobeChainLoaded {
		return fmt.Errorf("Enable requires the kprobe unwinder chain to be loaded at startup: " +
			"set LoadProbe: true in the tracer Config")
	}

	metadata := p.ReportMetadata()
	if metadata == nil {
		return errors.New("probe report metadata is nil")
	}
	originID, err := t.origins.register(metadata)
	if err != nil {
		return fmt.Errorf("failed to register probe origin: %w", err)
	}

	ctx := &ProbeContext{
		maps:                     t.ebpfMaps,
		sysVars:                  t.sysConfigVars,
		subscribeProcessObserver: t.processManager.SubscribeProcessObserver,
		registerMetrics:          t.registerProbeMetrics,
	}

	lnk, err := p.Load(originID, ctx)
	if err != nil {
		t.origins.unregister(originID)
		return fmt.Errorf("failed to load probe: %w", err)
	}
	if lnk == nil {
		t.origins.unregister(originID)
		return errors.New("probe returned a nil link")
	}

	t.hooks[hookPoint{group: "probe", name: fmt.Sprintf("%d", originID)}] = lnk
	return nil
}
