// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package liveheap tracks live (in-use) heap allocations by correlating
// sampled alloc and free events. It produces periodic snapshots of the
// current live set, aggregated by allocation call stack.
package liveheap // import "go.opentelemetry.io/ebpf-profiler/liveheap"

import (
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

const (
	// DefaultMaxEntries is the global cap on tracked live allocations.
	// Beyond this, new allocations are dropped and counted as overflow.
	DefaultMaxEntries = 100_000
)

// EstimateObjectWeight converts an unbiased byte weight into an integer object
// weight. For valid producer weights (weight >= size), deterministic stochastic
// rounding preserves fractional expected values while keeping repeated snapshots
// of one live allocation stable. Malformed smaller weights represent at least the
// observed allocation. salt must vary across sampled allocations.
func EstimateObjectWeight(weight int64, size, salt uint64) int64 {
	if weight <= 0 || size == 0 {
		return 1
	}
	unsignedWeight := uint64(weight)
	objects := unsignedWeight / size
	if objects == 0 {
		return 1
	}
	remainder := unsignedWeight % size
	if remainder == 0 {
		return int64(objects)
	}

	// SplitMix64's finalizer removes pointer alignment and timestamp structure
	// before using the remainder as a stochastic-rounding probability.
	salt ^= salt >> 30
	salt *= 0xbf58476d1ce4e5b9
	salt ^= salt >> 27
	salt *= 0x94d049bb133111eb
	salt ^= salt >> 31
	if salt%size < remainder {
		objects++
	}
	return int64(objects)
}

func addWeightSaturating(total, delta int64) int64 {
	const maxInt64 = int64(^uint64(0) >> 1)
	if delta > 0 && total > maxInt64-delta {
		return maxInt64
	}
	return total + delta
}

// ProcessMeta holds process metadata needed for inuse profile resource attributes.
type ProcessMeta struct {
	ExecutablePath libpf.String
	ContainerID    libpf.String
}

// allocKey uniquely identifies a live allocation: the process and the
// pointer returned to the application.
type allocKey struct {
	PID libpf.PID
	Ptr uint64
}

// allocEntry stores the metadata for one live allocation needed to
// produce inuse profiles and correlate with free events.
type allocEntry struct {
	TraceHash    libpf.TraceHash
	SpaceWeight  int64
	ObjectWeight int64
	ProcessMeta  ProcessMeta
	ExtraMeta    any
}

// InuseEntry is one row in the aggregated snapshot: a unique call stack
// and the total in-use bytes/objects attributed to it.
type InuseEntry struct {
	TraceHash   libpf.TraceHash
	Frames      libpf.Frames
	PID         libpf.PID
	ProcessMeta ProcessMeta
	ExtraMeta   any
	Space       int64 // estimated live bytes represented by allocations with this stack
	Objects     int64 // estimated live objects represented by allocations with this stack
}

// Tracker maintains the live allocation set for all tracked processes.
// It is safe for concurrent use.
type Tracker struct {
	mu         sync.Mutex
	live       map[allocKey]allocEntry
	maxEntries int

	// frames caches the resolved frame list per trace hash so that
	// snapshots can report stacks without re-symbolizing.
	frames map[libpf.TraceHash]libpf.Frames

	// liveHeapPIDs records when each PID generation was enabled after its
	// deallocation hook attached (see memory.EventDeallocation). Events older
	// than that boundary belong to a prior process generation and are ignored.
	liveHeapPIDs map[libpf.PID]int64

	// Metrics
	dropped      uint64 // allocs dropped due to global cap
	allocSamples uint64 // alloc samples received this interval
	freeSamples  uint64 // free samples received this interval
}

// NewTracker creates a Tracker with the given global cap on live entries.
func NewTracker(maxEntries int) *Tracker {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &Tracker{
		live:         make(map[allocKey]allocEntry, 4096),
		frames:       make(map[libpf.TraceHash]libpf.Frames, 1024),
		liveHeapPIDs: make(map[libpf.PID]int64),
		maxEntries:   maxEntries,
	}
}

// SetPIDLiveHeapSupport marks whether a PID supports live heap tracking
// (i.e., has the heap-sampler free probe attached). Only PIDs with support
// enabled will have their allocations tracked.
//
// Future improvement: PIDs that have the free probe but never actually free
// memory after some observation window could be auto-demoted to save tracker
// memory. This is not implemented yet but would be useful when live heap
// profiling is dynamically configured on the application side.
func (t *Tracker) SetPIDLiveHeapSupport(pid libpf.PID, supported bool) (wasSupported bool) {
	return t.SetPIDLiveHeapSupportAt(pid, supported, 0)
}

// SetPIDLiveHeapSupportAt marks live support at a monotonic-time process
// generation boundary. Repeated enablement retains the original boundary so
// ordinary mapping reconciliation cannot discard queued events from the same
// process generation.
func (t *Tracker) SetPIDLiveHeapSupportAt(pid libpf.PID, supported bool,
	enabledKTime int64,
) (wasSupported bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, wasSupported = t.liveHeapPIDs[pid]
	if supported {
		if !wasSupported {
			t.liveHeapPIDs[pid] = enabledKTime
		}
	} else {
		delete(t.liveHeapPIDs, pid)
	}
	return wasSupported
}

// HandleAlloc records an unweighted sampled allocation. It is retained for
// callers that do not have a distinct raw allocation size; production heap
// events use HandleAllocWithSize so object counts can be weighted correctly.
func (t *Tracker) HandleAlloc(pid libpf.PID, ptr uint64, traceHash libpf.TraceHash,
	weight int64, frames libpf.Frames,
) {
	size := uint64(0)
	if weight > 0 {
		size = uint64(weight)
	}
	t.HandleAllocWithSize(pid, ptr, traceHash, weight, size, frames)
}

// HandleAllocWithSize records a sampled allocation without process metadata.
// Production callers use HandleAllocWithSizeAndMeta so a snapshot remains bound
// to the process generation that produced the allocation.
func (t *Tracker) HandleAllocWithSize(pid libpf.PID, ptr uint64, traceHash libpf.TraceHash,
	weight int64, size uint64, frames libpf.Frames,
) {
	salt := ptr ^ (uint64(pid) << 32) ^ traceHash.Lo()
	t.HandleAllocWithSizeAndMeta(pid, ptr, traceHash, weight, size, frames,
		ProcessMeta{}, nil, 0, salt)
}

// HandleAllocWithSizeAndMeta records a sampled allocation. traceHash and frames
// come from the symbolized trace; ptr, size, weight, and process metadata come
// from the eBPF event. Called for every received alloc sample so allocSamples is
// a true received count; a no-op beyond that count when eBPF did not live-track
// the alloc (ptr == 0) or the PID doesn't support live heap.
func (t *Tracker) HandleAllocWithSizeAndMeta(pid libpf.PID, ptr uint64,
	traceHash libpf.TraceHash, weight int64, size uint64, frames libpf.Frames,
	processMeta ProcessMeta, extraMeta any, allocationKTime int64, allocationSalt uint64,
) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.allocSamples++

	// eBPF zeroes ptr for allocs it did not live-track (dropped at the per-PID
	// limit or a full map, a non-live PID, or a first sighting). Count the
	// received sample above, but there is no live entry to add, and no free
	// will ever arrive for it.
	if ptr == 0 {
		return
	}

	enabledKTime, ok := t.liveHeapPIDs[pid]
	if !ok || allocationKTime < enabledKTime {
		return
	}
	// A byte weight must represent at least one byte. Reject wrapped uint64
	// producer values rather than allowing negative live-profile samples.
	if weight <= 0 {
		return
	}

	// Only apply the global cap to genuinely new keys. A duplicate ptr
	// (realloc reusing an address without an intervening free) overwrites
	// an existing entry without growing the map, so it must always be
	// allowed; dropping it would leave a stale TraceHash/Weight in place
	// and free no capacity.
	key := allocKey{PID: pid, Ptr: ptr}
	if _, exists := t.live[key]; !exists && len(t.live) >= t.maxEntries {
		t.dropped++
		return
	}

	objectWeight := EstimateObjectWeight(weight, size, allocationSalt)
	t.live[key] = allocEntry{
		TraceHash:    traceHash,
		SpaceWeight:  weight,
		ObjectWeight: objectWeight,
		ProcessMeta:  processMeta,
		ExtraMeta:    extraMeta,
	}

	// Cache frames for this trace hash if not already present.
	if _, ok := t.frames[traceHash]; !ok && len(frames) > 0 {
		t.frames[traceHash] = frames
	}
}

// HandleFree removes a sampled allocation from the live set.
// Returns true if the allocation was found and removed.
func (t *Tracker) HandleFree(pid libpf.PID, ptr uint64) bool {
	return t.HandleFreeAt(pid, ptr, 0)
}

// HandleFreeAt removes a sampled allocation unless the event predates the
// current PID generation's live-tracking boundary.
func (t *Tracker) HandleFreeAt(pid libpf.PID, ptr uint64, freeKTime int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.freeSamples++

	enabledKTime, ok := t.liveHeapPIDs[pid]
	if !ok || freeKTime < enabledKTime {
		return false
	}
	key := allocKey{PID: pid, Ptr: ptr}
	_, ok = t.live[key]
	if ok {
		delete(t.live, key)
	}
	return ok
}

// HandleProcessExit removes all live allocations for the given PID and clears
// its live-heap support flag. It returns the removed pointers for eBPF cleanup
// and whether this PID was enabled, so unrelated process exits avoid a full map
// scan when live profiling is configured for only selected executables.
func (t *Tracker) HandleProcessExit(pid libpf.PID) (ptrs []uint64, wasSupported bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, wasSupported = t.liveHeapPIDs[pid]
	delete(t.liveHeapPIDs, pid)

	for key := range t.live {
		if key.PID == pid {
			ptrs = append(ptrs, key.Ptr)
			delete(t.live, key)
		}
	}

	// Purge frame cache entries no longer referenced by any live allocation.
	if len(ptrs) > 0 {
		t.pruneFrameCache()
	}

	return ptrs, wasSupported
}

// pruneFrameCache removes frame cache entries that are no longer
// referenced by any live allocation. Must be called with t.mu held.
func (t *Tracker) pruneFrameCache() {
	referenced := make(map[libpf.TraceHash]struct{}, len(t.frames))
	for _, entry := range t.live {
		referenced[entry.TraceHash] = struct{}{}
	}
	for hash := range t.frames {
		if _, ok := referenced[hash]; !ok {
			delete(t.frames, hash)
		}
	}
}

// pidTraceKey aggregates by PID, allocation-time process/sample metadata, and
// trace hash so snapshots preserve attributes across PID reuse and report intervals.
type pidTraceKey struct {
	PID            libpf.PID
	TraceHash      libpf.TraceHash
	ExecutablePath libpf.String
	ContainerID    libpf.String
	ExtraMeta      any
}

// Snapshot returns the current live set aggregated by process identity and trace hash.
// This is the data emitted as inuse_space/inuse_objects profiles.
func (t *Tracker) Snapshot() []InuseEntry {
	type snapshotAlloc struct {
		key    allocKey
		entry  allocEntry
		frames libpf.Frames
	}

	// Copy the current set under the tracker lock, then perform hash aggregation
	// outside it. This keeps alloc/free event handling from stalling behind the
	// more expensive profile-building work at the 100k-entry global cap.
	t.mu.Lock()
	allocs := make([]snapshotAlloc, 0, len(t.live))
	referenced := make(map[libpf.TraceHash]struct{}, len(t.frames))
	for key, entry := range t.live {
		allocs = append(allocs, snapshotAlloc{
			key: key, entry: entry, frames: t.frames[entry.TraceHash],
		})
		referenced[entry.TraceHash] = struct{}{}
	}
	// HandleFree removes only the live entry. Prune now-unreferenced frame lists
	// during the same pass instead of scanning the live set a second time.
	for hash := range t.frames {
		if _, ok := referenced[hash]; !ok {
			delete(t.frames, hash)
		}
	}
	t.mu.Unlock()

	// Aggregate by process identity and trace hash.
	agg := make(map[pidTraceKey]*InuseEntry, 256)
	for _, alloc := range allocs {
		entry := alloc.entry
		ak := pidTraceKey{
			PID:            alloc.key.PID,
			TraceHash:      entry.TraceHash,
			ExecutablePath: entry.ProcessMeta.ExecutablePath,
			ContainerID:    entry.ProcessMeta.ContainerID,
			ExtraMeta:      entry.ExtraMeta,
		}
		v, ok := agg[ak]
		if !ok {
			v = &InuseEntry{
				TraceHash:   entry.TraceHash,
				Frames:      alloc.frames,
				PID:         alloc.key.PID,
				ProcessMeta: entry.ProcessMeta,
				ExtraMeta:   entry.ExtraMeta,
			}
			agg[ak] = v
		}
		v.Space = addWeightSaturating(v.Space, entry.SpaceWeight)
		v.Objects = addWeightSaturating(v.Objects, entry.ObjectWeight)
	}

	result := make([]InuseEntry, 0, len(agg))
	for _, v := range agg {
		result = append(result, *v)
	}
	return result
}

// LiveCount returns the current number of tracked live allocations.
func (t *Tracker) LiveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.live)
}

// GetAndResetMetrics returns live-heap metrics and resets interval counters.
func (t *Tracker) GetAndResetMetrics() []metrics.Metric {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Surface cap-induced drops loudly in logs, at the single point where the
	// counter is consumed and reset. This is the only reset site for t.dropped
	// so the warning and the exported metric always agree.
	if t.dropped > 0 {
		log.Warnf("live heap: dropped %d allocations (tracker cap reached)", t.dropped)
	}

	result := []metrics.Metric{
		{ID: metrics.IDLiveHeapEntries, Value: metrics.MetricValue(len(t.live))},
		{ID: metrics.IDLiveHeapDroppedAllocs, Value: metrics.MetricValue(t.dropped)},
		{ID: metrics.IDHeapAllocSamples, Value: metrics.MetricValue(t.allocSamples)},
		{ID: metrics.IDHeapFreeSamples, Value: metrics.MetricValue(t.freeSamples)},
	}
	t.dropped = 0
	t.allocSamples = 0
	t.freeSamples = 0
	return result
}
