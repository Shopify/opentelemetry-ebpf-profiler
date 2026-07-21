// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveheap

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

// testFrames returns a minimal non-empty frame list so that HandleAlloc caches
// it (the cache is only populated for len(frames) > 0).
func testFrames() libpf.Frames {
	f := make(libpf.Frames, 0, 1)
	f.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x1000})
	return f
}

// metricValue extracts a single metric value from a GetAndResetMetrics result.
// Returns -1 if the metric is absent so a missing metric fails assertions.
func metricValue(ms []metrics.Metric, id metrics.MetricID) metrics.MetricValue {
	for _, m := range ms {
		if m.ID == id {
			return m.Value
		}
	}
	return -1
}

func TestTracker_AllocThenFreeRemovesEntry(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)

	tr.HandleAlloc(1, 0xdead, libpf.NewTraceHash(0, 1), 100, testFrames())
	require.Equal(t, 1, tr.LiveCount())

	snap := tr.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, int64(100), snap[0].Space)
	assert.Equal(t, int64(1), snap[0].Objects)

	assert.True(t, tr.HandleFree(1, 0xdead), "freeing a live ptr returns true")
	assert.Equal(t, 0, tr.LiveCount())
	assert.False(t, tr.HandleFree(1, 0xbeef), "freeing an unknown ptr returns false")
}

func TestTracker_UntrackedPIDIgnoredButCounted(t *testing.T) {
	tr := NewTracker(0)
	// PID 1 was never marked live-heap-supported.
	tr.HandleAlloc(1, 0xdead, libpf.NewTraceHash(0, 1), 100, testFrames())

	assert.Equal(t, 0, tr.LiveCount(), "alloc from unsupported PID must not be tracked")
	assert.Equal(t, metrics.MetricValue(1),
		metricValue(tr.GetAndResetMetrics(), metrics.IDHeapAllocSamples),
		"the received sample is still counted")
}

func TestTracker_CountsAllReceivedIncludingZeroPtr(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)

	// ptr == 0 means eBPF did not live-track the alloc (dropped / non-live /
	// first sighting): counted as received, never added to the live set.
	tr.HandleAlloc(1, 0, libpf.NewTraceHash(0, 1), 100, nil)
	assert.Equal(t, 0, tr.LiveCount(), "ptr == 0 must not enter the live set")

	tr.HandleAlloc(1, 0xdead, libpf.NewTraceHash(0, 2), 100, testFrames())
	assert.Equal(t, 1, tr.LiveCount())

	assert.Equal(t, metrics.MetricValue(2),
		metricValue(tr.GetAndResetMetrics(), metrics.IDHeapAllocSamples),
		"both received allocs are counted")
}

func TestTracker_DuplicatePtrOverwritesEvenAtCap(t *testing.T) {
	tr := NewTracker(1) // cap of one live entry
	tr.SetPIDLiveHeapSupport(1, true)

	h1 := libpf.NewTraceHash(0, 1)
	h2 := libpf.NewTraceHash(0, 2)

	tr.HandleAlloc(1, 0xaaa, h1, 100, testFrames()) // fills the cap
	require.Equal(t, 1, tr.LiveCount())

	// A genuinely new ptr at cap is dropped.
	tr.HandleAlloc(1, 0xbbb, h1, 50, testFrames())
	assert.Equal(t, 1, tr.LiveCount())

	// A duplicate ptr at cap overwrites the existing entry; it does not grow
	// the map, so it must be allowed and must refresh hash/weight.
	tr.HandleAlloc(1, 0xaaa, h2, 200, testFrames())
	assert.Equal(t, 1, tr.LiveCount())

	snap := tr.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, h2, snap[0].TraceHash, "duplicate ptr refreshes the trace hash")
	assert.Equal(t, int64(200), snap[0].Space, "duplicate ptr refreshes the weight")

	assert.Equal(t, metrics.MetricValue(1),
		metricValue(tr.GetAndResetMetrics(), metrics.IDLiveHeapDroppedAllocs),
		"only the distinct-ptr alloc is dropped")
}

func TestTracker_SnapshotAggregatesByPIDAndStack(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)
	tr.SetPIDLiveHeapSupport(2, true)

	h := libpf.NewTraceHash(0, 1)
	tr.HandleAlloc(1, 0xa, h, 100, testFrames())
	tr.HandleAlloc(1, 0xb, h, 200, testFrames()) // same PID + stack
	tr.HandleAlloc(2, 0xc, h, 50, testFrames())  // same stack, different PID

	snap := tr.Snapshot()
	require.Len(t, snap, 2, "aggregation is per (PID, stack)")

	byPID := map[libpf.PID]InuseEntry{}
	for _, e := range snap {
		byPID[e.PID] = e
	}
	assert.Equal(t, int64(300), byPID[1].Space)
	assert.Equal(t, int64(2), byPID[1].Objects)
	assert.Equal(t, int64(50), byPID[2].Space)
	assert.Equal(t, int64(1), byPID[2].Objects)
}

func TestTracker_DropsEventsFromPriorPIDGeneration(t *testing.T) {
	tr := NewTracker(0)
	hash := libpf.NewTraceHash(0, 1)
	tr.SetPIDLiveHeapSupportAt(1, true, 100)
	tr.SetPIDLiveHeapSupportAt(1, true, 200)

	tr.HandleAllocWithSizeAndMeta(1, 0xaaa, hash, 64, 64, testFrames(),
		ProcessMeta{}, nil, 99, 1)
	assert.Zero(t, tr.LiveCount(), "an old-generation allocation must be dropped")

	tr.HandleAllocWithSizeAndMeta(1, 0xaaa, hash, 64, 64, testFrames(),
		ProcessMeta{}, nil, 150, 2)
	require.Equal(t, 1, tr.LiveCount(),
		"repeated reconciliation must retain the original generation boundary")
	assert.False(t, tr.HandleFreeAt(1, 0xaaa, 99),
		"an old-generation free must not delete a current allocation")
	assert.Equal(t, 1, tr.LiveCount())
	assert.True(t, tr.HandleFreeAt(1, 0xaaa, 150))
	assert.Zero(t, tr.LiveCount())
}

func TestTracker_SnapshotSeparatesReusedPIDMetadata(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)
	hash := libpf.NewTraceHash(0, 1)
	oldMeta := ProcessMeta{
		ExecutablePath: libpf.Intern("/old/app"),
		ContainerID:    libpf.Intern("old-container"),
	}
	newMeta := ProcessMeta{
		ExecutablePath: libpf.Intern("/new/app"),
		ContainerID:    libpf.Intern("new-container"),
	}
	tr.HandleAllocWithSizeAndMeta(1, 0xaaa, hash, 64, 64, testFrames(), oldMeta, nil, 0, 1)
	tr.HandleAllocWithSizeAndMeta(1, 0xbbb, hash, 64, 64, testFrames(), newMeta, nil, 0, 2)

	snap := tr.Snapshot()
	require.Len(t, snap, 2,
		"allocations from distinct process generations must not aggregate by PID and stack")
	metas := []ProcessMeta{snap[0].ProcessMeta, snap[1].ProcessMeta}
	assert.ElementsMatch(t, []ProcessMeta{oldMeta, newMeta}, metas)
}

func TestTracker_SnapshotPreservesAllocationSampleMetadata(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)
	hash := libpf.NewTraceHash(0, 1)
	tr.HandleAllocWithSizeAndMeta(1, 0xaaa, hash, 64, 64, testFrames(),
		ProcessMeta{}, "pod-a", 0, 1)
	tr.HandleAllocWithSizeAndMeta(1, 0xbbb, hash, 64, 64, testFrames(),
		ProcessMeta{}, "pod-b", 0, 2)

	snap := tr.Snapshot()
	require.Len(t, snap, 2)
	assert.ElementsMatch(t, []any{"pod-a", "pod-b"},
		[]any{snap[0].ExtraMeta, snap[1].ExtraMeta})
}

func TestEstimateObjectWeightStochasticallyRoundsFractions(t *testing.T) {
	assert.Equal(t, int64(8), EstimateObjectWeight(512, 64, 1))
	assert.Equal(t, int64(1), EstimateObjectWeight(32, 64, 1),
		"an observed allocation always represents at least itself")

	const samples = 30_000
	var total int64
	for salt := range uint64(samples) {
		objects := EstimateObjectWeight(10, 3, salt)
		assert.Contains(t, []int64{3, 4}, objects)
		total += objects
	}
	assert.InDelta(t, 10.0/3.0, float64(total)/samples, 0.02,
		"fractional object weights must remain unbiased across allocations")
}

func TestTracker_ReusedPointerUsesPerAllocationSalt(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)
	hash := libpf.NewTraceHash(0, 1)

	var roundDownSalt, roundUpSalt uint64
	for salt := uint64(1); salt < 1000; salt++ {
		switch EstimateObjectWeight(10, 3, salt) {
		case 3:
			roundDownSalt = salt
		case 4:
			roundUpSalt = salt
		}
		if roundDownSalt != 0 && roundUpSalt != 0 {
			break
		}
	}
	require.NotZero(t, roundDownSalt)
	require.NotZero(t, roundUpSalt)

	tr.HandleAllocWithSizeAndMeta(1, 0xaaa, hash, 10, 3, testFrames(),
		ProcessMeta{}, nil, 0, roundDownSalt)
	require.Equal(t, int64(3), tr.Snapshot()[0].Objects)
	tr.HandleAllocWithSizeAndMeta(1, 0xaaa, hash, 10, 3, testFrames(),
		ProcessMeta{}, nil, 0, roundUpSalt)
	require.Equal(t, int64(4), tr.Snapshot()[0].Objects,
		"a reused address must not pin stochastic rounding across allocations")
}

func TestTracker_SnapshotUsesWeightedObjectCount(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)

	// A 64-byte sampled allocation representing 512 bytes estimates eight
	// objects, matching alloc_objects' weight/size convention.
	tr.HandleAllocWithSize(1, 0xaaa, libpf.NewTraceHash(0, 1), 512, 64, testFrames())

	snap := tr.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, int64(512), snap[0].Space)
	assert.Equal(t, int64(8), snap[0].Objects)
}

func TestTracker_RejectsNonPositiveAndSaturatesWeights(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)
	hash := libpf.NewTraceHash(0, 1)
	tr.HandleAllocWithSize(1, 0xaaa, hash, -1, 1, testFrames())
	assert.Zero(t, tr.LiveCount(), "wrapped producer weights must not enter live profiles")

	const maxInt64 = int64(^uint64(0) >> 1)
	tr.HandleAllocWithSize(1, 0xaaa, hash, maxInt64, 1, testFrames())
	tr.HandleAllocWithSize(1, 0xbbb, hash, maxInt64, 1, testFrames())
	snap := tr.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, maxInt64, snap[0].Space)
	assert.Equal(t, maxInt64, snap[0].Objects)
}

func TestTracker_SnapshotObjectWeightIsAtLeastOne(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)

	// A sampled allocation always represents at least the allocation that was
	// observed, even if a malformed or approximate producer reports weight<size.
	tr.HandleAllocWithSize(1, 0xaaa, libpf.NewTraceHash(0, 1), 32, 64, testFrames())

	snap := tr.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, int64(32), snap[0].Space)
	assert.Equal(t, int64(1), snap[0].Objects)
}

func TestTracker_SnapshotPrunesUnreferencedFrames(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)

	h1 := libpf.NewTraceHash(0, 1)
	h2 := libpf.NewTraceHash(0, 2)
	tr.HandleAlloc(1, 0xa, h1, 100, testFrames())
	tr.HandleAlloc(1, 0xb, h2, 100, testFrames())

	tr.mu.Lock()
	require.Len(t, tr.frames, 2)
	tr.mu.Unlock()

	// Free the only allocation referencing h2.
	tr.HandleFree(1, 0xb)
	tr.mu.Lock()
	assert.Len(t, tr.frames, 2, "HandleFree must not prune the frame cache")
	tr.mu.Unlock()

	// Snapshot prunes the now-unreferenced h2.
	tr.Snapshot()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	assert.Len(t, tr.frames, 1, "Snapshot prunes unreferenced frame-cache entries")
	_, ok := tr.frames[h1]
	assert.True(t, ok, "the still-referenced stack is retained")
}

func TestTracker_HandleProcessExit(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)
	tr.SetPIDLiveHeapSupport(2, true)

	h := libpf.NewTraceHash(0, 1)
	tr.HandleAlloc(1, 0xa, h, 100, testFrames())
	tr.HandleAlloc(1, 0xb, h, 100, testFrames())
	tr.HandleAlloc(2, 0xc, h, 100, testFrames())

	ptrs, wasSupported := tr.HandleProcessExit(1)
	assert.True(t, wasSupported)
	assert.ElementsMatch(t, []uint64{0xa, 0xb}, ptrs, "returns the exited PID's live ptrs")
	assert.Equal(t, 1, tr.LiveCount(), "other PIDs are untouched")

	// Exit clears the PID's live-heap support, so later allocs are ignored.
	tr.HandleAlloc(1, 0xd, h, 100, testFrames())
	assert.Equal(t, 1, tr.LiveCount())
}

func TestTracker_ConcurrentAllocFree(t *testing.T) {
	tr := NewTracker(0)
	tr.SetPIDLiveHeapSupport(1, true)

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range 1000 {
				ptr := uint64(worker*1000 + index + 1)
				tr.HandleAlloc(1, ptr, libpf.NewTraceHash(0, ptr), 100, testFrames())
				tr.HandleFree(1, ptr)
			}
		}()
	}
	wg.Wait()

	assert.Zero(t, tr.LiveCount())
	gotMetrics := tr.GetAndResetMetrics()
	assert.Equal(t, metrics.MetricValue(8000),
		metricValue(gotMetrics, metrics.IDHeapAllocSamples))
	assert.Equal(t, metrics.MetricValue(8000),
		metricValue(gotMetrics, metrics.IDHeapFreeSamples))
}

func TestTracker_GetAndResetMetrics(t *testing.T) {
	tr := NewTracker(1) // cap of one
	tr.SetPIDLiveHeapSupport(1, true)

	tr.HandleAlloc(1, 0xa, libpf.NewTraceHash(0, 1), 100, testFrames()) // tracked
	tr.HandleAlloc(1, 0xb, libpf.NewTraceHash(0, 2), 100, testFrames()) // dropped (cap)
	tr.HandleFree(1, 0xa)

	m := tr.GetAndResetMetrics()
	assert.Equal(t, metrics.MetricValue(2), metricValue(m, metrics.IDHeapAllocSamples))
	assert.Equal(t, metrics.MetricValue(1), metricValue(m, metrics.IDHeapFreeSamples))
	assert.Equal(t, metrics.MetricValue(1), metricValue(m, metrics.IDLiveHeapDroppedAllocs))

	// Interval counters reset after collection.
	m2 := tr.GetAndResetMetrics()
	assert.Equal(t, metrics.MetricValue(0), metricValue(m2, metrics.IDHeapAllocSamples))
	assert.Equal(t, metrics.MetricValue(0), metricValue(m2, metrics.IDHeapFreeSamples))
	assert.Equal(t, metrics.MetricValue(0), metricValue(m2, metrics.IDLiveHeapDroppedAllocs))
}
