// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"testing"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/liveheap"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// Make accessible for testing
func (t *Tracer) GetEbpfMaps() map[string]*cebpf.Map {
	return t.ebpfMaps
}

func TestLoadBpfTraceRejectsInvalidHeapWeight(t *testing.T) {
	for _, weight := range []uint64{0, 1 << 63} {
		rawTrace := support.Trace{Origin: uint32(support.TraceOriginHeapAlloc), Value: weight}
		raw := unsafe.Slice((*byte)(unsafe.Pointer(&rawTrace)), int(unsafe.Sizeof(rawTrace)))
		_, err := (&Tracer{}).loadBpfTrace(raw)
		require.ErrorContains(t, err, "invalid byte weight")
	}
}

func TestHandleTraceHeapFreeRemovesLiveAllocation(t *testing.T) {
	const (
		pid = libpf.PID(123)
		ptr = uint64(0xdeadbeef)
	)
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupportAt(pid, true, 100)
	tracker.HandleAllocWithSizeAndMeta(pid, ptr, libpf.NewTraceHash(0, 1), 64, 64,
		nil, liveheap.ProcessMeta{}, nil, 150, 1)
	require.Equal(t, 1, tracker.LiveCount())

	tr := &Tracer{tracePool: newTracePool(), liveHeapTracker: tracker}
	tr.HandleTrace(&libpf.EbpfTrace{
		Origin: support.TraceOriginHeapFree,
		PID:    pid,
		Ptr:    ptr,
		KTime:  99,
	})
	assert.Equal(t, 1, tracker.LiveCount(),
		"a delayed free from an earlier PID generation must be ignored")

	tr.HandleTrace(&libpf.EbpfTrace{
		Origin: support.TraceOriginHeapFree,
		PID:    pid,
		Ptr:    ptr,
		KTime:  150,
	})
	assert.Zero(t, tracker.LiveCount())
}
