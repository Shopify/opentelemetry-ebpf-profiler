// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestAsyncCorrelatorPreservesInitiatingTraceUntilCompletion(t *testing.T) {
	correlator := newAsyncTraceCorrelator(4, time.Minute)
	start := &libpf.EbpfTrace{
		PID:             42,
		TID:             43,
		Origin:          7,
		KTime:           100,
		CpuID:           1,
		CorrelationID:   99,
		AsyncUserData:   1234,
		AsyncOperation:  22,
		AsyncKind:       libpf.AsyncKindIOUring,
		EventKind:       libpf.TraceEventAsyncStart,
		FrameData:       []uint64{1, 2, 3},
		NumFrames:       2,
		CustomLabels:    map[libpf.String]libpf.String{libpf.Intern("start"): libpf.Intern("yes")},
		ProcessName:     libpf.Intern("submitter"),
		ExecutablePath:  libpf.Intern("/bin/submitter"),
		AsyncAttributes: libpf.AsyncAttrSQPoll,
	}
	correlator.add(start)

	// The pending entry owns compact copies rather than pooled trace slices/maps.
	start.FrameData[0] = 999
	start.CustomLabels[libpf.Intern("start")] = libpf.Intern("mutated")

	completion := &libpf.EbpfTrace{
		PID:             500,
		TID:             501,
		Origin:          7,
		KTime:           250,
		CpuID:           3,
		Value:           150,
		CorrelationID:   99,
		AsyncUserData:   1234,
		AsyncResult:     64,
		AsyncFlags:      4,
		AsyncOperation:  22,
		AsyncKind:       libpf.AsyncKindIOUring,
		EventKind:       libpf.TraceEventAsyncComplete,
		AsyncAttributes: 0,
	}
	require.True(t, correlator.complete(completion))

	require.Equal(t, libpf.PID(42), completion.PID)
	require.Equal(t, libpf.PID(43), completion.TID)
	require.Equal(t, int64(250), completion.KTime)
	require.Equal(t, int64(150), completion.Value)
	require.Equal(t, uint32(3), completion.CpuID)
	require.Equal(t, []uint64{1, 2, 3}, completion.FrameData)
	require.Equal(t, libpf.TraceEventNormal, completion.EventKind)
	require.Equal(t, libpf.Intern("yes"), completion.CustomLabels[libpf.Intern("start")])
	require.Equal(t, libpf.Intern("read"), completion.CustomLabels[libpf.Intern("io.operation")])
	require.Equal(t, libpf.Intern("64"), completion.CustomLabels[libpf.Intern("io.result")])
	require.Equal(t, libpf.Intern("true"), completion.CustomLabels[libpf.Intern("io_uring.sq_poll")])
	require.Empty(t, correlator.pending)
}

func TestAsyncCorrelatorRetainsMultishotUntilFinalCompletion(t *testing.T) {
	correlator := newAsyncTraceCorrelator(2, time.Minute)
	correlator.add(&libpf.EbpfTrace{
		Origin: 1, CorrelationID: 2, KTime: 10,
		EventKind: libpf.TraceEventAsyncStart,
	})

	first := &libpf.EbpfTrace{
		Origin: 1, CorrelationID: 2, KTime: 20, Value: 10,
		EventKind:       libpf.TraceEventAsyncComplete,
		AsyncAttributes: libpf.AsyncAttrMore,
	}
	require.True(t, correlator.complete(first))
	require.Len(t, correlator.pending, 1)

	final := &libpf.EbpfTrace{
		Origin: 1, CorrelationID: 2, KTime: 30, Value: 20,
		EventKind: libpf.TraceEventAsyncComplete,
	}
	require.True(t, correlator.complete(final))
	require.Empty(t, correlator.pending)
	require.Equal(t, uint64(2), correlator.stats.completions)
}

func TestAsyncCorrelatorReplacesFallbackWithRicherStart(t *testing.T) {
	correlator := newAsyncTraceCorrelator(2, time.Minute)
	correlator.add(&libpf.EbpfTrace{
		Origin: 1, CorrelationID: 2, KTime: 10,
		FrameData: []uint64{1}, EventKind: libpf.TraceEventAsyncStart,
	})
	correlator.add(&libpf.EbpfTrace{
		Origin: 1, CorrelationID: 2, KTime: 10,
		FrameData: []uint64{2, 3, 4}, EventKind: libpf.TraceEventAsyncStart,
	})

	completion := &libpf.EbpfTrace{
		Origin: 1, CorrelationID: 2, KTime: 20,
		EventKind: libpf.TraceEventAsyncComplete,
	}
	require.True(t, correlator.complete(completion))
	require.Equal(t, []uint64{2, 3, 4}, completion.FrameData)
	require.Equal(t, uint64(1), correlator.stats.duplicateStarts)
}

func TestAsyncCorrelatorAddsBlockLabels(t *testing.T) {
	correlator := newAsyncTraceCorrelator(2, time.Minute)
	correlator.add(&libpf.EbpfTrace{
		Origin: 1, CorrelationID: 2, KTime: 10,
		AsyncKind: libpf.AsyncKindBlock, EventKind: libpf.TraceEventAsyncStart,
	})
	completion := &libpf.EbpfTrace{
		Origin: 1, CorrelationID: 2, KTime: 20, Value: 10,
		AsyncKind: libpf.AsyncKindBlock, AsyncOperation: 1,
		AsyncUserData: uint64(8)<<32 | 1,
		EventKind:     libpf.TraceEventAsyncComplete,
	}
	require.True(t, correlator.complete(completion))
	require.Equal(t, libpf.Intern("write"),
		completion.CustomLabels[libpf.Intern("io.operation")])
	require.Equal(t, libpf.Intern("8:1"),
		completion.CustomLabels[libpf.Intern("io.device")])
	require.Equal(t, libpf.Intern("ok"),
		completion.CustomLabels[libpf.Intern("io.status")])
}

func TestAsyncCorrelatorConsumesFilteredCompletion(t *testing.T) {
	correlator := newAsyncTraceCorrelator(2, time.Minute)
	correlator.add(&libpf.EbpfTrace{Origin: 1, CorrelationID: 2, KTime: 10})
	completion := &libpf.EbpfTrace{
		Origin: 1, CorrelationID: 2, KTime: 20,
		EventKind:       libpf.TraceEventAsyncComplete,
		AsyncAttributes: libpf.AsyncAttrFiltered,
	}
	require.True(t, correlator.complete(completion))
	require.Empty(t, correlator.pending)
	require.Equal(t, uint64(1), correlator.stats.filteredCompletions)
}

func TestAsyncCorrelatorBoundsExpiresAndCountsOrphans(t *testing.T) {
	correlator := newAsyncTraceCorrelator(1, 10*time.Nanosecond)
	correlator.add(&libpf.EbpfTrace{Origin: 1, CorrelationID: 1, KTime: 10})
	correlator.add(&libpf.EbpfTrace{Origin: 1, CorrelationID: 2, KTime: 15})
	require.Equal(t, uint64(1), correlator.stats.capacityEvictions)

	// The second entry expires before this unrelated completion is looked up.
	completion := &libpf.EbpfTrace{Origin: 1, CorrelationID: 3, KTime: 30}
	require.False(t, correlator.complete(completion))
	require.Equal(t, uint64(1), correlator.stats.expirationEvictions)
	require.Equal(t, uint64(1), correlator.stats.orphanCompletions)
	require.Empty(t, correlator.pending)
}
