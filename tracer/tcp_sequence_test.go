// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func tcpSequenceEvent(
	kind libpf.AsyncKind, event libpf.TraceEventKind, operation uint16,
	origin uint16, correlation, socket uint64, sequence uint32,
	result, ktime int64,
) *libpf.EbpfTrace {
	return &libpf.EbpfTrace{
		AsyncKind: kind, EventKind: event, AsyncOperation: operation,
		Origin: origin, CorrelationID: correlation, AsyncUserData: socket,
		AsyncFlags: sequence, AsyncResult: result, KTime: ktime,
	}
}

func TestTCPSequenceSendCompletesOnCumulativeACK(t *testing.T) {
	correlator := newTCPSequenceCorrelator(32, time.Minute)
	begin := tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncRegister,
		tcpSequenceCallBegin, 7, 11, 99, 100, 10, 101)
	require.Empty(t, correlator.handle(begin))
	start := tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncStart, 0,
		7, 11, 99, 0, 0, 100)
	start.PID = 42
	start.FrameData = []uint64{1, 2, 3}
	require.Empty(t, correlator.handle(start))
	result := tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncRegister,
		tcpSequenceCallResult, 7, 11, 99, 100, 10, 120)
	require.Empty(t, correlator.handle(result))

	ack := tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncProgress,
		0, 7, 99, 109, 0, 0, 200)
	require.Empty(t, correlator.handle(ack))
	ack.AsyncUserData = 110
	completed := correlator.handle(ack)
	require.Len(t, completed, 1)
	require.Equal(t, int64(100), completed[0].value)
	require.Equal(t, int64(10), completed[0].result)
	require.Equal(t, libpf.PID(42), completed[0].snapshot.pid)
	require.Equal(t, []uint64{1, 2, 3}, completed[0].snapshot.frameData)
	require.Zero(t, correlator.order.Len())
}

func TestTCPSequenceACKMayArriveBeforeSendEvents(t *testing.T) {
	correlator := newTCPSequenceCorrelator(32, time.Minute)
	progress := tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncProgress,
		0, 1, 9, 110, 0, 0, 200)
	require.Empty(t, correlator.handle(progress))
	socket := tcpSequenceSocketKey{origin: 1, socket: 9}
	require.Contains(t, correlator.ackProgress, socket)
	for _, event := range []*libpf.EbpfTrace{
		tcpSequenceEvent(libpf.AsyncKindTCPAck, libpf.TraceEventAsyncRegister,
			tcpSequenceCallBegin, 1, 2, 9, 100, 10, 101),
		tcpSequenceEvent(libpf.AsyncKindTCPAck, libpf.TraceEventAsyncStart,
			0, 1, 2, 9, 0, 0, 100),
	} {
		require.Empty(t, correlator.handle(event))
	}
	require.Contains(t, correlator.ackProgress, socket)
	completed := correlator.handle(tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncRegister,
		tcpSequenceCallResult, 1, 2, 9, 100, 10, 120))
	require.Len(t, completed, 1)
	require.Equal(t, int64(100), completed[0].value)
}

func TestTCPSequenceSendHandlesSequenceWrap(t *testing.T) {
	correlator := newTCPSequenceCorrelator(32, time.Minute)
	startSequence := uint32(math.MaxUint32 - 4)
	for _, event := range []*libpf.EbpfTrace{
		tcpSequenceEvent(libpf.AsyncKindTCPAck, libpf.TraceEventAsyncRegister,
			tcpSequenceCallBegin, 1, 2, 3, startSequence, 10, 10),
		tcpSequenceEvent(libpf.AsyncKindTCPAck, libpf.TraceEventAsyncStart,
			0, 1, 2, 3, 0, 0, 10),
		tcpSequenceEvent(libpf.AsyncKindTCPAck, libpf.TraceEventAsyncRegister,
			tcpSequenceCallResult, 1, 2, 3, startSequence, 10, 11),
	} {
		require.Empty(t, correlator.handle(event))
	}
	progress := tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncProgress,
		0, 1, 3, 4, 0, 0, 20)
	require.Empty(t, correlator.handle(progress))
	progress.AsyncUserData = 5
	require.Len(t, correlator.handle(progress), 1)
}

func TestTCPSequenceReceiveConsumesQueuedRanges(t *testing.T) {
	correlator := newTCPSequenceCorrelator(32, time.Minute)
	arrival := tcpSequenceEvent(
		libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
		tcpSequenceRange, 2, 77, uint64(100)<<32|110, 0, 0, 100)
	require.Empty(t, correlator.handle(arrival))
	for _, testCase := range []struct {
		token    uint64
		sequence uint32
		consumed int64
		at       int64
	}{{8, 100, 5, 200}, {9, 105, 5, 300}} {
		begin := tcpSequenceEvent(
			libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
			tcpSequenceCallBegin, 2, testCase.token, 77,
			testCase.sequence, 5, testCase.at-10)
		require.Empty(t, correlator.handle(begin))
		start := tcpSequenceEvent(
			libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncStart,
			0, 2, testCase.token, 77, 0, 0, testCase.at-10)
		start.TID = 123
		require.Empty(t, correlator.handle(start))
		result := tcpSequenceEvent(
			libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
			tcpSequenceCallResult, 2, testCase.token, 77,
			testCase.sequence, testCase.consumed, testCase.at)
		completed := correlator.handle(result)
		require.Len(t, completed, 1)
		require.Equal(t, testCase.at-100, completed[0].value)
		require.Equal(t, libpf.PID(123), completed[0].snapshot.tid)
	}
	require.Zero(t, correlator.order.Len())
}

func TestTCPSequenceReceiveMayArriveAfterReadResult(t *testing.T) {
	correlator := newTCPSequenceCorrelator(32, time.Minute)
	for _, event := range []*libpf.EbpfTrace{
		tcpSequenceEvent(libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
			tcpSequenceCallBegin, 1, 6, 5, 10, 10, 190),
		tcpSequenceEvent(libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncStart,
			0, 1, 6, 5, 0, 0, 190),
		tcpSequenceEvent(libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
			tcpSequenceCallResult, 1, 6, 5, 10, 10, 200),
	} {
		require.Empty(t, correlator.handle(event))
	}
	completed := correlator.handle(tcpSequenceEvent(
		libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
		tcpSequenceRange, 1, 5, uint64(10)<<32|20, 0, 0, 100))
	require.Len(t, completed, 1)
	require.Equal(t, int64(100), completed[0].value)
	require.Zero(t, correlator.order.Len())
}

func TestTCPSequenceCloseClearsSocketState(t *testing.T) {
	correlator := newTCPSequenceCorrelator(8, time.Minute)
	correlator.handle(tcpSequenceEvent(
		libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
		tcpSequenceRange, 1, 5, uint64(10)<<32|20, 0, 0, 100))
	correlator.handle(tcpSequenceEvent(
		libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
		tcpSequenceCallBegin, 1, 6, 5, 10, 4, 110))
	require.Equal(t, 2, correlator.order.Len())
	correlator.handle(tcpSequenceEvent(
		libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncProgress,
		tcpSequenceReset, 1, 5, 0, 0, 0, 120))
	require.Zero(t, correlator.order.Len())
	require.Empty(t, correlator.receiveRanges)
	require.Empty(t, correlator.calls)
	// A cross-CPU event delivered after CLOSE but timestamped before it is stale.
	correlator.handle(tcpSequenceEvent(
		libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
		tcpSequenceRange, 1, 5, uint64(10)<<32|20, 0, 0, 100))
	require.Zero(t, correlator.order.Len())
	// Pointer reuse is accepted once an event is newer than the close.
	correlator.handle(tcpSequenceEvent(
		libpf.AsyncKindTCPReceive, libpf.TraceEventAsyncRegister,
		tcpSequenceRange, 1, 5, uint64(20)<<32|30, 0, 0, 130))
	require.Equal(t, 1, correlator.order.Len())
}

func TestTCPReceiveWindowCoverageMergesRangesAndDetectsGaps(t *testing.T) {
	ranges := []*tcpReceiveRange{
		{start: 105, end: 110, queued: 200},
		{start: 100, end: 105, queued: 100},
	}
	covered, oldest := tcpReceiveWindowCoverage(ranges, 100, 110, 10)
	require.True(t, covered)
	require.Equal(t, int64(100), oldest)

	ranges[1].end = 104
	covered, _ = tcpReceiveWindowCoverage(ranges, 100, 110, 10)
	require.False(t, covered)
}

func TestTCPReceiveWindowCoverageHandlesSequenceWrap(t *testing.T) {
	start := uint32(math.MaxUint32 - 4)
	ranges := []*tcpReceiveRange{
		{start: start, end: 0, queued: 100},
		{start: 0, end: 5, queued: 200},
	}
	covered, oldest := tcpReceiveWindowCoverage(ranges, start, 5, 10)
	require.True(t, covered)
	require.Equal(t, int64(100), oldest)
}

func TestTCPSequenceDurationFilterConsumesState(t *testing.T) {
	correlator := newTCPSequenceCorrelator(8, time.Minute)
	begin := tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncRegister,
		tcpSequenceCallBegin, 1, 2, 3, 10, 1, 100)
	begin.AsyncThreshold = 100
	correlator.handle(begin)
	start := tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncStart,
		0, 1, 2, 3, 0, 0, 100)
	start.AsyncThreshold = 100
	correlator.handle(start)
	result := tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncRegister,
		tcpSequenceCallResult, 1, 2, 3, 10, 1, 110)
	result.AsyncThreshold = 100
	correlator.handle(result)
	completed := correlator.handle(tcpSequenceEvent(
		libpf.AsyncKindTCPAck, libpf.TraceEventAsyncProgress,
		0, 1, 3, 11, 0, 0, 150))
	require.Empty(t, completed)
	require.Zero(t, correlator.order.Len())
	require.Equal(t, uint64(1), correlator.stats.filtered)
}
