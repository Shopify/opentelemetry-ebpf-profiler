// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"container/list"
	"math"
	"sort"
	"sync"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/times"
)

const (
	tcpSequenceCallBegin  = 1
	tcpSequenceCallResult = 2
	tcpSequenceRange      = 3
	tcpSequenceReset      = 4
)

type tcpSequenceKey struct {
	origin uint16
	token  uint64
}

type tcpSequenceSocketKey struct {
	origin uint16
	socket uint64
}

type tcpSequenceEntryKind uint8

const (
	tcpSequenceEntryCall tcpSequenceEntryKind = iota
	tcpSequenceEntrySendRange
	tcpSequenceEntryReceiveRange
)

type tcpSequenceEntry struct {
	kind      tcpSequenceEntryKind
	key       tcpSequenceKey
	socket    tcpSequenceSocketKey
	call      *tcpSequenceCall
	send      *tcpSendRange
	receive   *tcpReceiveRange
	timestamp int64
}

type tcpSequenceCall struct {
	key        tcpSequenceKey
	kind       libpf.AsyncKind
	socket     uint64
	startSeq   uint32
	threshold  uint64
	snapshot   *asyncTraceSnapshot
	result     int64
	resultAt   int64
	resultCPU  uint32
	resultSeen bool
	element    *list.Element
}

type tcpSendRange struct {
	key       tcpSequenceKey
	socket    tcpSequenceSocketKey
	endSeq    uint32
	bytes     int64
	threshold uint64
	snapshot  asyncTraceSnapshot
	element   *list.Element
}

type tcpReceiveRange struct {
	socket  tcpSequenceSocketKey
	start   uint32
	end     uint32
	queued  int64
	element *list.Element
}

type tcpSequenceProgress struct {
	sequence uint32
	ktime    int64
	cpu      uint32
}

type tcpSequenceStats struct {
	orphans   uint64
	evictions uint64
	filtered  uint64
}

type tcpSequenceCorrelator struct {
	mu             sync.Mutex
	capacity       int
	ttl            time.Duration
	order          *list.List
	calls          map[tcpSequenceKey]*tcpSequenceCall
	sendRanges     map[tcpSequenceSocketKey][]*tcpSendRange
	sendCallCounts map[tcpSequenceSocketKey]int
	ackProgress    map[tcpSequenceSocketKey]tcpSequenceProgress
	receiveRanges  map[tcpSequenceSocketKey][]*tcpReceiveRange
	resets         map[tcpSequenceSocketKey]int64
	stats          tcpSequenceStats
}

type tcpSequenceCompletion struct {
	snapshot asyncTraceSnapshot
	kind     libpf.AsyncKind
	ktime    int64
	cpu      uint32
	value    int64
	result   int64
}

func newTCPSequenceCorrelator(capacity int, ttl time.Duration) *tcpSequenceCorrelator {
	return &tcpSequenceCorrelator{
		capacity:       capacity,
		ttl:            ttl,
		order:          list.New(),
		calls:          make(map[tcpSequenceKey]*tcpSequenceCall),
		sendRanges:     make(map[tcpSequenceSocketKey][]*tcpSendRange),
		sendCallCounts: make(map[tcpSequenceSocketKey]int),
		ackProgress:    make(map[tcpSequenceSocketKey]tcpSequenceProgress),
		receiveRanges:  make(map[tcpSequenceSocketKey][]*tcpReceiveRange),
		resets:         make(map[tcpSequenceSocketKey]int64),
	}
}

func (c *tcpSequenceCorrelator) handle(trace *libpf.EbpfTrace) []tcpSequenceCompletion {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(trace.KTime)
	socket := tcpSequenceEventSocket(trace)
	if trace.EventKind == libpf.TraceEventAsyncProgress &&
		trace.AsyncOperation == tcpSequenceReset {
		c.clearSocket(trace.AsyncKind, socket)
		c.recordReset(socket, trace.KTime)
		return nil
	}
	if socket.socket != 0 {
		if resetAt, exists := c.resets[socket]; exists && trace.KTime <= resetAt {
			return nil
		}
	}

	switch trace.AsyncKind {
	case libpf.AsyncKindTCPAck:
		return c.handleSend(trace)
	case libpf.AsyncKindTCPReceive:
		return c.handleReceive(trace)
	default:
		return nil
	}
}

func (c *tcpSequenceCorrelator) handleSend(trace *libpf.EbpfTrace) []tcpSequenceCompletion {
	switch trace.EventKind {
	case libpf.TraceEventAsyncStart:
		call := c.callFor(trace)
		call.socket = trace.AsyncUserData
		call.threshold = trace.AsyncThreshold
		c.trackSendCallSocket(call)
		snapshot := snapshotAsyncTrace(trace)
		if call.snapshot == nil || len(snapshot.frameData) > len(call.snapshot.frameData) {
			call.snapshot = &snapshot
		}
		return c.finalizeSendCall(call)
	case libpf.TraceEventAsyncRegister:
		call := c.callFor(trace)
		call.socket = trace.AsyncUserData
		call.startSeq = trace.AsyncFlags
		call.threshold = trace.AsyncThreshold
		if trace.AsyncOperation == tcpSequenceCallBegin {
			c.trackSendCallSocket(call)
			return nil
		}
		if trace.AsyncOperation == tcpSequenceCallResult {
			call.result = trace.AsyncResult
			call.resultAt = trace.KTime
			call.resultCPU = trace.CpuID
			call.resultSeen = true
			c.trackSendCallSocket(call)
			return c.finalizeSendCall(call)
		}
	case libpf.TraceEventAsyncProgress:
		socket := tcpSequenceSocketKey{origin: trace.Origin, socket: trace.CorrelationID}
		progress := tcpSequenceProgress{
			sequence: uint32(trace.AsyncUserData), ktime: trace.KTime, cpu: trace.CpuID,
		}
		c.storeACKProgress(socket, progress)
		return c.completeAcknowledged(socket, progress)
	}
	return nil
}

func (c *tcpSequenceCorrelator) handleReceive(trace *libpf.EbpfTrace) []tcpSequenceCompletion {
	if trace.EventKind == libpf.TraceEventAsyncRegister &&
		trace.AsyncOperation == tcpSequenceRange {
		start := uint32(trace.AsyncUserData >> 32)
		end := uint32(trace.AsyncUserData)
		if start != end {
			rangeState := &tcpReceiveRange{
				socket: tcpSequenceSocketKey{origin: trace.Origin, socket: trace.CorrelationID},
				start:  start, end: end, queued: trace.KTime,
			}
			entry := &tcpSequenceEntry{
				kind: tcpSequenceEntryReceiveRange, socket: rangeState.socket,
				receive: rangeState, timestamp: trace.KTime,
			}
			rangeState.element = c.addEntry(entry)
			c.receiveRanges[rangeState.socket] = append(
				c.receiveRanges[rangeState.socket], rangeState)
			return c.finalizeReceiveCallsForSocket(rangeState.socket)
		}
		return nil
	}

	switch trace.EventKind {
	case libpf.TraceEventAsyncStart:
		call := c.callFor(trace)
		call.socket = trace.AsyncUserData
		call.threshold = trace.AsyncThreshold
		snapshot := snapshotAsyncTrace(trace)
		if call.snapshot == nil || len(snapshot.frameData) > len(call.snapshot.frameData) {
			call.snapshot = &snapshot
		}
		return c.finalizeReceiveCall(call)
	case libpf.TraceEventAsyncRegister:
		call := c.callFor(trace)
		call.socket = trace.AsyncUserData
		call.startSeq = trace.AsyncFlags
		call.threshold = trace.AsyncThreshold
		if trace.AsyncOperation == tcpSequenceCallResult {
			call.result = trace.AsyncResult
			call.resultAt = trace.KTime
			call.resultCPU = trace.CpuID
			call.resultSeen = true
			return c.finalizeReceiveCall(call)
		}
	}
	return nil
}

func (c *tcpSequenceCorrelator) callFor(trace *libpf.EbpfTrace) *tcpSequenceCall {
	key := tcpSequenceKey{origin: trace.Origin, token: trace.CorrelationID}
	if call := c.calls[key]; call != nil {
		return call
	}
	call := &tcpSequenceCall{key: key, kind: trace.AsyncKind}
	entry := &tcpSequenceEntry{
		kind: tcpSequenceEntryCall, key: key, call: call, timestamp: trace.KTime,
	}
	call.element = c.addEntry(entry)
	c.calls[key] = call
	return call
}

func (c *tcpSequenceCorrelator) trackSendCallSocket(call *tcpSequenceCall) {
	if call.socket == 0 || call.kind != libpf.AsyncKindTCPAck {
		return
	}
	entry := call.element.Value.(*tcpSequenceEntry)
	socket := tcpSequenceSocketKey{origin: call.key.origin, socket: call.socket}
	if entry.socket == socket {
		return
	}
	if entry.socket.socket != 0 {
		c.decrementSendCall(entry.socket)
	}
	entry.socket = socket
	c.sendCallCounts[socket]++
}

func (c *tcpSequenceCorrelator) finalizeSendCall(
	call *tcpSequenceCall,
) []tcpSequenceCompletion {
	if call.snapshot == nil || !call.resultSeen {
		return nil
	}
	if call.result <= 0 || call.result > math.MaxInt32 || call.socket == 0 {
		c.removeCall(call)
		return nil
	}

	rangeState := &tcpSendRange{
		key:    call.key,
		socket: tcpSequenceSocketKey{origin: call.key.origin, socket: call.socket},
		endSeq: call.startSeq + uint32(call.result),
		bytes:  call.result, threshold: call.threshold, snapshot: *call.snapshot,
	}
	progress, hasProgress := c.ackProgress[rangeState.socket]
	timestamp := call.snapshot.ktime
	c.removeCall(call)
	entry := &tcpSequenceEntry{
		kind: tcpSequenceEntrySendRange, key: rangeState.key, socket: rangeState.socket,
		send: rangeState, timestamp: timestamp,
	}
	rangeState.element = c.addEntry(entry)
	c.sendRanges[rangeState.socket] = append(c.sendRanges[rangeState.socket], rangeState)
	if hasProgress {
		c.ackProgress[rangeState.socket] = progress
		return c.completeAcknowledged(rangeState.socket, progress)
	}
	return nil
}

func (c *tcpSequenceCorrelator) finalizeReceiveCallsForSocket(
	socket tcpSequenceSocketKey,
) []tcpSequenceCompletion {
	var completed []tcpSequenceCompletion
	for _, call := range c.calls {
		if call.kind == libpf.AsyncKindTCPReceive &&
			call.key.origin == socket.origin && call.socket == socket.socket {
			completed = append(completed, c.finalizeReceiveCall(call)...)
		}
	}
	return completed
}

func (c *tcpSequenceCorrelator) finalizeReceiveCall(
	call *tcpSequenceCall,
) []tcpSequenceCompletion {
	if call.snapshot == nil || !call.resultSeen {
		return nil
	}
	if call.result <= 0 || call.result > math.MaxInt32 || call.socket == 0 {
		c.removeCall(call)
		return nil
	}

	end := call.startSeq + uint32(call.result)
	socket := tcpSequenceSocketKey{origin: call.key.origin, socket: call.socket}
	ranges := c.receiveRanges[socket]
	covered, oldest := tcpReceiveWindowCoverage(
		ranges, call.startSeq, end, uint32(call.result))
	if !covered {
		return nil
	}
	remaining := ranges[:0]
	for _, rangeState := range ranges {
		if tcpSeqLessEqual(rangeState.end, call.startSeq) {
			c.removeOrderedElement(rangeState.element)
			continue
		}
		if tcpSeqLess(rangeState.start, end) && tcpSeqLess(call.startSeq, rangeState.end) {
			if tcpSeqLessEqual(rangeState.end, end) {
				c.removeOrderedElement(rangeState.element)
				continue
			}
			if tcpSeqLess(rangeState.start, end) {
				rangeState.start = end
			}
		}
		remaining = append(remaining, rangeState)
	}
	if len(remaining) == 0 {
		delete(c.receiveRanges, socket)
	} else {
		c.receiveRanges[socket] = remaining
	}

	if oldest == 0 || call.resultAt < oldest {
		c.removeCall(call)
		c.stats.orphans++
		return nil
	}
	latency := call.resultAt - oldest
	if uint64(latency) < call.threshold {
		c.removeCall(call)
		c.stats.filtered++
		return nil
	}
	completion := tcpSequenceCompletion{
		snapshot: *call.snapshot, kind: libpf.AsyncKindTCPReceive,
		ktime: call.resultAt, cpu: call.resultCPU, value: latency, result: call.result,
	}
	c.removeCall(call)
	return []tcpSequenceCompletion{completion}
}

func (c *tcpSequenceCorrelator) storeACKProgress(
	socket tcpSequenceSocketKey, progress tcpSequenceProgress,
) {
	if _, exists := c.ackProgress[socket]; !exists && len(c.ackProgress) >= c.capacity {
		var oldestSocket tcpSequenceSocketKey
		oldestTime := int64(math.MaxInt64)
		for candidate, state := range c.ackProgress {
			if state.ktime < oldestTime {
				oldestSocket, oldestTime = candidate, state.ktime
			}
		}
		delete(c.ackProgress, oldestSocket)
		c.stats.evictions++
	}
	if previous, exists := c.ackProgress[socket]; !exists || progress.ktime >= previous.ktime {
		c.ackProgress[socket] = progress
	}
}

func (c *tcpSequenceCorrelator) completeAcknowledged(
	socket tcpSequenceSocketKey, progress tcpSequenceProgress,
) []tcpSequenceCompletion {
	ranges := c.sendRanges[socket]
	if len(ranges) == 0 {
		return nil
	}
	remaining := ranges[:0]
	completed := make([]tcpSequenceCompletion, 0, len(ranges))
	for _, rangeState := range ranges {
		if !tcpSeqLessEqual(rangeState.endSeq, progress.sequence) ||
			progress.ktime < rangeState.snapshot.ktime {
			remaining = append(remaining, rangeState)
			continue
		}
		latency := progress.ktime - rangeState.snapshot.ktime
		c.removeOrderedElement(rangeState.element)
		if uint64(latency) < rangeState.threshold {
			c.stats.filtered++
			continue
		}
		completed = append(completed, tcpSequenceCompletion{
			snapshot: rangeState.snapshot, kind: libpf.AsyncKindTCPAck,
			ktime: progress.ktime, cpu: progress.cpu, value: latency,
			result: rangeState.bytes,
		})
	}
	if len(remaining) == 0 {
		delete(c.sendRanges, socket)
		if c.sendCallCounts[socket] == 0 {
			delete(c.ackProgress, socket)
		}
	} else {
		c.sendRanges[socket] = remaining
	}
	return completed
}

func tcpSequenceEventSocket(trace *libpf.EbpfTrace) tcpSequenceSocketKey {
	socket := trace.AsyncUserData
	if trace.EventKind == libpf.TraceEventAsyncProgress ||
		(trace.AsyncKind == libpf.AsyncKindTCPReceive &&
			trace.AsyncOperation == tcpSequenceRange) {
		socket = trace.CorrelationID
	}
	return tcpSequenceSocketKey{origin: trace.Origin, socket: socket}
}

func (c *tcpSequenceCorrelator) recordReset(socket tcpSequenceSocketKey, ktime int64) {
	if socket.socket == 0 {
		return
	}
	if _, exists := c.resets[socket]; !exists && len(c.resets) >= c.capacity {
		var oldestSocket tcpSequenceSocketKey
		oldestTime := int64(math.MaxInt64)
		for candidate, timestamp := range c.resets {
			if timestamp < oldestTime {
				oldestSocket, oldestTime = candidate, timestamp
			}
		}
		delete(c.resets, oldestSocket)
		c.stats.evictions++
	}
	if c.resets[socket] < ktime {
		c.resets[socket] = ktime
	}
}

func (c *tcpSequenceCorrelator) clearSocket(
	kind libpf.AsyncKind, socket tcpSequenceSocketKey,
) {
	for _, call := range c.calls {
		if call.kind == kind && call.key.origin == socket.origin &&
			call.socket == socket.socket {
			c.removeCall(call)
		}
	}
	if kind == libpf.AsyncKindTCPAck {
		for _, rangeState := range c.sendRanges[socket] {
			c.removeOrderedElement(rangeState.element)
		}
		delete(c.sendRanges, socket)
		delete(c.sendCallCounts, socket)
		delete(c.ackProgress, socket)
		return
	}
	for _, rangeState := range c.receiveRanges[socket] {
		c.removeOrderedElement(rangeState.element)
	}
	delete(c.receiveRanges, socket)
}

func (c *tcpSequenceCorrelator) addEntry(entry *tcpSequenceEntry) *list.Element {
	for c.order.Len() >= c.capacity {
		c.removeEntry(c.order.Front())
		c.stats.evictions++
	}
	return c.order.PushBack(entry)
}

func (c *tcpSequenceCorrelator) removeCall(call *tcpSequenceCall) {
	if call == nil || call.element == nil {
		return
	}
	c.removeEntry(call.element)
}

func (c *tcpSequenceCorrelator) removeOrderedElement(element *list.Element) {
	if element != nil {
		c.order.Remove(element)
	}
}

func (c *tcpSequenceCorrelator) removeEntry(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*tcpSequenceEntry)
	c.order.Remove(element)
	switch entry.kind {
	case tcpSequenceEntryCall:
		if c.calls[entry.key] == entry.call {
			delete(c.calls, entry.key)
		}
		if entry.socket.socket != 0 && entry.call.kind == libpf.AsyncKindTCPAck {
			c.decrementSendCall(entry.socket)
		}
	case tcpSequenceEntrySendRange:
		ranges := c.sendRanges[entry.socket]
		for i, candidate := range ranges {
			if candidate == entry.send {
				ranges = append(ranges[:i], ranges[i+1:]...)
				break
			}
		}
		if len(ranges) == 0 {
			delete(c.sendRanges, entry.socket)
			if c.sendCallCounts[entry.socket] == 0 {
				delete(c.ackProgress, entry.socket)
			}
		} else {
			c.sendRanges[entry.socket] = ranges
		}
	case tcpSequenceEntryReceiveRange:
		ranges := c.receiveRanges[entry.socket]
		for i, candidate := range ranges {
			if candidate == entry.receive {
				ranges = append(ranges[:i], ranges[i+1:]...)
				break
			}
		}
		if len(ranges) == 0 {
			delete(c.receiveRanges, entry.socket)
		} else {
			c.receiveRanges[entry.socket] = ranges
		}
	}
}

func (c *tcpSequenceCorrelator) decrementSendCall(socket tcpSequenceSocketKey) {
	count := c.sendCallCounts[socket] - 1
	if count <= 0 {
		delete(c.sendCallCounts, socket)
		if len(c.sendRanges[socket]) == 0 {
			delete(c.ackProgress, socket)
		}
		return
	}
	c.sendCallCounts[socket] = count
}

func (c *tcpSequenceCorrelator) prune(now int64) {
	cutoff := now - c.ttl.Nanoseconds()
	for socket, resetAt := range c.resets {
		if resetAt < cutoff {
			delete(c.resets, socket)
		}
	}
	for socket, progress := range c.ackProgress {
		if progress.ktime < cutoff {
			delete(c.ackProgress, socket)
			c.stats.evictions++
		}
	}
	for element := c.order.Front(); element != nil; {
		next := element.Next()
		entry := element.Value.(*tcpSequenceEntry)
		if entry.timestamp < cutoff {
			c.removeEntry(element)
			c.stats.evictions++
		}
		element = next
	}
}

func (c *tcpSequenceCorrelator) getAndResetMetrics() []metrics.Metric {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(int64(times.GetKTime()))
	result := []metrics.Metric{
		{ID: metrics.IDTCPSequenceCorrelationOrphans, Value: metrics.MetricValue(c.stats.orphans)},
		{ID: metrics.IDTCPSequenceCorrelationEvictions, Value: metrics.MetricValue(c.stats.evictions)},
		{ID: metrics.IDTCPSequenceCorrelationFiltered, Value: metrics.MetricValue(c.stats.filtered)},
		{ID: metrics.IDTCPSequenceCorrelationPending, Value: metrics.MetricValue(c.order.Len() + len(c.ackProgress))},
	}
	c.stats = tcpSequenceStats{}
	return result
}

type tcpSequenceInterval struct {
	start uint32
	end   uint32
}

func tcpReceiveWindowCoverage(
	ranges []*tcpReceiveRange, start, end, size uint32,
) (bool, int64) {
	intervals := make([]tcpSequenceInterval, 0, len(ranges))
	oldest := int64(0)
	for _, rangeState := range ranges {
		if !tcpSeqLess(rangeState.start, end) || !tcpSeqLess(start, rangeState.end) {
			continue
		}
		overlapStart := rangeState.start
		if tcpSeqLess(overlapStart, start) {
			overlapStart = start
		}
		overlapEnd := rangeState.end
		if tcpSeqLess(end, overlapEnd) {
			overlapEnd = end
		}
		intervals = append(intervals, tcpSequenceInterval{
			start: overlapStart - start, end: overlapEnd - start,
		})
		if oldest == 0 || rangeState.queued < oldest {
			oldest = rangeState.queued
		}
	}
	if len(intervals) == 0 {
		return false, 0
	}
	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i].start < intervals[j].start
	})
	covered := uint32(0)
	currentStart, currentEnd := intervals[0].start, intervals[0].end
	for _, interval := range intervals[1:] {
		if interval.start > currentEnd {
			covered += currentEnd - currentStart
			currentStart, currentEnd = interval.start, interval.end
			continue
		}
		if interval.end > currentEnd {
			currentEnd = interval.end
		}
	}
	covered += currentEnd - currentStart
	return covered >= size, oldest
}

func tcpSeqLess(left, right uint32) bool {
	return int32(left-right) < 0
}

func tcpSeqLessEqual(left, right uint32) bool {
	return int32(left-right) <= 0
}
