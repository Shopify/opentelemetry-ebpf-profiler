// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"container/list"
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/times"
)

const (
	defaultAsyncCorrelationCapacity = 16 * 1024
	defaultAsyncCorrelationTTL      = 5 * time.Minute
)

type asyncTraceKey struct {
	origin        uint16
	correlationID uint64
}

type asyncTraceSnapshot struct {
	envVars          map[libpf.String]libpf.String
	processName      libpf.String
	executablePath   libpf.String
	containerID      libpf.String
	customLabels     map[libpf.String]libpf.String
	comm             libpf.Comm
	frameData        []uint64
	kernelFrames     libpf.Frames
	value            int64
	ktime            int64
	cpuID            uint32
	tid              libpf.PID
	pid              libpf.PID
	numFrames        uint16
	origin           uint16
	apmTraceID       libpf.APMTraceID
	apmTransactionID libpf.APMTransactionID
	correlationID    uint64
	asyncUserData    uint64
	asyncOperation   uint16
	asyncKind        libpf.AsyncKind
	asyncAttributes  libpf.AsyncAttributes
}

func snapshotAsyncTrace(trace *libpf.EbpfTrace) asyncTraceSnapshot {
	return asyncTraceSnapshot{
		envVars:          trace.EnvVars,
		processName:      trace.ProcessName,
		executablePath:   trace.ExecutablePath,
		containerID:      trace.ContainerID,
		customLabels:     cloneLabels(trace.CustomLabels),
		comm:             trace.Comm,
		frameData:        append([]uint64(nil), trace.FrameData...),
		kernelFrames:     append(libpf.Frames(nil), trace.KernelFrames...),
		value:            trace.Value,
		ktime:            trace.KTime,
		cpuID:            trace.CpuID,
		tid:              trace.TID,
		pid:              trace.PID,
		numFrames:        trace.NumFrames,
		origin:           trace.Origin,
		apmTraceID:       trace.APMTraceID,
		apmTransactionID: trace.APMTransactionID,
		correlationID:    trace.CorrelationID,
		asyncUserData:    trace.AsyncUserData,
		asyncOperation:   trace.AsyncOperation,
		asyncKind:        trace.AsyncKind,
		asyncAttributes:  trace.AsyncAttributes,
	}
}

func (s *asyncTraceSnapshot) restore(trace *libpf.EbpfTrace) {
	*trace = libpf.EbpfTrace{
		EnvVars:          s.envVars,
		ProcessName:      s.processName,
		ExecutablePath:   s.executablePath,
		ContainerID:      s.containerID,
		CustomLabels:     cloneLabels(s.customLabels),
		Comm:             s.comm,
		KernelFrames:     append(trace.KernelFrames[:0], s.kernelFrames...),
		Value:            s.value,
		KTime:            s.ktime,
		CpuID:            s.cpuID,
		TID:              s.tid,
		PID:              s.pid,
		NumFrames:        s.numFrames,
		Origin:           s.origin,
		APMTraceID:       s.apmTraceID,
		APMTransactionID: s.apmTransactionID,
		CorrelationID:    s.correlationID,
		AsyncUserData:    s.asyncUserData,
		AsyncOperation:   s.asyncOperation,
		AsyncKind:        s.asyncKind,
		AsyncAttributes:  s.asyncAttributes,
	}
	trace.FrameData = trace.FrameDataBuf[:len(s.frameData)]
	copy(trace.FrameData, s.frameData)
}

func cloneLabels(labels map[libpf.String]libpf.String) map[libpf.String]libpf.String {
	if len(labels) == 0 {
		return nil
	}
	cloned := make(map[libpf.String]libpf.String, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

type asyncPendingEntry struct {
	key      asyncTraceKey
	snapshot asyncTraceSnapshot
}

type asyncCorrelatorStats struct {
	starts              uint64
	completions         uint64
	duplicateStarts     uint64
	orphanCompletions   uint64
	capacityEvictions   uint64
	expirationEvictions uint64
}

// asyncTraceCorrelator joins bounded asynchronous completion events to compact
// copies of their initiating traces.
type asyncTraceCorrelator struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	pending  map[asyncTraceKey]*list.Element
	order    *list.List
	stats    asyncCorrelatorStats
}

func newAsyncTraceCorrelator(capacity int, ttl time.Duration) *asyncTraceCorrelator {
	return &asyncTraceCorrelator{
		capacity: capacity,
		ttl:      ttl,
		pending:  make(map[asyncTraceKey]*list.Element, max(capacity, 0)),
		order:    list.New(),
	}
}

func (c *asyncTraceCorrelator) add(trace *libpf.EbpfTrace) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(trace.KTime)
	c.stats.starts++

	key := asyncTraceKey{origin: trace.Origin, correlationID: trace.CorrelationID}
	if existing, ok := c.pending[key]; ok {
		c.stats.duplicateStarts++
		entry := existing.Value.(*asyncPendingEntry)
		// A tracepoint fallback can arrive immediately before a fully unwound
		// kprobe trace. Retain whichever start carries more user frame data.
		if len(trace.FrameData) > len(entry.snapshot.frameData) {
			entry.snapshot = snapshotAsyncTrace(trace)
		}
		return
	}
	if c.capacity <= 0 {
		c.stats.capacityEvictions++
		return
	}
	for len(c.pending) >= c.capacity {
		c.removeOldest(false)
	}
	entry := &asyncPendingEntry{key: key, snapshot: snapshotAsyncTrace(trace)}
	c.pending[key] = c.order.PushBack(entry)
}

// complete restores the initiating trace into completion. It returns false for
// an orphan completion. Multishot operations remain pending until the final
// completion no longer carries AsyncAttrMore.
func (c *asyncTraceCorrelator) complete(completion *libpf.EbpfTrace) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(completion.KTime)
	key := asyncTraceKey{
		origin:        completion.Origin,
		correlationID: completion.CorrelationID,
	}
	element, ok := c.pending[key]
	if !ok {
		c.stats.orphanCompletions++
		return false
	}

	completionValue := completion.Value
	completionKTime := completion.KTime
	completionCPU := completion.CpuID
	completionResult := completion.AsyncResult
	completionFlags := completion.AsyncFlags
	completionOperation := completion.AsyncOperation
	completionUserData := completion.AsyncUserData
	completionKind := completion.AsyncKind
	completionAttributes := completion.AsyncAttributes
	completionLabels := cloneLabels(completion.CustomLabels)

	entry := element.Value.(*asyncPendingEntry)
	entry.snapshot.restore(completion)
	completion.Value = completionValue
	completion.KTime = completionKTime
	completion.CpuID = completionCPU
	completion.AsyncResult = completionResult
	completion.AsyncFlags = completionFlags
	completion.AsyncOperation = completionOperation
	completion.AsyncUserData = completionUserData
	completion.AsyncKind = completionKind
	completion.AsyncAttributes |= completionAttributes
	completion.EventKind = libpf.TraceEventNormal
	for key, value := range completionLabels {
		if completion.CustomLabels == nil {
			completion.CustomLabels = make(map[libpf.String]libpf.String)
		}
		completion.CustomLabels[key] = value
	}
	addAsyncLabels(completion)

	c.stats.completions++
	if completionAttributes&libpf.AsyncAttrMore == 0 {
		delete(c.pending, key)
		c.order.Remove(element)
	}
	return true
}

func (c *asyncTraceCorrelator) expire(now int64) {
	if c.ttl <= 0 || now <= 0 {
		return
	}
	for {
		front := c.order.Front()
		if front == nil {
			return
		}
		entry := front.Value.(*asyncPendingEntry)
		if entry.snapshot.ktime <= 0 || now-entry.snapshot.ktime <= int64(c.ttl) {
			return
		}
		c.removeOldest(true)
	}
}

func (c *asyncTraceCorrelator) getAndResetMetrics() []metrics.Metric {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(int64(times.GetKTime()))
	updates := []metrics.Metric{
		{ID: metrics.IDAsyncCorrelationStarts, Value: metrics.MetricValue(c.stats.starts)},
		{ID: metrics.IDAsyncCorrelationCompletions, Value: metrics.MetricValue(c.stats.completions)},
		{ID: metrics.IDAsyncCorrelationDuplicateStarts, Value: metrics.MetricValue(c.stats.duplicateStarts)},
		{ID: metrics.IDAsyncCorrelationOrphanCompletions, Value: metrics.MetricValue(c.stats.orphanCompletions)},
		{ID: metrics.IDAsyncCorrelationCapacityEvictions, Value: metrics.MetricValue(c.stats.capacityEvictions)},
		{ID: metrics.IDAsyncCorrelationExpirationEvictions, Value: metrics.MetricValue(c.stats.expirationEvictions)},
		{ID: metrics.IDAsyncCorrelationPending, Value: metrics.MetricValue(len(c.pending))},
	}
	c.stats = asyncCorrelatorStats{}
	return updates
}

func (c *asyncTraceCorrelator) removeOldest(expired bool) {
	front := c.order.Front()
	if front == nil {
		return
	}
	entry := front.Value.(*asyncPendingEntry)
	delete(c.pending, entry.key)
	c.order.Remove(front)
	if expired {
		c.stats.expirationEvictions++
	} else {
		c.stats.capacityEvictions++
	}
}

func addAsyncLabels(trace *libpf.EbpfTrace) {
	if trace.AsyncKind != libpf.AsyncKindIOUring {
		return
	}
	if trace.CustomLabels == nil {
		trace.CustomLabels = make(map[libpf.String]libpf.String, 5)
	}
	trace.CustomLabels[libpf.Intern("io.operation")] =
		libpf.Intern(ioUringOperationName(trace.AsyncOperation))
	trace.CustomLabels[libpf.Intern("io.result")] =
		libpf.Intern(strconv.FormatInt(trace.AsyncResult, 10))
	trace.CustomLabels[libpf.Intern("io.completion_flags")] =
		libpf.Intern(fmt.Sprintf("0x%x", trace.AsyncFlags))
	if trace.AsyncAttributes&libpf.AsyncAttrSQPoll != 0 {
		trace.CustomLabels[libpf.Intern("io_uring.sq_poll")] = libpf.Intern("true")
	}
	if trace.AsyncResult == -125 {
		trace.CustomLabels[libpf.Intern("io.status")] = libpf.Intern("cancelled")
	} else if trace.AsyncResult < 0 {
		trace.CustomLabels[libpf.Intern("io.status")] = libpf.Intern("error")
	} else {
		trace.CustomLabels[libpf.Intern("io.status")] = libpf.Intern("ok")
	}
}

func ioUringOperationName(operation uint16) string {
	// Values are stable Linux UAPI IORING_OP_* identifiers.
	names := [...]string{
		"nop", "readv", "writev", "fsync", "read_fixed", "write_fixed",
		"poll_add", "poll_remove", "sync_file_range", "sendmsg", "recvmsg",
		"timeout", "timeout_remove", "accept", "async_cancel", "link_timeout",
		"connect", "fallocate", "openat", "close", "files_update", "statx",
		"read", "write", "fadvise", "madvise", "send", "recv", "openat2",
		"epoll_ctl", "splice", "provide_buffers", "remove_buffers", "tee",
		"shutdown", "renameat", "unlinkat", "mkdirat", "symlinkat", "linkat",
		"msg_ring", "fsetxattr", "setxattr", "fgetxattr", "getxattr", "socket",
		"uring_cmd", "send_zc", "sendmsg_zc", "read_multishot", "waitid",
		"futex_wait", "futex_wake", "futex_waitv", "fixed_fd_install",
		"ftruncate", "bind", "listen", "recv_zc", "epoll_wait",
		"readv_fixed", "writev_fixed",
	}
	if int(operation) < len(names) {
		return names[operation]
	}
	return strconv.FormatUint(uint64(operation), 10)
}
