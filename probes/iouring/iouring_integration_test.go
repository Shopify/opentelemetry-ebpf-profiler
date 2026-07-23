//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package iouring

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/sys/unix"
)

type integrationIntervals struct{}

func (integrationIntervals) MonitorInterval() time.Duration       { return time.Second }
func (integrationIntervals) TracePollInterval() time.Duration     { return 10 * time.Millisecond }
func (integrationIntervals) PIDCleanupInterval() time.Duration    { return time.Second }
func (integrationIntervals) ExecutableUnloadDelay() time.Duration { return time.Second }

type reportedTrace struct {
	trace *libpf.Trace
	meta  *samples.TraceEventMeta
}

type captureReporter struct {
	traces chan reportedTrace
}

func (r *captureReporter) ReportTraceEvent(
	trace *libpf.Trace, meta *samples.TraceEventMeta,
) error {
	copiedTrace := &libpf.Trace{
		CustomLabels: make(map[libpf.String]libpf.String, len(trace.CustomLabels)),
		Frames:       append(libpf.Frames(nil), trace.Frames...),
	}
	for key, value := range trace.CustomLabels {
		copiedTrace.CustomLabels[key] = value
	}
	copiedMeta := *meta
	select {
	case r.traces <- reportedTrace{trace: copiedTrace, meta: &copiedMeta}:
	default:
	}
	return nil
}

var startMetricsOnce sync.Once

func TestIOUringSubmissionToCQE(t *testing.T) {
	if _, err := discoverLayout(tracefsEventRoots); err != nil {
		t.Skipf("io_uring tracepoints unavailable: %v", err)
	}
	if err := submitNOP(0x1234); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("io_uring unavailable: %v", err)
		}
		require.NoError(t, err)
	}

	startMetricsOnce.Do(func() { metrics.Start(noop.Meter{}) })
	reporter := &captureReporter{traces: make(chan reportedTrace, 128)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		TraceReporter:          reporter,
		Intervals:              integrationIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		SamplesPerSecond:       20,
		FrameCacheSize:         1024,
		ProbabilisticInterval:  time.Minute,
		ProbabilisticThreshold: tracer.ProbabilisticThresholdMax,
		LoadProbe:              true,
	})
	require.NoError(t, err)
	defer trc.Close()

	trc.StartPIDEventProcessor(ctx)
	traces := make(chan *libpf.EbpfTrace, 4096)
	require.NoError(t, trc.StartMapMonitors(ctx, traces))
	go func() {
		for {
			select {
			case trace, ok := <-traces:
				if !ok {
					return
				}
				if trace != nil {
					trc.HandleTrace(trace)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	created, err := New(map[string]any{})
	require.NoError(t, err)
	require.NoError(t, trc.Enable(created))

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for attempt := uint64(0); ; attempt++ {
		require.NoError(t, submitNOP(0xfeed0000+attempt))
		select {
		case reported := <-reporter.traces:
			if reported.meta.ProfileType.SampleType != SampleType {
				continue
			}
			require.Positive(t, reported.meta.Value)
			require.NotEmpty(t, reported.trace.Frames)
			hasUserFrame := false
			for _, frame := range reported.trace.Frames {
				if frame.Value().Type != libpf.KernelFrame {
					hasUserFrame = true
					break
				}
			}
			if !hasUserFrame {
				// The first request can race initial process-mapping discovery.
				continue
			}
			require.Equal(t, libpf.Intern("nop"),
				reported.trace.CustomLabels[libpf.Intern("io.operation")])
			require.Equal(t, libpf.Intern("0"),
				reported.trace.CustomLabels[libpf.Intern("io.result")])
			return
		case <-deadline.C:
			t.Fatal("timed out waiting for an io_uring completion profile")
		default:
		}
	}
}

const (
	ioUringOffSQRing      = int64(0)
	ioUringOffCQRing      = int64(0x8000000)
	ioUringOffSQEs        = int64(0x10000000)
	ioUringFeatSingleMMap = uint32(1)
	ioUringEnterGetEvents = uintptr(1)
	ioUringSQESize        = uint32(64)
	ioUringCQESize        = uint32(16)
)

type ioUringSQOffsets struct {
	head, tail, ringMask, ringEntries, flags, dropped, array, reserved uint32
	userAddress                                                        uint64
}

type ioUringCQOffsets struct {
	head, tail, ringMask, ringEntries, overflow, cqes, flags, reserved uint32
	userAddress                                                        uint64
}

type ioUringParams struct {
	sqEntries, cqEntries, flags, sqThreadCPU, sqThreadIdle, features, wqFD uint32
	reserved                                                               [3]uint32
	sqOffsets                                                              ioUringSQOffsets
	cqOffsets                                                              ioUringCQOffsets
}

func submitNOP(userData uint64) error {
	var params ioUringParams
	fd, _, errno := unix.Syscall(
		unix.SYS_IO_URING_SETUP, 8, uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return errno
	}
	defer unix.Close(int(fd))

	sqSize := params.sqOffsets.array + params.sqEntries*4
	cqSize := params.cqOffsets.cqes + params.cqEntries*ioUringCQESize
	mmapFlags := unix.MAP_SHARED | unix.MAP_POPULATE
	var sqRing, cqRing []byte
	var err error
	if params.features&ioUringFeatSingleMMap != 0 {
		ringSize := max(sqSize, cqSize)
		sqRing, err = unix.Mmap(int(fd), ioUringOffSQRing, int(ringSize),
			unix.PROT_READ|unix.PROT_WRITE, mmapFlags)
		if err != nil {
			return err
		}
		cqRing = sqRing
		defer unix.Munmap(sqRing)
	} else {
		sqRing, err = unix.Mmap(int(fd), ioUringOffSQRing, int(sqSize),
			unix.PROT_READ|unix.PROT_WRITE, mmapFlags)
		if err != nil {
			return err
		}
		defer unix.Munmap(sqRing)
		cqRing, err = unix.Mmap(int(fd), ioUringOffCQRing, int(cqSize),
			unix.PROT_READ|unix.PROT_WRITE, mmapFlags)
		if err != nil {
			return err
		}
		defer unix.Munmap(cqRing)
	}
	sqes, err := unix.Mmap(int(fd), ioUringOffSQEs,
		int(params.sqEntries*ioUringSQESize), unix.PROT_READ|unix.PROT_WRITE, mmapFlags)
	if err != nil {
		return err
	}
	defer unix.Munmap(sqes)

	sqHead := uint32At(sqRing, params.sqOffsets.head)
	sqTail := uint32At(sqRing, params.sqOffsets.tail)
	sqMask := uint32At(sqRing, params.sqOffsets.ringMask)
	sqArray := uint32At(sqRing, params.sqOffsets.array)
	tail := atomic.LoadUint32(sqTail)
	if tail-atomic.LoadUint32(sqHead) >= params.sqEntries {
		return errors.New("io_uring submission queue is full")
	}
	index := tail & *sqMask
	sqe := sqes[index*ioUringSQESize : (index+1)*ioUringSQESize]
	clear(sqe)
	binary.NativeEndian.PutUint64(sqe[32:40], userData)
	*(*uint32)(unsafe.Add(unsafe.Pointer(sqArray), uintptr(index*4))) = index
	atomic.StoreUint32(sqTail, tail+1)

	_, _, errno = unix.Syscall6(
		unix.SYS_IO_URING_ENTER, fd, 1, 1, ioUringEnterGetEvents, 0, 0)
	if errno != 0 {
		return errno
	}

	cqHead := uint32At(cqRing, params.cqOffsets.head)
	cqTail := uint32At(cqRing, params.cqOffsets.tail)
	if atomic.LoadUint32(cqHead) == atomic.LoadUint32(cqTail) {
		return errors.New("io_uring returned no completion")
	}
	cqMask := uint32At(cqRing, params.cqOffsets.ringMask)
	cqeIndex := atomic.LoadUint32(cqHead) & *cqMask
	cqeOffset := params.cqOffsets.cqes + cqeIndex*ioUringCQESize
	result := int32(binary.NativeEndian.Uint32(cqRing[cqeOffset+8 : cqeOffset+12]))
	atomic.StoreUint32(cqHead, atomic.LoadUint32(cqHead)+1)
	if result < 0 {
		return fmt.Errorf("io_uring NOP failed: %w", unix.Errno(-result))
	}
	return nil
}

func uint32At(buffer []byte, offset uint32) *uint32 {
	return (*uint32)(unsafe.Add(unsafe.Pointer(&buffer[0]), uintptr(offset)))
}
