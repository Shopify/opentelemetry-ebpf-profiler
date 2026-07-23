//go:build integration && linux && cgo

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package lockwait

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/probes/functionlatency"
	"go.opentelemetry.io/ebpf-profiler/probes/usertarget"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/otel/metric/noop"
)

type integrationIntervals struct{}

var startMetricsOnce sync.Once

func (integrationIntervals) MonitorInterval() time.Duration       { return time.Second }
func (integrationIntervals) TracePollInterval() time.Duration     { return 10 * time.Millisecond }
func (integrationIntervals) PIDCleanupInterval() time.Duration    { return time.Second }
func (integrationIntervals) ExecutableUnloadDelay() time.Duration { return time.Second }

type originCaptureProbe struct {
	tracer.Probe
	origin uint16
}

func (probe *originCaptureProbe) Load(origin uint16, ctx *tracer.ProbeContext) (link.Link, error) {
	probe.origin = origin
	return probe.Probe.Load(origin, ctx)
}

type discardTraceReporter struct{}

func (discardTraceReporter) ReportTraceEvent(*libpf.Trace, *samples.TraceEventMeta) error {
	return nil
}

func integrationTargetOffset(t *testing.T, path string, address uint64) (string, uint64) {
	t.Helper()
	parsed, err := pfelf.Open(path)
	require.NoError(t, err)
	defer parsed.Close()
	buildID, err := parsed.GetBuildID()
	require.NoError(t, err)

	pid := libpf.PID(os.Getpid())
	current := process.New(pid, pid)
	defer current.Close()
	var offset uint64
	_, err = current.IterateMappings(func(mapping process.RawMapping) bool {
		if mapping.IsExecutable() && address >= mapping.Vaddr &&
			address-mapping.Vaddr < mapping.Length {
			offset = mapping.FileOffset + address - mapping.Vaddr
		}
		return true
	})
	require.NoError(t, err)
	require.NotZero(t, offset, "target address has no executable mapping")
	return buildID, offset
}

func metricsByID(values []metrics.Metric) map[metrics.MetricID]metrics.MetricValue {
	result := make(map[metrics.MetricID]metrics.MetricValue, len(values))
	for _, value := range values {
		result[value.ID] = value.Value
	}
	return result
}

func TestLockWaitMetricsResetProcess(t *testing.T) {
	restore, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restore()

	starts, err := cebpf.NewMap(&cebpf.MapSpec{
		Type: cebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 16,
	})
	require.NoError(t, err)
	defer starts.Close()
	metricsMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Type: cebpf.PerCPUArray, KeySize: 4,
		ValueSize: uint32(unsafe.Sizeof(lockWaitBPFMetrics{})), MaxEntries: 1,
	})
	require.NoError(t, err)
	defer metricsMap.Close()

	collector, err := newLockWaitMetricsCollector(metricsMap, starts)
	require.NoError(t, err)
	perCPU := make([]lockWaitBPFMetrics, len(collector.perCPUValues))
	perCPU[0] = lockWaitBPFMetrics{Entries: 4, Returns: 1, ActiveStates: 3}
	zero := uint32(0)
	require.NoError(t, metricsMap.Update(&zero, perCPU, cebpf.UpdateAny))

	pid := libpf.PID(41)
	keys := []uint64{
		uint64(pid)<<32 | 1,
		uint64(pid)<<32 | 2,
		uint64(libpf.PID(42))<<32 | 1,
	}
	timestamp := uint64(100)
	for _, key := range keys {
		require.NoError(t, starts.Update(&key, &timestamp, cebpf.UpdateAny))
	}
	require.Equal(t, metrics.MetricValue(3),
		metricsByID(collector.Collect())[metrics.IDLockWaitActiveStates])

	require.NoError(t, collector.ResetProcess(pid))
	for _, key := range keys[:2] {
		require.ErrorIs(t, starts.Lookup(&key, &timestamp), cebpf.ErrKeyNotExist)
	}
	require.NoError(t, starts.Lookup(&keys[2], &timestamp))
	second := metricsByID(collector.Collect())
	require.Equal(t, metrics.MetricValue(0), second[metrics.IDLockWaitEntries])
	require.Equal(t, metrics.MetricValue(1), second[metrics.IDLockWaitActiveStates])

	previous := collector.previous
	require.NoError(t, metricsMap.Close())
	failed := collector.Collect()
	require.Equal(t, []metrics.Metric{{
		ID: metrics.IDLockWaitMetricReadFailures, Value: 1,
	}}, failed)
	require.Equal(t, previous, collector.previous)
}

func TestLockWaitProbe(t *testing.T) {
	startMetricsOnce.Do(func() { metrics.Start(noop.Meter{}) })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		TraceReporter:          discardTraceReporter{},
		Intervals:              integrationIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		SamplesPerSecond:       50,
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

	executable, err := os.Executable()
	require.NoError(t, err)
	buildID, targetOffset := integrationTargetOffset(t, executable, lockWaitCTargetAddress())
	created, err := New(Definition{
		Target: usertarget.Target{
			Name:     "integration-lock-wait",
			Process:  usertarget.ProcessSelector{ExecutablePath: executable},
			Object:   usertarget.ObjectSelector{Path: executable, BuildID: buildID},
			Offsets:  []usertarget.BuildIDOffset{{BuildID: buildID, FileOffset: targetOffset}},
			MaxLinks: 4,
		},
		Labels: Labels{Kind: "test", Mode: "exclusive", Operation: "lock"},
		ABI: ABI{
			ReturnValueMode:        ReturnValueSigned32,
			SuccessfulReturnValues: []int64{-7},
		},
	}, map[string]any{"min_duration": "4ms"})
	require.NoError(t, err)
	probe := &originCaptureProbe{Probe: created}
	require.NoError(t, trc.Enable(probe))

	// Drive production mapping synchronization for this process before the
	// userspace target is attached.
	discoveryProbe, err := functionlatency.New(functionlatency.Definition{
		Symbol: "vfs_read", SampleType: "lockwait_test_discovery",
	}, nil)
	require.NoError(t, err)
	require.NoError(t, trc.Enable(discoveryProbe))

	pid := libpf.PID(os.Getpid())
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		_, err := os.ReadFile("/proc/self/stat")
		require.NoError(t, err)
		callLockWaitCTarget(uint64(5 * time.Millisecond))

		select {
		case trace, ok := <-traces:
			require.True(t, ok, "trace monitor stopped")
			if trace == nil {
				continue
			}
			matched := trace.PID == pid && trace.Origin == probe.origin &&
				trace.Value >= int64(4*time.Millisecond)
			if matched {
				require.NotEmpty(t, trace.FrameData)
				require.Positive(t, trace.NumFrames)
			}
			// Production controllers feed traces back into the process manager;
			// this is what synchronizes mappings and publishes process events.
			if trace.PID == pid {
				trc.HandleTrace(trace)
			}
			if matched {
				return
			}
		case <-deadline.C:
			t.Fatal("timed out waiting for a userspace lock-wait latency trace")
		default:
		}
	}
}
