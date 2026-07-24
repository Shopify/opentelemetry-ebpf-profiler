//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package offcpu

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/otel/metric/noop"
)

type integrationIntervals struct{}

var startMetricsOnce sync.Once

func (integrationIntervals) MonitorInterval() time.Duration       { return time.Second }
func (integrationIntervals) TracePollInterval() time.Duration     { return 10 * time.Millisecond }
func (integrationIntervals) PIDCleanupInterval() time.Duration    { return time.Second }
func (integrationIntervals) ExecutableUnloadDelay() time.Duration { return time.Second }

func newIntegrationTracer(t *testing.T) (*tracer.Tracer, context.CancelFunc, chan *libpf.EbpfTrace) {
	t.Helper()
	startMetricsOnce.Do(func() { metrics.Start(noop.Meter{}) })

	ctx, cancel := context.WithCancel(t.Context())

	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:                    integrationIntervals{},
		InterpretersConfig:           interpreterconfig.AllInterpreters(),
		SamplesPerSecond:             20,
		FrameCacheSize:               1024,
		ProbabilisticInterval:        time.Minute,
		ProbabilisticThreshold:       tracer.ProbabilisticThresholdMax,
		LoadProbe:                    true,
		DynamicProbeResourcePrefixes: []string{SampleType},
	})
	require.NoError(t, err)

	trc.StartPIDEventProcessor(ctx)
	traces := make(chan *libpf.EbpfTrace, 4096)
	require.NoError(t, trc.StartMapMonitors(ctx, traces))
	return trc, cancel, traces
}

func TestOffCPUTimeProbe(t *testing.T) {
	trc, cancel, traces := newIntegrationTracer(t)
	defer cancel()
	defer trc.Close()

	minDuration := 20 * time.Millisecond
	probe, err := New(map[string]any{"min_duration": minDuration.String()})
	require.NoError(t, err)
	labeler, ok := probe.(tracer.TraceLabeler)
	require.True(t, ok, "off-cpu probe must implement tracer.TraceLabeler")
	require.NoError(t, trc.Enable(probe))

	// Block a thread of this process well past min_duration in a loop. Each
	// timer wakeup switches the sleeping thread back in and emits a sample
	// carrying the measured off-CPU nanoseconds.
	sleeperDone := make(chan struct{})
	defer close(sleeperDone)
	go func() {
		for {
			select {
			case <-sleeperDone:
				return
			default:
				time.Sleep(3 * minDuration)
			}
		}
	}()

	// Drain the channel at full speed: the probe observes the whole system,
	// so this process's samples arrive interleaved with everything else's.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	pid := libpf.PID(os.Getpid())
	for {
		select {
		case trace := <-traces:
			if trace == nil || trace.PID != pid {
				continue
			}
			// CPU-sampling traces from this process carry no value; only
			// off-CPU time samples report a duration past the threshold.
			if trace.Value < int64(minDuration) {
				continue
			}
			require.NotEmpty(t, trace.KernelFrames)
			require.NotEmpty(t, trace.FrameData)
			require.Positive(t, trace.NumFrames)

			// The sleeper blocks in nanosleep, so its switch-out state must
			// have been captured as TASK_INTERRUPTIBLE. Wait for one such
			// sample; other threads of this process may block differently.
			if trace.ProbeUserData != 0x0001 {
				continue
			}
			// The raw monitor channel taps traces before Tracer.HandleTrace
			// runs the labeler, so apply it directly to prove the state
			// reaches the sample label.
			labeler.LabelTrace(trace)
			require.Equal(t, libpf.Intern("interruptible"),
				trace.CustomLabels[libpf.Intern("thread.state")])
			return
		case <-deadline.C:
			t.Fatal("timed out waiting for an off-cpu time trace")
		}
	}
}

func TestOffCPUTimeProbeFiltersShortWaits(t *testing.T) {
	trc, cancel, traces := newIntegrationTracer(t)
	defer cancel()
	defer trc.Close()

	// A threshold far above any wait this workload produces: nothing may be
	// emitted for this process.
	probe, err := New(map[string]any{"min_duration": "10m"})
	require.NoError(t, err)
	require.NoError(t, trc.Enable(probe))

	sleeperDone := make(chan struct{})
	defer close(sleeperDone)
	go func() {
		for {
			select {
			case <-sleeperDone:
				return
			default:
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	pid := libpf.PID(os.Getpid())
	quiet := time.NewTimer(3 * time.Second)
	defer quiet.Stop()
	for {
		select {
		case trace := <-traces:
			if trace != nil && trace.PID == pid && trace.Value > 0 {
				t.Fatalf("unexpected off-cpu sample below threshold: %d ns", trace.Value)
			}
		case <-quiet.C:
			return
		}
	}
}
