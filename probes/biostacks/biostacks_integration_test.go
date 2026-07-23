//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package biostacks

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/otel/metric/noop"
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

func TestBlockIOLifecycleProbes(t *testing.T) {
	for _, event := range []string{
		insertTracepointName, issueTracepointName, completeTracepointName,
	} {
		if !tracepointAvailable("block", event) {
			t.Skipf("tracepoint block/%s is unavailable", event)
		}
	}
	layout, err := discoverBlockLayout()
	require.NoError(t, err)
	startMetricsOnce.Do(func() { metrics.Start(noop.Meter{}) })

	reporter := &captureReporter{traces: make(chan reportedTrace, 1024)}
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

	for _, sampleType := range []string{SampleType, ServiceSampleType, FullSampleType} {
		created, createErr := NewForSampleType(sampleType, map[string]any{})
		require.NoError(t, createErr)
		require.NoError(t, trc.Enable(created))
	}

	file, err := os.CreateTemp("", "otel-block-lifecycle-*")
	require.NoError(t, err)
	defer os.Remove(file.Name())
	defer file.Close()
	payload := make([]byte, 4*1024*1024)
	_, err = rand.Read(payload)
	require.NoError(t, err)

	wanted := map[string]bool{
		SampleType: false, ServiceSampleType: false, FullSampleType: false,
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		_, err = file.Write(payload)
		require.NoError(t, err)
		require.NoError(t, file.Sync())
		require.NoError(t, file.Truncate(0))
		_, err = file.Seek(0, 0)
		require.NoError(t, err)

		select {
		case reported := <-reporter.traces:
			sampleType := reported.meta.ProfileType.SampleType
			if _, ok := wanted[sampleType]; !ok {
				continue
			}
			require.Positive(t, reported.meta.Value)
			require.NotEmpty(t, reported.trace.Frames)
			require.NotEmpty(t,
				reported.trace.CustomLabels[libpf.Intern("io.operation")].String())
			if layout.hasBTF {
				require.NotEmpty(t,
					reported.trace.CustomLabels[libpf.Intern("io.device")].String())
			}
			if sampleType == FullSampleType && layout.hasBTF {
				hasUserFrame := false
				for _, frame := range reported.trace.Frames {
					if frame.Value().Type != libpf.KernelFrame {
						hasUserFrame = true
						break
					}
				}
				if !hasUserFrame {
					continue
				}
			}
			wanted[sampleType] = true
			if wanted[SampleType] && wanted[ServiceSampleType] && wanted[FullSampleType] {
				return
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for block lifecycle profiles: %+v", wanted)
		default:
		}
	}
}

func tracepointAvailable(group, event string) bool {
	for _, root := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		path := filepath.Join(root, "events", group, event, "id")
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}
