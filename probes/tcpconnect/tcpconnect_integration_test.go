//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tcpconnect

import (
	"context"
	"net"
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
	copied := &libpf.Trace{
		CustomLabels: make(map[libpf.String]libpf.String, len(trace.CustomLabels)),
		Frames:       append(libpf.Frames(nil), trace.Frames...),
	}
	for key, value := range trace.CustomLabels {
		copied.CustomLabels[key] = value
	}
	copiedMeta := *meta
	select {
	case r.traces <- reportedTrace{trace: copied, meta: &copiedMeta}:
	default:
	}
	return nil
}

var startMetricsOnce sync.Once

func TestTCPConnectHandshakeLatency(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	acceptCtx, stopAccept := context.WithCancel(t.Context())
	defer stopAccept()
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = connection.Close()
			select {
			case <-acceptCtx.Done():
				return
			default:
			}
		}
	}()

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
	for {
		connection, dialErr := net.Dial("tcp4", listener.Addr().String())
		require.NoError(t, dialErr)
		require.NoError(t, connection.Close())

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
				continue
			}
			require.Equal(t, libpf.Intern("connect"),
				reported.trace.CustomLabels[libpf.Intern("network.operation")])
			require.Equal(t, libpf.Intern("tcp"),
				reported.trace.CustomLabels[libpf.Intern("network.transport")])
			require.Equal(t, libpf.Intern("ipv4"),
				reported.trace.CustomLabels[libpf.Intern("network.type")])
			require.Equal(t, libpf.Intern("ok"),
				reported.trace.CustomLabels[libpf.Intern("network.connect.status")])
			return
		case <-deadline.C:
			t.Fatal("timed out waiting for a TCP connect latency profile")
		default:
		}
	}
}
