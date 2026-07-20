//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package functionlatency

import (
	"context"
	"io"
	"net"
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
		Intervals:              integrationIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		SamplesPerSecond:       20,
		FrameCacheSize:         1024,
		ProbabilisticInterval:  time.Minute,
		ProbabilisticThreshold: tracer.ProbabilisticThresholdMax,
		LoadProbe:              true,
	})
	require.NoError(t, err)

	trc.StartPIDEventProcessor(ctx)
	traces := make(chan *libpf.EbpfTrace, 4096)
	require.NoError(t, trc.StartMapMonitors(ctx, traces))
	return trc, cancel, traces
}

func TestFunctionLatencyProbe(t *testing.T) {
	trc, cancel, traces := newIntegrationTracer(t)
	defer cancel()
	defer trc.Close()

	probe, err := New(Definition{
		Symbol:     "vfs_read",
		SampleType: "vfs_read_latency",
	}, map[string]any{})
	require.NoError(t, err)
	require.NoError(t, trc.Enable(probe))

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	pid := libpf.PID(os.Getpid())
	for {
		_, err := os.ReadFile("/proc/self/stat")
		require.NoError(t, err)

		select {
		case trace := <-traces:
			if trace.PID != pid {
				continue
			}
			require.Positive(t, trace.Value)
			require.NotEmpty(t, trace.KernelFrames)
			require.NotEmpty(t, trace.FrameData)
			require.Positive(t, trace.NumFrames)
			return
		case <-deadline.C:
			t.Fatal("timed out waiting for a vfs_read latency trace")
		default:
		}
	}
}

func TestTCPFunctionLatencyProbe(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(io.Discard, connection)
	}()

	connection, err := net.Dial("tcp4", listener.Addr().String())
	require.NoError(t, err)
	defer func() {
		_ = connection.Close()
		<-serverDone
	}()

	trc, cancel, traces := newIntegrationTracer(t)
	defer cancel()
	defer trc.Close()

	probe, err := New(Definition{
		Symbol:     "tcp_sendmsg",
		SampleType: "tcp_send_latency",
	}, map[string]any{})
	require.NoError(t, err)
	require.NoError(t, trc.Enable(probe))

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	pid := libpf.PID(os.Getpid())
	payload := []byte("latency probe test")
	for {
		_, err := connection.Write(payload)
		require.NoError(t, err)

		select {
		case trace := <-traces:
			if trace.PID != pid {
				continue
			}
			require.Positive(t, trace.Value)
			require.NotEmpty(t, trace.KernelFrames)
			require.NotEmpty(t, trace.FrameData)
			require.Positive(t, trace.NumFrames)
			return
		case <-deadline.C:
			t.Fatal("timed out waiting for a tcp_sendmsg latency trace")
		default:
		}
	}
}
