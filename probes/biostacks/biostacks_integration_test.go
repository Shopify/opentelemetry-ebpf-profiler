//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package biostacks

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
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

func (integrationIntervals) MonitorInterval() time.Duration       { return time.Second }
func (integrationIntervals) TracePollInterval() time.Duration     { return 10 * time.Millisecond }
func (integrationIntervals) PIDCleanupInterval() time.Duration    { return time.Second }
func (integrationIntervals) ExecutableUnloadDelay() time.Duration { return time.Second }

func TestBlockIOStacksProbe(t *testing.T) {
	for _, event := range []string{startTracepointName, issueTracepointName} {
		if !tracepointAvailable(startTracepointGroup, event) {
			t.Skipf("tracepoint %s/%s is unavailable", startTracepointGroup, event)
		}
	}
	metrics.Start(noop.Meter{})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
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
	defer trc.Close()

	trc.StartPIDEventProcessor(ctx)
	traces := make(chan *libpf.EbpfTrace, 4096)
	require.NoError(t, trc.StartMapMonitors(ctx, traces))

	probe, err := New(map[string]any{})
	require.NoError(t, err)
	require.NoError(t, trc.Enable(probe))

	file, err := os.CreateTemp("", "otel-biostacks-*")
	require.NoError(t, err)
	defer os.Remove(file.Name())
	defer file.Close()

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	payload := make([]byte, 4*1024*1024)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	for {
		_, err := file.Write(payload)
		require.NoError(t, err)
		require.NoError(t, file.Sync())
		require.NoError(t, file.Truncate(0))
		_, err = file.Seek(0, 0)
		require.NoError(t, err)

		select {
		case trace := <-traces:
			require.Positive(t, trace.Value)
			require.NotEmpty(t, trace.KernelFrames)
			operation, ok := trace.CustomLabels[libpf.Intern("io.operation")]
			require.True(t, ok)
			require.NotEmpty(t, operation.String())
			device, ok := trace.CustomLabels[libpf.Intern("io.device")]
			require.True(t, ok)
			require.Len(t, device.String(), 8)
			return
		case <-deadline.C:
			t.Fatal("timed out waiting for a block I/O queue latency trace")
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
