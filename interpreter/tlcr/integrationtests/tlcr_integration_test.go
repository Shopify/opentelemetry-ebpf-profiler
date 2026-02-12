//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtests

import (
	"context"
	_ "embed"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/otel/metric/noop"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// Pre-built test binary that writes known TLCR data and burns CPU.
// Build with: cd testapp && make
//
//go:embed tlcr_testapp
var tlcrTestApp []byte

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration  { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration { return 1 * time.Second }

func isRoot() bool {
	return os.Geteuid() == 0
}

// expectedTraceID is all 0x42 bytes (set by testapp/main.c)
var expectedTraceID = [16]byte{
	0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
}

// expectedSpanID is all 0xAB bytes (set by testapp/main.c)
var expectedSpanID = [8]byte{
	0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
}

func Test_TLCR(t *testing.T) {
	if !isRoot() {
		t.Skip("root privileges required")
	}

	exe, err := os.CreateTemp(t.TempDir(), "tlcr_testapp")
	require.NoError(t, err)
	defer os.Remove(exe.Name())

	_, err = exe.Write(tlcrTestApp)
	require.NoError(t, err)
	require.NoError(t, exe.Close())
	require.NoError(t, os.Chmod(exe.Name(), 0o755))

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	debug.SetTraceback("all")
	metrics.Start(noop.Meter{})

	enabledTracers, _ := tracertypes.Parse("")

	log.SetLevel(slog.LevelDebug)
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              &mockIntervals{},
		IncludeTracers:         enabledTracers,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		OffCPUThreshold:        uint32(math.MaxUint32 / 100),
		VerboseMode:            true,
	})
	require.NoError(t, err)
	defer trc.Close()

	trc.StartPIDEventProcessor(ctx)
	require.NoError(t, trc.AttachTracer())

	t.Log("Attached tracer program")
	require.NoError(t, trc.EnableProfiling())
	require.NoError(t, trc.AttachSchedMonitor())

	traceCh := make(chan *libpf.EbpfTrace)
	require.NoError(t, trc.StartMapMonitors(ctx, traceCh))

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := exec.CommandContext(ctx, exe.Name()).Run()
		select {
		case <-ctx.Done():
			t.Log("Test program cancelled (run complete)")
		default:
			require.NoError(t, err)
			cancel()
			panic("TLCR test app exited before we captured frames")
		}
	}()

	ok := false
	for trace := range traceCh {
		if trace == nil {
			continue
		}
		// Check if this trace has the expected APM trace/span IDs
		if trace.APMTraceID == expectedTraceID {
			t.Logf("Found matching trace_id, checking span_id...")
			if trace.APMTransactionID == expectedSpanID {
				t.Log("TLCR trace_id and span_id match expected values")
				ok = true
				cancel()
				break
			}
		}
	}

	t.Log("Exiting TLCR test")
	require.True(t, ok, "TLCR trace context not received from profiler")
	wg.Wait()
}
