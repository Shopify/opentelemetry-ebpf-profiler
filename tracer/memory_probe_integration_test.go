//go:build integration && linux

package tracer_test

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/probes/memory"
	"go.opentelemetry.io/ebpf-profiler/probes/probeconfig"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

func TestDirectMallocEmitsAllocation(t *testing.T) {
	var compiler string
	for _, candidate := range []string{"cc", "clang", "clang-17"} {
		if path, err := exec.LookPath(candidate); err == nil {
			compiler = path
			break
		}
	}
	if compiler == "" {
		t.Skip("C compiler unavailable for direct-malloc fixture")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "fixture.c")
	binary := filepath.Join(dir, "malloc-fixture")
	require.NoError(t, os.WriteFile(source, []byte(`#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
  puts("ready"); fflush(stdout);
  if (getchar() == EOF) return 2;
  void *p = malloc(12345);
  if (!p) return 3;
  ((volatile char *)p)[0] = 1;
  puts("allocated"); fflush(stdout);
  sleep(2);
  free(p);
  return 0;
}
`), 0o600))
	cmd := exec.Command(compiler, "-O0", "-g", "-fno-omit-frame-pointer", source, "-o", binary)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	fixture := exec.Command(binary)
	stdin, err := fixture.StdinPipe()
	require.NoError(t, err)
	stdout, err := fixture.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, fixture.Start())
	defer func() { _ = fixture.Process.Kill(); _ = fixture.Wait() }()
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan())
	require.Equal(t, "ready", scanner.Text())

	ctx, cancel := context.WithCancel(t.Context())
	probes := probeconfig.DefaultConfig()
	probes.Memory.Enabled = true
	probes.Memory.SamplingIntervalBytes = 1
	probes.Memory.ProcessExecutablePatterns = []string{"malloc-fixture"}
	probes.Memory.AllocationHooks = []memory.Hook{memory.UprobeHook("libc.so.6", "malloc")}
	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals: &mockIntervals{}, InterpretersConfig: interpreterconfig.AllInterpreters(),
		ProbesConfig: probes, SamplesPerSecond: 20,
		ProbabilisticInterval: 100, ProbabilisticThreshold: 100,
		OffCPUThreshold: uint32(math.MaxUint32 / 100),
	})
	require.NoError(t, err)
	defer func() { cancel(); tr.Close() }()
	traceCh := make(chan *libpf.EbpfTrace, 64)
	require.NoError(t, tr.StartMapMonitors(ctx, traceCh))
	tr.StartPIDEventProcessor(ctx)
	tr.ProcessManager().SynchronizeProcess(process.New(libpf.PID(fixture.Process.Pid), libpf.PID(fixture.Process.Pid)))

	_, err = fmt.Fprintln(stdin)
	require.NoError(t, err)

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case got := <-traceCh:
			if got.Origin == libpf.Origin(support.TraceOriginHeapAlloc) && got.PID == libpf.PID(fixture.Process.Pid) {
				require.Equal(t, uint64(12345), got.Size)
				require.Equal(t, int64(12345), got.Value)
				return
			}
		case <-timeout.C:
			t.Fatal("timed out waiting for direct malloc allocation trace")
		}
	}
}

func TestPreloadedHeapShimEmitsWeightedAllocationAndFree(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("experimental heap shim is x86-64 only")
	}
	shim := os.Getenv("PROPHILER_TEST_HEAP_SHIM")
	if shim == "" {
		t.Skip("set PROPHILER_TEST_HEAP_SHIM to run the preloaded-shim integration test")
	}
	if _, err := os.Stat(shim); err != nil {
		t.Skipf("experimental heap shim unavailable: %v", err)
	}

	var compiler string
	for _, candidate := range []string{"cc", "clang", "clang-17"} {
		if path, err := exec.LookPath(candidate); err == nil {
			compiler = path
			break
		}
	}
	if compiler == "" {
		t.Skip("C compiler unavailable for heap-shim fixture")
	}

	dir := t.TempDir()
	source := filepath.Join(dir, "fixture.c")
	binary := filepath.Join(dir, "heap-shim-fixture")
	require.NoError(t, os.WriteFile(source, []byte(`#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
  puts("ready"); fflush(stdout);
  if (getchar() == EOF) return 2;
  void *p = malloc(12345);
  if (!p) return 3;
  ((volatile char *)p)[0] = 1;
  puts("allocated"); fflush(stdout);
  if (getchar() == EOF) return 4;
  free(p);
  puts("freed"); fflush(stdout);
  sleep(2);
  return 0;
}
`), 0o600))
	build := exec.Command(compiler, "-O0", "-g", "-fno-builtin",
		"-fno-omit-frame-pointer", source, "-o", binary)
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))

	fixture := exec.Command(binary)
	fixture.Env = append(os.Environ(),
		"LD_PRELOAD="+shim,
		"PROPHILER_HEAP_SAMPLING_INTERVAL_BYTES=1",
		"PROPHILER_HEAP_LIVE=1")
	stdin, err := fixture.StdinPipe()
	require.NoError(t, err)
	stdout, err := fixture.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, fixture.Start())
	defer func() { _ = fixture.Process.Kill(); _ = fixture.Wait() }()
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan())
	require.Equal(t, "ready", scanner.Text())

	ctx, cancel := context.WithCancel(t.Context())
	probes := probeconfig.DefaultConfig()
	probes.Memory.Enabled = true
	probes.Memory.Live = true
	probes.Memory.SamplingIntervalBytes = 1
	probes.Memory.ProcessExecutablePatterns = []string{"heap-shim-fixture"}
	probes.Memory.AllocationHooks = []memory.Hook{
		memory.USDTHook(memory.ExperimentalShimProvider, "alloc"),
	}
	probes.Memory.DeallocationHooks = []memory.Hook{
		memory.USDTHook(memory.ExperimentalShimProvider, "free"),
	}
	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals: &mockIntervals{}, InterpretersConfig: interpreterconfig.AllInterpreters(),
		ProbesConfig: probes, SamplesPerSecond: 20,
		ProbabilisticInterval: 100, ProbabilisticThreshold: 100,
		OffCPUThreshold: uint32(math.MaxUint32 / 100),
	})
	require.NoError(t, err)
	defer func() { cancel(); tr.Close() }()
	traceCh := make(chan *libpf.EbpfTrace, 64)
	require.NoError(t, tr.StartMapMonitors(ctx, traceCh))
	tr.StartPIDEventProcessor(ctx)
	tr.ProcessManager().SynchronizeProcess(
		process.New(libpf.PID(fixture.Process.Pid), libpf.PID(fixture.Process.Pid)))

	_, err = fmt.Fprintln(stdin)
	require.NoError(t, err)

	var allocationPointer uint64
	allocationTimeout := time.NewTimer(5 * time.Second)
	defer allocationTimeout.Stop()
	for allocationPointer == 0 {
		select {
		case got := <-traceCh:
			if got.Origin == libpf.Origin(support.TraceOriginHeapAlloc) &&
				got.PID == libpf.PID(fixture.Process.Pid) && got.Size == 12345 {
				require.Equal(t, int64(12345), got.Value)
				require.NotZero(t, got.Ptr)
				allocationPointer = got.Ptr
			}
		case <-allocationTimeout.C:
			t.Fatal("timed out waiting for weighted heap-shim allocation trace")
		}
	}

	_, err = fmt.Fprintln(stdin)
	require.NoError(t, err)
	freeTimeout := time.NewTimer(5 * time.Second)
	defer freeTimeout.Stop()
	for {
		select {
		case got := <-traceCh:
			if got.Origin == libpf.Origin(support.TraceOriginHeapFree) &&
				got.PID == libpf.PID(fixture.Process.Pid) && got.Ptr == allocationPointer {
				return
			}
		case <-freeTimeout.C:
			t.Fatal("timed out waiting for matching heap-shim free trace")
		}
	}
}
