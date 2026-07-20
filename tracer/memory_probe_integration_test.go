//go:build integration && linux

package tracer_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	parcausdt "github.com/parca-dev/usdt"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/liveheap"
	"go.opentelemetry.io/ebpf-profiler/probes/memory"
	"go.opentelemetry.io/ebpf-profiler/probes/probeconfig"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type heapShimSemaphores struct {
	allocation libpf.Address
	free       libpf.Address
	objects    int
}

func locateHeapShimSemaphores(
	t *testing.T, pid libpf.PID, shimPath string,
) heapShimSemaphores {
	t.Helper()

	probes, err := parcausdt.ParseProbesFromFile(shimPath)
	require.NoError(t, err)
	offsets := make(map[string]uint64, 2)
	for _, probe := range probes {
		if probe.Provider == memory.ExperimentalShimProvider &&
			(probe.Name == "alloc" || probe.Name == "free") {
			offsets[probe.Name] = probe.SemaphoreOffset
		}
	}
	require.NotZero(t, offsets["alloc"])
	require.NotZero(t, offsets["free"])

	addresses := heapShimSemaphores{}
	objects := make(map[[2]uint64]struct{})
	pr := process.New(pid, pid)
	_, err = pr.IterateMappings(func(mapping process.RawMapping) bool {
		if !strings.Contains(mapping.Path, "prophiler-heap-shim") {
			return true
		}
		objects[[2]uint64{mapping.Device, mapping.Inode}] = struct{}{}
		for name, offset := range offsets {
			if offset < mapping.FileOffset ||
				offset+2 > mapping.FileOffset+mapping.Length {
				continue
			}
			address := libpf.Address(mapping.Vaddr + offset - mapping.FileOffset)
			if name == "alloc" {
				addresses.allocation = address
			} else {
				addresses.free = address
			}
		}
		return true
	})
	require.NoError(t, err)
	require.NotZero(t, addresses.allocation)
	require.NotZero(t, addresses.free)
	addresses.objects = len(objects)
	return addresses
}

func requireHeapShimSemaphore(
	t *testing.T, pid libpf.PID, address libpf.Address, expected uint16,
) {
	t.Helper()
	remote := remotememory.NewProcessVirtualMemory(pid)
	require.Eventually(t, func() bool {
		var data [2]byte
		if err := remote.Read(address, data[:]); err != nil {
			return false
		}
		return binary.LittleEndian.Uint16(data[:]) == expected
	}, time.Second, 10*time.Millisecond)
}

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
		LiveHeapTracker: liveheap.NewTracker(1024),
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

func TestInjectedHeapShimEmitsWeightedAllocationAndFree(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("experimental heap shim is x86-64 only")
	}
	shim := os.Getenv("PROPHILER_TEST_HEAP_SHIM")
	if shim == "" {
		t.Skip("set PROPHILER_TEST_HEAP_SHIM to run the injected-shim integration test")
	}
	shimBytes, err := os.ReadFile(shim)
	if err != nil {
		t.Skipf("experimental heap shim unavailable: %v", err)
	}

	var compiler string
	for _, candidate := range []string{"cc", "clang", "clang-17"} {
		if path, lookupErr := exec.LookPath(candidate); lookupErr == nil {
			compiler = path
			break
		}
	}
	if compiler == "" {
		t.Skip("C compiler unavailable for injected heap-shim fixture")
	}

	dir := t.TempDir()
	injectionShim := filepath.Join(dir, "libprophiler-heap-shim.so")
	require.NoError(t, os.WriteFile(injectionShim, shimBytes, 0o555))
	source := filepath.Join(dir, "fixture.c")
	binary := filepath.Join(dir, "injected-heap-shim-fixture")
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
  if (getchar() == EOF) return 5;
  puts("done"); fflush(stdout);
  return 0;
}
`), 0o600))
	build := exec.Command(compiler, "-O0", "-g", "-fno-builtin",
		"-fno-omit-frame-pointer", source, "-o", binary)
	out, err := build.CombinedOutput()
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
	probes.Memory.Live = true
	probes.Memory.SamplingIntervalBytes = 1
	probes.Memory.ProcessExecutablePatterns = []string{"injected-heap-shim-fixture"}
	probes.Memory.AllocationHooks = []memory.Hook{
		memory.USDTHook(memory.ExperimentalShimProvider, "alloc"),
	}
	probes.Memory.DeallocationHooks = []memory.Hook{
		memory.USDTHook(memory.ExperimentalShimProvider, "free"),
	}
	probes.Memory.ExperimentalInjectionMode = memory.InjectionGOT
	probes.Memory.ExperimentalShimPath = injectionShim
	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals: &mockIntervals{}, InterpretersConfig: interpreterconfig.AllInterpreters(),
		ProbesConfig: probes, SamplesPerSecond: 20,
		ProbabilisticInterval: 100, ProbabilisticThreshold: 100,
		OffCPUThreshold: uint32(math.MaxUint32 / 100),
		LiveHeapTracker: liveheap.NewTracker(1024),
	})
	require.NoError(t, err)
	trClosed := false
	defer func() {
		if !trClosed {
			cancel()
			tr.Close()
		}
	}()
	traceCh := make(chan *libpf.EbpfTrace, 64)
	require.NoError(t, tr.StartMapMonitors(ctx, traceCh))
	tr.StartPIDEventProcessor(ctx)

	pid := libpf.PID(fixture.Process.Pid)
	// The first pass injects after finding no producer. The second discovers
	// the sealed memfd and attaches its semaphore-gated allocation/free notes.
	tr.ProcessManager().SynchronizeProcess(process.New(pid, pid))
	semaphores := locateHeapShimSemaphores(t, pid, injectionShim)
	require.Equal(t, 1, semaphores.objects, "injection created multiple shim objects")
	requireHeapShimSemaphore(t, pid, semaphores.allocation, 0)
	requireHeapShimSemaphore(t, pid, semaphores.free, 0)

	tr.ProcessManager().SynchronizeProcess(process.New(pid, pid))
	requireHeapShimSemaphore(t, pid, semaphores.allocation, 1)
	requireHeapShimSemaphore(t, pid, semaphores.free, 1)

	_, err = fmt.Fprintln(stdin)
	require.NoError(t, err)
	var allocationPointer uint64
	allocationTimeout := time.NewTimer(5 * time.Second)
	defer allocationTimeout.Stop()
	for allocationPointer == 0 {
		select {
		case got := <-traceCh:
			if got.Origin == libpf.Origin(support.TraceOriginHeapAlloc) &&
				got.PID == pid && got.Size == 12345 {
				require.Equal(t, int64(12345), got.Value)
				require.NotZero(t, got.Ptr)
				allocationPointer = got.Ptr
			}
		case <-allocationTimeout.C:
			t.Fatal("timed out waiting for injected weighted heap allocation trace")
		}
	}

	_, err = fmt.Fprintln(stdin)
	require.NoError(t, err)
	freeTimeout := time.NewTimer(5 * time.Second)
	defer freeTimeout.Stop()
freeLoop:
	for {
		select {
		case got := <-traceCh:
			if got.Origin == libpf.Origin(support.TraceOriginHeapFree) &&
				got.PID == pid && got.Ptr == allocationPointer {
				break freeLoop
			}
		case <-freeTimeout.C:
			t.Fatal("timed out waiting for matching injected heap free trace")
		}
	}

	// Link teardown must decrement both reference counters. Interposition stays
	// installed, but the producer becomes inert.
	cancel()
	tr.Close()
	trClosed = true
	requireHeapShimSemaphore(t, pid, semaphores.allocation, 0)
	requireHeapShimSemaphore(t, pid, semaphores.free, 0)

	// Simulate a profiler restart. Existing memfd discovery must attach to the
	// same object without injecting another copy, then detach cleanly again.
	ctx2, cancel2 := context.WithCancel(t.Context())
	tr2, err := tracer.NewTracer(ctx2, &tracer.Config{
		Intervals: &mockIntervals{}, InterpretersConfig: interpreterconfig.AllInterpreters(),
		ProbesConfig: probes, SamplesPerSecond: 20,
		ProbabilisticInterval: 100, ProbabilisticThreshold: 100,
		OffCPUThreshold: uint32(math.MaxUint32 / 100),
		LiveHeapTracker: liveheap.NewTracker(1024),
	})
	require.NoError(t, err)
	tr2Closed := false
	defer func() {
		if !tr2Closed {
			cancel2()
			tr2.Close()
		}
	}()
	tr2.ProcessManager().SynchronizeProcess(process.New(pid, pid))
	restartedSemaphores := locateHeapShimSemaphores(t, pid, injectionShim)
	require.Equal(t, 1, restartedSemaphores.objects,
		"profiler restart reinjected the heap shim")
	require.Equal(t, semaphores.allocation, restartedSemaphores.allocation)
	require.Equal(t, semaphores.free, restartedSemaphores.free)
	requireHeapShimSemaphore(t, pid, semaphores.allocation, 1)
	requireHeapShimSemaphore(t, pid, semaphores.free, 1)
	cancel2()
	tr2.Close()
	tr2Closed = true
	requireHeapShimSemaphore(t, pid, semaphores.allocation, 0)
	requireHeapShimSemaphore(t, pid, semaphores.free, 0)

	_, err = fmt.Fprintln(stdin)
	require.NoError(t, err)
	require.True(t, scanner.Scan())
	require.Equal(t, "allocated", scanner.Text())
	require.True(t, scanner.Scan())
	require.Equal(t, "freed", scanner.Text())
	require.True(t, scanner.Scan())
	require.Equal(t, "done", scanner.Text())
}
