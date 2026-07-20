// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package memory

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	lru "github.com/elastic/go-freelru"
	parcausdt "github.com/parca-dev/usdt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/util"
)

func TestInjectionSymbolMappingFilters(t *testing.T) {
	mapping := func(path string) processMapping { return processMapping{path: path} }
	assert.True(t, isAllocatorRuntimeMapping(mapping("/usr/lib/x86_64-linux-gnu/libc.so.6")))
	assert.True(t, isAllocatorRuntimeMapping(mapping("/lib/libdl.so.2 (deleted)")))
	assert.True(t, isAllocatorRuntimeMapping(mapping("/usr/lib64/libc-2.17.so")))
	assert.True(t, isAllocatorRuntimeMapping(mapping("/usr/lib64/libdl-2.17.so")))
	assert.False(t, isAllocatorRuntimeMapping(mapping("/tmp/libc.so-pretender")))
	assert.False(t, isAllocatorRuntimeMapping(mapping("/tmp/libc.so.6.pretender")))
	assert.False(t, isAllocatorRuntimeMapping(mapping("/tmp/libc.so.6..1")))
	assert.False(t, isAllocatorRuntimeMapping(mapping("/tmp/libc-2.x.so")))
	assert.False(t, isAllocatorRuntimeMapping(mapping("/usr/bin/target")))
	assert.True(t, isExperimentalShimMapping(mapping("/memfd:prophiler-heap-shim (deleted)")))
	assert.True(t, isExperimentalShimMapping(mapping("/opt/prophiler/libprophiler-heap-shim.so")))
	assert.False(t, isExperimentalShimMapping(mapping("/tmp/prophiler-heap-shim-decoy.so")))
	assert.False(t, isExperimentalShimMapping(mapping("/usr/lib/libc.so.6")))
}

func TestValidateAndSealOpenedShimMemfd(t *testing.T) {
	fd, err := unix.MemfdCreate("prophiler-heap-shim", remoteMfdFlags)
	require.NoError(t, err)
	memfd := os.NewFile(uintptr(fd), "prophiler-heap-shim")
	require.NotNil(t, memfd)
	defer memfd.Close()
	_, err = memfd.Write([]byte("shim"))
	require.NoError(t, err)

	var stat unix.Stat_t
	require.NoError(t, validateOpenedShimMemfd(memfd, &stat))
	require.NoError(t, sealOpenedShimMemfd(memfd))
	seals, err := unix.FcntlInt(memfd.Fd(), unix.F_GET_SEALS, 0)
	require.NoError(t, err)
	assert.Equal(t, remoteMfdSeals, seals&remoteMfdSeals)
	_, err = memfd.WriteAt([]byte("x"), 0)
	require.Error(t, err, "sealed shim bytes must be immutable")
}

func TestValidateOpenedShimMemfdRejectsWrongName(t *testing.T) {
	fd, err := unix.MemfdCreate("other-shim", remoteMfdFlags)
	require.NoError(t, err)
	memfd := os.NewFile(uintptr(fd), "other-shim")
	require.NotNil(t, memfd)
	defer memfd.Close()
	var stat unix.Stat_t
	require.ErrorContains(t, validateOpenedShimMemfd(memfd, &stat),
		"not the requested heap shim memfd")
}

func TestValidateOpenedShimMemfdRejectsNamedFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "prophiler-heap-shim")
	require.NoError(t, err)
	defer file.Close()
	var stat unix.Stat_t
	require.ErrorContains(t, validateOpenedShimMemfd(file, &stat),
		"not an unlinked regular memfd")
	require.NoError(t, unix.Fstat(int(file.Fd()), &stat))
	mapping := processMapping{device: uint64(stat.Dev), inode: stat.Ino}
	assert.True(t, openedFileMatchesMapping(file, mapping))
	mapping.inode++
	assert.False(t, openedFileMatchesMapping(file, mapping))
	mapping.inode = stat.Ino
	mapping.device++
	assert.False(t, openedFileMatchesMapping(file, mapping))
}

func TestPotentialRemoteReturnStop(t *testing.T) {
	returned := unix.WaitStatus(int(unix.SIGSEGV)<<8 | 0x7f)
	stopped := unix.WaitStatus(int(unix.SIGSTOP)<<8 | 0x7f)
	assert.True(t, potentialRemoteReturnStop(returned))
	assert.False(t, potentialRemoteReturnStop(stopped))
	assert.False(t, potentialRemoteReturnStop(0))
}

func TestPtraceSessionCloseRecoversRunningTracee(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	session, err := attachThreads(cmd.Process.Pid, []int{cmd.Process.Pid})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("ptrace unavailable: %v", err)
	}
	require.NoError(t, err)
	defer func() { _ = session.Close() }()
	require.NoError(t, unix.PtraceCont(cmd.Process.Pid, 0))
	require.NoError(t, session.Close(), "running tracee was not recovered and detached")

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("detached tracee remained stopped")
	}
}

func TestRequiredAllocatorPatchesPresent(t *testing.T) {
	tests := []struct {
		name        string
		status      uint64
		requireFree bool
		expected    bool
	}{
		{name: "allocation malloc only", status: shimInlineMallocBit, expected: true},
		{name: "allocation no malloc", status: shimInlineFreeBit, expected: false},
		{name: "live both", status: shimInlineMallocBit | shimInlineFreeBit, requireFree: true, expected: true},
		{name: "live malloc only", status: shimInlineMallocBit, requireFree: true, expected: false},
		{name: "live free only", status: shimInlineFreeBit, requireFree: true, expected: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, requiredAllocatorPatchesPresent(
				test.status, test.requireFree, shimInlineMallocBit, shimInlineFreeBit))
		})
	}
}

func TestExperimentalShimUSDTNotes(t *testing.T) {
	shim := os.Getenv("PROPHILER_TEST_HEAP_SHIM")
	if shim == "" {
		t.Skip("set PROPHILER_TEST_HEAP_SHIM to inspect the experimental shim")
	}
	ef, err := pfelf.Open(shim)
	require.NoError(t, err)
	defer ef.Close()
	probes, err := parcausdt.ParseProbes(&pfelfReader{f: ef})
	require.NoError(t, err)

	found := make(map[string]bool)
	for _, probe := range probes {
		if probe.Provider != ExperimentalShimProvider {
			continue
		}
		if probe.Name == "alloc" || probe.Name == "free" {
			assert.NotZero(t, probe.SemaphoreOffset)
			found[probe.Name] = true
		}
	}
	assert.Equal(t, map[string]bool{"alloc": true, "free": true}, found)

	contents, err := os.ReadFile(shim)
	require.NoError(t, err)
	for _, name := range []string{"alloc", "free"} {
		t.Run("reject missing "+name, func(t *testing.T) {
			corrupt := append([]byte(nil), contents...)
			needle := []byte(ExperimentalShimProvider + "\x00" + name + "\x00")
			note := bytes.Index(corrupt, needle)
			require.NotEqual(t, -1, note, "%s USDT descriptor not found", name)
			corrupt[note+len(ExperimentalShimProvider)+1] = 'x'
			require.ErrorContains(t, validateExperimentalShimProbes(corrupt),
				"missing semaphore-gated USDT probe")
		})
	}

	zeroSemaphore := append([]byte(nil), contents...)
	allocNote := bytes.Index(zeroSemaphore,
		[]byte(ExperimentalShimProvider+"\x00alloc\x00"))
	require.GreaterOrEqual(t, allocNote, 8, "allocation USDT descriptor not found")
	clear(zeroSemaphore[allocNote-8 : allocNote])
	require.ErrorContains(t, validateExperimentalShimProbes(zeroSemaphore),
		"has no semaphore offset")
}

func TestExperimentalAllocatorInjection(t *testing.T) {
	shim := os.Getenv("PROPHILER_TEST_HEAP_SHIM")
	if shim == "" {
		t.Skip("set PROPHILER_TEST_HEAP_SHIM to run destructive ptrace integration test")
	}
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}

	dir := t.TempDir()
	buildTarget := func(name string, extraFlags ...string) string {
		t.Helper()
		target := filepath.Join(dir, name)
		args := []string{"-O0", "-g", "-fno-builtin", "-pthread"}
		args = append(args, extraFlags...)
		args = append(args, "-o", target, "testdata/heap_injection_target.c", "-ldl")
		build := exec.Command(compiler, args...)
		buildOutput, buildErr := build.CombinedOutput()
		require.NoError(t, buildErr, string(buildOutput))
		return target
	}
	gotTarget := buildTarget("heap-injection-got-target")
	inlineTarget := buildTarget("heap-injection-inline-target", "-DRESOLVE_ALLOCATORS")

	for _, test := range []struct {
		name         string
		target       string
		mode         InjectionMode
		requireFree  bool
		expectInline bool
	}{
		{name: "got-allocation", target: gotTarget, mode: InjectionGOT},
		{name: "got-live", target: gotTarget, mode: InjectionGOT, requireFree: true},
		{name: "inline-allocation", target: inlineTarget, mode: InjectionGOTThenInline, expectInline: true},
		{name: "inline-live", target: inlineTarget, mode: InjectionGOTThenInline, requireFree: true, expectInline: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(test.target)
			stdout, err := cmd.StdoutPipe()
			require.NoError(t, err)
			cmd.Stderr = os.Stderr
			require.NoError(t, cmd.Start())
			t.Cleanup(func() {
				_ = cmd.Process.Signal(os.Interrupt)
				_, _ = cmd.Process.Wait()
			})

			ready := make(chan string, 1)
			go func() {
				scanner := bufio.NewScanner(stdout)
				if scanner.Scan() {
					ready <- scanner.Text()
				}
			}()
			select {
			case line := <-ready:
				require.Equal(t, "ready", line)
			case <-time.After(5 * time.Second):
				t.Fatal("target did not become ready")
			}

			injector, err := newAllocatorInjector(
				shim, test.mode, DefaultSamplingIntervalBytes, test.requireFree)
			require.NoError(t, err)
			result, err := injector.Inject(libpf.PID(cmd.Process.Pid))
			require.NoError(t, err)
			if test.expectInline {
				assert.True(t, result.InlineMallocPatched)
				assert.Equal(t, test.requireFree, result.InlineFreePatched)
			} else {
				assert.True(t, result.GOTMallocPatched)
				assert.Equal(t, test.requireFree, result.GOTFreePatched)
				assert.Greater(t, result.PatchedSlots, uint32(0))
			}
			time.Sleep(20 * time.Millisecond)
			require.NoError(t, cmd.Process.Signal(syscall.Signal(0)),
				"target died after allocator mutation")

			// A fresh manager after an agent restart must recognize the mapped shim
			// and never layer another allocator patch over the first one.
			second, err := injector.Inject(libpf.PID(cmd.Process.Pid))
			require.NoError(t, err)
			assert.True(t, second.AlreadyPresent)

			// Verify the next reconciliation can parse the injected memfd and find
			// its semaphore-gated sampled producers.
			cache, err := lru.NewSynced[util.OnDiskFileIdentifier, parsedFile](
				8, util.OnDiskFileIdentifier.Hash32)
			require.NoError(t, err)
			hooks := []configuredHook{{
				id: 1, event: EventAllocation,
				hook: Hook{
					Type: HookTypeUSDT, ABI: ABIWeightedAllocation,
					Provider: ExperimentalShimProvider, Name: "alloc",
				},
			}}
			if test.requireFree {
				hooks = append(hooks, configuredHook{
					id: 2, event: EventDeallocation,
					hook: Hook{
						Type: HookTypeUSDT, ABI: ABIFree,
						Provider: ExperimentalShimProvider, Name: "free",
					},
				})
			}
			manager := &Manager{hooks: hooks, needsUSDT: true, parseCache: cache}
			pr := process.New(libpf.PID(cmd.Process.Pid), libpf.PID(cmd.Process.Pid))
			var discovered []resolvedHook
			var scanErr error
			_, err = pr.IterateMappings(func(mapping process.RawMapping) bool {
				if !mapping.IsExecutable() || !mapping.IsMemFD() ||
					!strings.Contains(mapping.Path, "prophiler-heap-shim") {
					return true
				}
				discovered, scanErr = manager.scanMapping(pr, &mapping)
				return false
			})
			if err != nil && !errors.Is(err, process.ErrCallbackStopped) {
				require.NoError(t, err)
			}
			if errors.Is(scanErr, os.ErrPermission) {
				t.Logf("injection succeeded; skipping memfd discovery without map_files permission: %v", scanErr)
				return
			}
			require.NoError(t, scanErr)
			require.Len(t, discovered, len(hooks),
				"injected memfd did not expose every configured USDT producer")
			for _, hook := range discovered {
				assert.NotZero(t, hook.SemaphoreOffset)
			}

			// Let the worker execute patched allocator calls before checking liveness.
			time.Sleep(100 * time.Millisecond)
			require.NoError(t, cmd.Process.Signal(syscall.Signal(0)))
		})
	}
}
