// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package memory

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	lru "github.com/elastic/go-freelru"
	parcausdt "github.com/parca-dev/usdt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/util"
)

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
}

func TestExperimentalGOTInjection(t *testing.T) {
	shim := os.Getenv("PROPHILER_TEST_HEAP_SHIM")
	if shim == "" {
		t.Skip("set PROPHILER_TEST_HEAP_SHIM to run destructive ptrace integration test")
	}
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}

	target := filepath.Join(t.TempDir(), "heap-injection-target")
	build := exec.Command(compiler, "-O0", "-g", "-fno-builtin", "-pthread", "-o", target,
		"testdata/heap_injection_target.c")
	buildOutput, err := build.CombinedOutput()
	require.NoError(t, err, string(buildOutput))

	for _, test := range []struct {
		name        string
		requireFree bool
	}{
		{name: "allocation"},
		{name: "live", requireFree: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(target)
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
				shim, InjectionGOT, DefaultSamplingIntervalBytes, test.requireFree)
			require.NoError(t, err)
			result, err := injector.Inject(libpf.PID(cmd.Process.Pid))
			require.NoError(t, err)
			assert.True(t, result.GOTMallocPatched)
			assert.Equal(t, test.requireFree, result.GOTFreePatched)
			assert.Greater(t, result.PatchedSlots, uint32(0))

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
