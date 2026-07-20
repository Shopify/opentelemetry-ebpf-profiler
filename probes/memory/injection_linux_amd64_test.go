// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package memory

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

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
	build := exec.Command(compiler, "-O0", "-g", "-fno-builtin", "-o", target,
		"testdata/heap_injection_target.c")
	buildOutput, err := build.CombinedOutput()
	require.NoError(t, err, string(buildOutput))

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

	injector, err := newAllocatorInjector(shim, InjectionGOT, DefaultSamplingIntervalBytes)
	require.NoError(t, err)
	result, err := injector.Inject(libpf.PID(cmd.Process.Pid))
	require.NoError(t, err)
	assert.True(t, result.GOTPatched)
	assert.Greater(t, result.PatchedSlots, uint32(0))

	// Let the target execute patched allocator calls before checking liveness.
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, cmd.Process.Signal(syscall.Signal(0)))
}
