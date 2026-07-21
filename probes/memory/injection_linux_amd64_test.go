// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package memory

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

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

func TestReadTargetExecutableIdentity(t *testing.T) {
	identity, err := readTargetExecutableIdentity(os.Getpid())
	require.NoError(t, err)
	assert.NotEmpty(t, identity.path)
	assert.NotZero(t, identity.inode)
	assert.NotZero(t, identity.startTime)

	again, err := readTargetExecutableIdentity(os.Getpid())
	require.NoError(t, err)
	assert.True(t, sameTargetExecutable(identity, again))
}

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
	assert.True(t, isExperimentalShimMapping(mapping("/tmp/libprophiler-heap-shim.so")),
		"an explicitly preloaded package shim may live outside the install prefix")
	assert.False(t, isExperimentalShimMapping(mapping("/tmp/prophiler-heap-shim-decoy.so")))
	assert.False(t, isExperimentalShimMapping(mapping("/usr/lib/libc.so.6")))
}

func TestTrustedShimOwner(t *testing.T) {
	assert.True(t, trustedShimOwner(0, 1234), "root-owned package artifacts are trusted")
	assert.True(t, trustedShimOwner(1234, 1234), "the profiler may own its shim")
	assert.False(t, trustedShimOwner(5678, 1234), "foreign-user shim bytes are untrusted")
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

func TestTerminateUnsafeTraceeKillsTarget(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	terminated, err := terminateUnsafeTracee(
		cmd.Process.Pid, cmd.Process.Pid, "synthetic restore failure")
	require.True(t, terminated)
	require.ErrorContains(t, err,
		"sent SIGKILL rather than detach with injector state installed")
	require.ErrorIs(t, err, errUnsafeTraceeTerminated)
	assert.NotContains(t, err.Error(), "target termination was not observed")
	require.ErrorIs(t, unix.Kill(cmd.Process.Pid, 0), unix.ESRCH)
}

func TestPtraceSessionCloseRefusesUnsafeDetach(t *testing.T) {
	session := &ptraceSession{
		threads:        []int{1234},
		unsafeToDetach: map[int]struct{}{1234: {}},
	}
	_, err := session.Call(0)
	require.ErrorContains(t, err, "unrestored remote-call state")
	require.ErrorContains(t, session.Close(),
		"refusing to detach tid 1234 with unrestored remote-call state")
	assert.True(t, session.closed)
}

func TestRemoteCallRejectsInvalidDataArgument(t *testing.T) {
	_, err := (&ptraceSession{}).call(0, []uint64{0}, -1, []byte{1})
	require.ErrorContains(t, err, "remote data argument -1 is invalid")

	_, err = (&ptraceSession{}).call(0, []uint64{0}, 1, []byte{1})
	require.ErrorContains(t, err, "remote data argument 1 outside 1 arguments")
}

func TestPotentialRemoteReturnStop(t *testing.T) {
	returned := unix.WaitStatus(int(unix.SIGSEGV)<<8 | 0x7f)
	stopped := unix.WaitStatus(int(unix.SIGSTOP)<<8 | 0x7f)
	assert.True(t, potentialRemoteReturnStop(returned))
	assert.False(t, potentialRemoteReturnStop(stopped))
	assert.False(t, potentialRemoteReturnStop(0))
	assert.True(t, isInjectorFaultSignal(unix.SIGSEGV))
	assert.True(t, isInjectorFaultSignal(unix.SIGILL))
	assert.False(t, isInjectorFaultSignal(unix.SIGTERM))
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

func TestPtraceSessionDetachFallbackRedeliversSavedSignal(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dir := t.TempDir()
	termMarker := filepath.Join(dir, "sigterm-delivered")
	usr1Marker := filepath.Join(dir, "sigusr1-delivered")
	cmd := exec.Command("sh", "-c",
		`trap ': > "$TERM_MARKER"' TERM; trap ': > "$USR1_MARKER"' USR1; `+
			`echo ready; while :; do :; done`)
	cmd.Env = append(os.Environ(), "TERM_MARKER="+termMarker, "USR1_MARKER="+usr1Marker)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "target did not install its signal handlers")
	require.Equal(t, "ready", scanner.Text())
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

	// Simulate two workload signals retained across separate remote calls while
	// forcing Close down its running-tracee fallback. The cleanup SIGSTOP is a
	// group-stop, so both signals must be requeued after a zero-signal detach.
	session.preserveSignalOnDetach(cmd.Process.Pid, unix.SIGTERM)
	session.preserveSignalOnDetach(cmd.Process.Pid, unix.SIGUSR1)
	require.NoError(t, unix.PtraceCont(cmd.Process.Pid, 0))
	require.NoError(t, session.Close())

	require.Eventually(t, func() bool {
		_, termErr := os.Stat(termMarker)
		_, usr1Err := os.Stat(usr1Marker)
		return termErr == nil && usr1Err == nil
	}, 2*time.Second, 10*time.Millisecond,
		"saved target signals were lost during detach fallback")
}

func TestConsumePendingRecoveryStopKeepsTraceeRunnableAfterDetach(t *testing.T) {
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

	// Simulate the timeout race: the tracee is already in another ptrace stop
	// when the recovery SIGSTOP is generated, so that stop remains pending.
	require.NoError(t, unix.Tgkill(cmd.Process.Pid, cmd.Process.Pid, unix.SIGSTOP))
	require.NoError(t, consumePendingRecoveryStop(cmd.Process.Pid, cmd.Process.Pid, 0))
	require.NoError(t, session.Close())

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("detached tracee remained stopped by the recovery SIGSTOP")
	}
}

func TestConsumePendingRecoveryStopRedeliversTargetSignals(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dir := t.TempDir()
	termMarker := filepath.Join(dir, "sigterm-delivered")
	usr1Marker := filepath.Join(dir, "sigusr1-delivered")
	cmd := exec.Command("sh", "-c",
		`trap ': > "$TERM_MARKER"' TERM; trap ': > "$USR1_MARKER"' USR1; `+
			`echo ready; while :; do :; done`)
	cmd.Env = append(os.Environ(),
		"TERM_MARKER="+termMarker, "USR1_MARKER="+usr1Marker)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "target did not install its SIGTERM handler")
	require.Equal(t, "ready", scanner.Text())
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

	// Put SIGTERM in the current ptrace signal-delivery stop, then queue the
	// timeout-recovery SIGSTOP and a lower-numbered SIGUSR1 behind it. Linux
	// presents SIGUSR1 before SIGSTOP; recovery must preserve both target signals.
	require.NoError(t, unix.PtraceCont(cmd.Process.Pid, 0))
	require.NoError(t, unix.Tgkill(cmd.Process.Pid, cmd.Process.Pid, unix.SIGTERM))
	status, observed, err := pollWaitStatus(cmd.Process.Pid, ptraceStopRecoveryTime)
	require.NoError(t, err)
	require.True(t, observed)
	require.True(t, status.Stopped())
	require.Equal(t, unix.SIGTERM, status.StopSignal())
	require.NoError(t, unix.Tgkill(cmd.Process.Pid, cmd.Process.Pid, unix.SIGSTOP))
	require.NoError(t, unix.Tgkill(cmd.Process.Pid, cmd.Process.Pid, unix.SIGUSR1))

	require.NoError(t, consumePendingRecoveryStop(
		cmd.Process.Pid, cmd.Process.Pid, int(unix.SIGTERM)))
	require.NoError(t, session.Close())

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, termErr := os.Stat(termMarker)
		_, usr1Err := os.Stat(usr1Marker)
		if termErr == nil && usr1Err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("target signal handlers did not both run after recovery: "+
				"SIGTERM=%v SIGUSR1=%v", termErr, usr1Err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConsumePendingRecoveryStopFallbackPreservesSignals(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dir := t.TempDir()
	markers := map[unix.Signal]string{
		unix.SIGHUP:  filepath.Join(dir, "sighup-delivered"),
		unix.SIGUSR1: filepath.Join(dir, "sigusr1-delivered"),
		unix.SIGUSR2: filepath.Join(dir, "sigusr2-delivered"),
		unix.SIGALRM: filepath.Join(dir, "sigalrm-delivered"),
		unix.SIGTERM: filepath.Join(dir, "sigterm-delivered"),
	}
	cmd := exec.Command("sh", "-c",
		`trap ': > "$HUP_MARKER"' HUP; trap ': > "$USR1_MARKER"' USR1; `+
			`trap ': > "$USR2_MARKER"' USR2; trap ': > "$ALRM_MARKER"' ALRM; `+
			`trap ': > "$TERM_MARKER"' TERM; echo ready; while :; do :; done`)
	cmd.Env = append(os.Environ(),
		"HUP_MARKER="+markers[unix.SIGHUP],
		"USR1_MARKER="+markers[unix.SIGUSR1],
		"USR2_MARKER="+markers[unix.SIGUSR2],
		"ALRM_MARKER="+markers[unix.SIGALRM],
		"TERM_MARKER="+markers[unix.SIGTERM])
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "target did not install its signal handlers")
	require.Equal(t, "ready", scanner.Text())
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

	// Hold SIGTERM in the current signal-delivery stop. Queue four lower-numbered
	// signals ahead of SIGSTOP so the bounded primary loop is exhausted and the
	// fallback stop path must preserve every signal it consumed.
	require.NoError(t, unix.PtraceCont(cmd.Process.Pid, 0))
	require.NoError(t, unix.Tgkill(cmd.Process.Pid, cmd.Process.Pid, unix.SIGTERM))
	status, observed, err := pollWaitStatus(cmd.Process.Pid, ptraceStopRecoveryTime)
	require.NoError(t, err)
	require.True(t, observed)
	require.True(t, status.Stopped())
	require.Equal(t, unix.SIGTERM, status.StopSignal())
	require.NoError(t, unix.Tgkill(cmd.Process.Pid, cmd.Process.Pid, unix.SIGSTOP))
	for _, signal := range []unix.Signal{unix.SIGHUP, unix.SIGUSR1, unix.SIGUSR2, unix.SIGALRM} {
		require.NoError(t, unix.Tgkill(cmd.Process.Pid, cmd.Process.Pid, signal))
	}

	require.NoError(t, consumePendingRecoveryStop(
		cmd.Process.Pid, cmd.Process.Pid, int(unix.SIGTERM)))
	require.NoError(t, session.Close())

	deadline := time.Now().Add(5 * time.Second)
	for {
		var missing []unix.Signal
		for signal, marker := range markers {
			if _, err := os.Stat(marker); err != nil {
				missing = append(missing, signal)
			}
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("target handlers did not receive signals after fallback: %v", missing)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Prove no second recovery SIGSTOP remained pending after detach. A stopped
	// tracee would not run this new signal handler invocation.
	require.NoError(t, os.Remove(markers[unix.SIGUSR2]))
	require.NoError(t, unix.Tgkill(cmd.Process.Pid, cmd.Process.Pid, unix.SIGUSR2))
	require.Eventually(t, func() bool {
		_, err := os.Stat(markers[unix.SIGUSR2])
		return err == nil
	}, 2*time.Second, 10*time.Millisecond,
		"tracee remained stopped after fallback recovery detach")
}

func TestPtraceRemoteCallRedeliversCurrentTargetSignal(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable for ptrace signal target")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "sigterm-delivered")
	source := filepath.Join(dir, "remote-call-signal.c")
	target := filepath.Join(dir, "remote-call-signal")
	require.NoError(t, os.WriteFile(source, []byte(`#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
static const char *marker;
static void handle_term(int signal) {
  (void)signal;
  int fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd >= 0) close(fd);
}
__attribute__((noinline)) static void grow_stack(void) {
  volatile char padding[65536];
  for (size_t i = 0; i < sizeof(padding); i += 4096) padding[i] = 1;
}
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  marker = argv[1];
  grow_stack();
  struct sigaction action = {0};
  action.sa_handler = handle_term;
  sigaction(SIGTERM, &action, NULL);
  puts("ready");
  fflush(stdout);
  for (;;) pause();
}
`), 0o600))
	build := exec.Command(compiler, "-O0", "-g", "-o", target, source)
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))

	cmd := exec.Command(target, marker)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "target did not install its SIGTERM handler")
	require.Equal(t, "ready", scanner.Text())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	pauseAddr, err := resolveProcessSymbol(cmd.Process.Pid, "pause", isAllocatorRuntimeMapping)
	require.NoError(t, err)
	session, err := attachThreads(cmd.Process.Pid, []int{cmd.Process.Pid})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("ptrace unavailable: %v", err)
	}
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	signalDone := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		signalDone <- unix.Tgkill(cmd.Process.Pid, cmd.Process.Pid, unix.SIGTERM)
	}()
	_, callErr := session.Call(pauseAddr)
	require.ErrorContains(t, callErr, "stopped unexpectedly")
	require.NoError(t, <-signalDone)
	require.NoError(t, session.Close())

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("target SIGTERM handler did not run after remote-call cleanup")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPtraceRemoteCallHandlesTargetExit(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable for ptrace target")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "remote-call-exit.c")
	target := filepath.Join(dir, "remote-call-exit")
	require.NoError(t, os.WriteFile(source, []byte(`#include <stdio.h>
#include <unistd.h>
__attribute__((noinline, visibility("default")))
void remote_wait(void) { for (;;) pause(); }
int main(void) {
  printf("%p\n", (void *)remote_wait);
  fflush(stdout);
  for (;;) pause();
}
`), 0o600))
	build := exec.Command(compiler, "-O0", "-g", "-fno-pie", "-no-pie",
		"-o", target, source)
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))

	cmd := exec.Command(target)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "target did not publish remote function address")
	remoteAddr, err := strconv.ParseUint(strings.TrimPrefix(scanner.Text(), "0x"), 16, 64)
	require.NoError(t, err)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	session, err := attachThreads(cmd.Process.Pid, []int{cmd.Process.Pid})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("ptrace unavailable: %v", err)
	}
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	killDone := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		killDone <- cmd.Process.Kill()
	}()
	_, callErr := session.Call(remoteAddr)
	require.Error(t, callErr, "remote call unexpectedly survived target exit")
	require.NoError(t, <-killDone)
	require.NoError(t, session.Close(), "exited tracee was not cleaned up")
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
	semaphoreOffsets := make(map[string]uint64)
	for _, probe := range probes {
		if probe.Provider != ExperimentalShimProvider {
			continue
		}
		if probe.Name == "alloc" || probe.Name == "free" {
			assert.NotZero(t, probe.SemaphoreOffset)
			found[probe.Name] = true
			semaphoreOffsets[probe.Name] = probe.SemaphoreOffset
		}
	}
	assert.Equal(t, map[string]bool{"alloc": true, "free": true}, found)
	assert.NotEqual(t, semaphoreOffsets["alloc"], semaphoreOffsets["free"])

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

	sharedSemaphore := append([]byte(nil), contents...)
	freeNote := bytes.Index(sharedSemaphore,
		[]byte(ExperimentalShimProvider+"\x00free\x00"))
	require.GreaterOrEqual(t, freeNote, 8, "free USDT descriptor not found")
	copy(sharedSemaphore[freeNote-8:freeNote], contents[allocNote-8:allocNote])
	require.ErrorContains(t, validateExperimentalShimProbes(sharedSemaphore),
		"share one semaphore")

	writableShim := filepath.Join(t.TempDir(), "libprophiler-heap-shim.so")
	require.NoError(t, os.WriteFile(writableShim, contents, 0o600))
	require.NoError(t, os.Chmod(writableShim, 0o666))
	_, err = newAllocatorInjector(
		writableShim, InjectionGOT, DefaultSamplingIntervalBytes, false)
	require.ErrorContains(t, err, "group/world writable")

	_, err = newAllocatorInjector(t.TempDir(), InjectionGOT,
		DefaultSamplingIntervalBytes, false)
	require.ErrorContains(t, err, "must be a regular file")

	mappedFile, err := os.Open(shim)
	require.NoError(t, err)
	defer mappedFile.Close()
	mapped, err := unix.Mmap(int(mappedFile.Fd()), 0, len(contents),
		unix.PROT_READ, unix.MAP_PRIVATE)
	require.NoError(t, err)
	defer unix.Munmap(mapped)
	start := uintptr(unsafe.Pointer(&mapped[0]))
	pageSize := uintptr(os.Getpagesize())
	mappedLength := (uintptr(len(contents)) + pageSize - 1) &^ (pageSize - 1)
	mapping := processMapping{start: uint64(start), end: uint64(start + mappedLength)}
	if err := validateExistingShimMapping(os.Getpid(), mapping, contents); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Logf("skipping map_files identity assertion without permission: %v", err)
			return
		}
		require.NoError(t, err)
	}
	mismatched := append([]byte(nil), contents...)
	mismatched[len(mismatched)-1] ^= 1
	require.ErrorContains(t,
		validateExistingShimMapping(os.Getpid(), mapping, mismatched),
		"does not match configured shim image")
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

			targetExecutable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid))
			require.NoError(t, err)
			injector, err := newAllocatorInjector(
				shim, test.mode, DefaultSamplingIntervalBytes, test.requireFree)
			require.NoError(t, err)
			if test.name == "got-allocation" {
				_, err := injector.Inject(
					libpf.PID(cmd.Process.Pid), libpf.Intern("/unexpected/executable"))
				require.ErrorContains(t, err, "target executable changed before injection")
				require.NoError(t, cmd.Process.Signal(syscall.Signal(0)),
					"identity rejection must not mutate or terminate the target")
			}
			result, err := injector.Inject(
				libpf.PID(cmd.Process.Pid), libpf.Intern(targetExecutable))
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
			second, err := injector.Inject(
				libpf.PID(cmd.Process.Pid), libpf.Intern(targetExecutable))
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
