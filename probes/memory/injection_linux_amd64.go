// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package memory // import "go.opentelemetry.io/ebpf-profiler/probes/memory"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	parcausdt "github.com/parca-dev/usdt"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

const (
	remoteCallTimeout       = 5 * time.Second
	ptraceStopRecoveryTime  = time.Second
	maxThreadAttachPasses   = 16
	maxExperimentalShimSize = 16 << 20
	remoteSysMemfdCreate    = 319
	remoteSysClose          = 3
	remoteMfdFlags          = unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING
	remoteMfdSeals          = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	remoteRtldNow = 2

	shimGOTMallocBit    = 1 << 0
	shimGOTFreeBit      = 1 << 1
	shimInlineMallocBit = 1 << 2
	shimInlineFreeBit   = 1 << 3
)

func requiredAllocatorPatchesPresent(status uint64, requireFree bool,
	mallocBit, freeBit uint64) bool {
	if status&mallocBit == 0 {
		return false
	}
	return !requireFree || status&freeBit != 0
}

type ptraceAllocatorInjector struct {
	shim             []byte
	mode             InjectionMode
	samplingInterval uint64
	requireFree      bool
}

func newAllocatorInjector(path string, mode InjectionMode,
	samplingInterval uint64, requireFree bool) (allocatorInjector, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open experimental allocator shim %q: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat experimental allocator shim %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("experimental allocator shim %q must be a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("experimental allocator shim %q must not be group/world writable", path)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, fmt.Errorf("fstat experimental allocator shim %q: %w", path, err)
	}
	euid := uint32(os.Geteuid())
	if !trustedShimOwner(stat.Uid, euid) {
		return nil, fmt.Errorf("experimental allocator shim %q must be owned by root or profiler uid %d, got uid %d",
			path, euid, stat.Uid)
	}
	if info.Size() <= 0 || info.Size() > maxExperimentalShimSize {
		return nil, fmt.Errorf("experimental allocator shim %q has invalid size %d", path, info.Size())
	}

	// Read through the already-validated descriptor. Injection uses this immutable
	// snapshot, so replacing the configured path later cannot change the bytes
	// copied into a target.
	shim, err := io.ReadAll(io.LimitReader(file, maxExperimentalShimSize+1))
	if err != nil {
		return nil, fmt.Errorf("read experimental allocator shim %q: %w", path, err)
	}
	if len(shim) > maxExperimentalShimSize {
		return nil, fmt.Errorf("experimental allocator shim %q exceeds %d bytes", path, maxExperimentalShimSize)
	}
	parsed, err := elf.NewFile(bytes.NewReader(shim))
	if err != nil {
		return nil, fmt.Errorf("parse experimental allocator shim %q: %w", path, err)
	}
	defer parsed.Close()
	if parsed.Class != elf.ELFCLASS64 || parsed.Machine != elf.EM_X86_64 || parsed.Type != elf.ET_DYN {
		return nil, fmt.Errorf("experimental allocator shim must be an x86-64 ET_DYN ELF")
	}
	if err := validateExperimentalShimSymbols(parsed, mode); err != nil {
		return nil, fmt.Errorf("validate experimental allocator shim %q: %w", path, err)
	}
	if err := validateExperimentalShimProbes(shim); err != nil {
		return nil, fmt.Errorf("validate experimental allocator shim %q: %w", path, err)
	}
	return &ptraceAllocatorInjector{
		shim: shim, mode: mode, samplingInterval: samplingInterval,
		requireFree: requireFree,
	}, nil
}

func trustedShimOwner(fileUID, profilerUID uint32) bool {
	return fileUID == 0 || fileUID == profilerUID
}

func validateExperimentalShimSymbols(parsed *elf.File, mode InjectionMode) error {
	required := map[string]bool{
		"malloc":                               false,
		"free":                                 false,
		ExperimentalShimAllocSymbol:            false,
		ExperimentalShimFreeSymbol:             false,
		"prophiler_heap_set_sampling_interval": false,
		"prophiler_heap_install_got":           false,
	}
	if mode == InjectionGOTThenInline {
		required["prophiler_heap_install_inline"] = false
	}
	symbols, err := parsed.DynamicSymbols()
	if err != nil {
		return fmt.Errorf("read dynamic symbols: %w", err)
	}
	for _, symbol := range symbols {
		if _, wanted := required[symbol.Name]; wanted && symbol.Section != elf.SHN_UNDEF &&
			elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
			required[symbol.Name] = true
		}
	}
	var missing []string
	for name, present := range required {
		if !present {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		return fmt.Errorf("missing exported symbols: %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateExperimentalShimProbes(shim []byte) error {
	parsed, err := pfelf.NewFile(bytes.NewReader(shim), 0, false)
	if err != nil {
		return fmt.Errorf("parse probe ELF: %w", err)
	}
	defer parsed.Close()
	probes, err := parcausdt.ParseProbes(&pfelfReader{f: parsed})
	if err != nil {
		return fmt.Errorf("parse USDT notes: %w", err)
	}

	required := map[string]bool{"alloc": false, "free": false}
	semaphoreOffsets := make(map[string]uint64, len(required))
	for _, probe := range probes {
		if probe.Provider != ExperimentalShimProvider {
			continue
		}
		if _, wanted := required[probe.Name]; !wanted {
			continue
		}
		if probe.SemaphoreOffset == 0 {
			return fmt.Errorf("USDT probe %s:%s has no semaphore offset",
				probe.Provider, probe.Name)
		}
		if len(shim) < 2 || probe.SemaphoreOffset > uint64(len(shim)-2) {
			return fmt.Errorf("USDT probe %s:%s semaphore offset %#x is outside the shim",
				probe.Provider, probe.Name, probe.SemaphoreOffset)
		}
		required[probe.Name] = true
		semaphoreOffsets[probe.Name] = probe.SemaphoreOffset
	}
	for name, found := range required {
		if !found {
			return fmt.Errorf("missing semaphore-gated USDT probe %s:%s",
				ExperimentalShimProvider, name)
		}
	}
	if semaphoreOffsets["alloc"] == semaphoreOffsets["free"] {
		return errors.New("allocation and free USDT probes share one semaphore")
	}
	return nil
}

func validateOpenedShimMemfd(file *os.File, stat *unix.Stat_t) error {
	if file == nil || stat == nil {
		return errors.New("missing opened memfd or stat destination")
	}
	if err := unix.Fstat(int(file.Fd()), stat); err != nil {
		return fmt.Errorf("stat opened target fd: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 0 {
		return fmt.Errorf("target fd is not an unlinked regular memfd (mode=%#o nlink=%d)",
			stat.Mode, stat.Nlink)
	}
	openedPath := fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	target, err := os.Readlink(openedPath)
	if err != nil {
		return fmt.Errorf("read opened target fd identity: %w", err)
	}
	target = strings.TrimSuffix(target, " (deleted)")
	if target != "/memfd:prophiler-heap-shim" && target != "memfd:prophiler-heap-shim" {
		return fmt.Errorf("target fd is not the requested heap shim memfd: %q", target)
	}
	return nil
}

type targetExecutableIdentity struct {
	path      string
	device    uint64
	inode     uint64
	startTime uint64
}

func readProcessStartTime(pid int) (uint64, error) {
	contents, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// comm is parenthesized and may contain spaces or ')'. Fields after the
	// final ')' begin at field 3; starttime is field 22, hence offset 19.
	commEnd := bytes.LastIndexByte(contents, ')')
	if commEnd < 0 {
		return 0, errors.New("process stat has no closing comm parenthesis")
	}
	fields := strings.Fields(string(contents[commEnd+1:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("process stat has %d fields after comm, need 20", len(fields))
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse process start time: %w", err)
	}
	return startTime, nil
}

func readTargetExecutableIdentity(pid int) (targetExecutableIdentity, error) {
	startBefore, err := readProcessStartTime(pid)
	if err != nil {
		return targetExecutableIdentity{}, fmt.Errorf("read process start time: %w", err)
	}
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	resolved, err := os.Readlink(exePath)
	if err != nil {
		return targetExecutableIdentity{}, fmt.Errorf("read process executable path: %w", err)
	}
	file, err := os.Open(exePath)
	if err != nil {
		return targetExecutableIdentity{}, fmt.Errorf("open process executable: %w", err)
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return targetExecutableIdentity{}, fmt.Errorf("stat process executable: %w", err)
	}
	startAfter, err := readProcessStartTime(pid)
	if err != nil {
		return targetExecutableIdentity{}, fmt.Errorf("re-read process start time: %w", err)
	}
	if startBefore != startAfter {
		return targetExecutableIdentity{}, errors.New("process identity changed while reading executable")
	}
	return targetExecutableIdentity{
		path: resolved, device: uint64(stat.Dev), inode: stat.Ino, startTime: startAfter,
	}, nil
}

func sameTargetExecutable(first, second targetExecutableIdentity) bool {
	return first.path == second.path && first.device == second.device &&
		first.inode == second.inode && first.startTime == second.startTime
}

func validateExistingShimMapping(pid int, mapping processMapping, expected []byte) error {
	mappingPath := fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, mapping.start, mapping.end)
	file, err := os.Open(mappingPath)
	if err != nil {
		return fmt.Errorf("open claimed existing shim mapping %s: %w", mappingPath, err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxExperimentalShimSize+1))
	if err != nil {
		return fmt.Errorf("read claimed existing shim mapping %s: %w", mappingPath, err)
	}
	if !bytes.Equal(contents, expected) {
		return fmt.Errorf("claimed existing shim mapping %s does not match configured shim image",
			mappingPath)
	}
	return nil
}

func sealOpenedShimMemfd(file *os.File) error {
	if file == nil {
		return errors.New("missing opened memfd")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, remoteMfdSeals); err != nil {
		return fmt.Errorf("seal target shim memfd: %w", err)
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return fmt.Errorf("read target shim memfd seals: %w", err)
	}
	if seals&remoteMfdSeals != remoteMfdSeals {
		return fmt.Errorf("target shim memfd has incomplete seals %#x", seals)
	}
	return nil
}

func (i *ptraceAllocatorInjector) Inject(pid libpf.PID,
	expectedExecutable libpf.String,
) (result InjectionResult, retErr error) {
	// Linux records ptrace ownership at thread granularity. Keep every attach,
	// wait, register operation, and detach on one tracer thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	leader := int(pid)
	initialIdentity, err := readTargetExecutableIdentity(leader)
	if err != nil {
		return result, fmt.Errorf("read target identity before injection: %w", err)
	}
	if expectedExecutable == libpf.NullString ||
		initialIdentity.path != expectedExecutable.String() {
		return result, fmt.Errorf("target executable changed before injection: expected %q, got %q",
			expectedExecutable.String(), initialIdentity.path)
	}

	// Keep other threads running while invoking the dynamic loader. Stopping all
	// of them can deadlock if one owns rtld's loader lock. This is still invasive:
	// ptrace redirects an arbitrary stopped thread through libc.
	session, err := attachThreads(leader, []int{leader})
	if err != nil {
		return result, err
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			retErr = errors.Join(retErr, closeErr)
		}
	}()

	stoppedIdentity, err := readTargetExecutableIdentity(leader)
	if err != nil {
		return result, fmt.Errorf("verify stopped target identity: %w", err)
	}
	if !sameTargetExecutable(initialIdentity, stoppedIdentity) {
		return result, fmt.Errorf("target executable changed before ptrace mutation: "+
			"before=%q dev=%d ino=%d start=%d stopped=%q dev=%d ino=%d start=%d",
			initialIdentity.path, initialIdentity.device, initialIdentity.inode,
			initialIdentity.startTime, stoppedIdentity.path, stoppedIdentity.device,
			stoppedIdentity.inode, stoppedIdentity.startTime)
	}

	mappings, err := readProcessMappings(leader)
	if err != nil {
		return result, fmt.Errorf("read stopped target mappings before injection: %w", err)
	}
	for _, mapping := range mappings {
		if !isExperimentalShimMapping(mapping) {
			continue
		}
		if err := validateExistingShimMapping(leader, mapping, i.shim); err != nil {
			return result, err
		}
		result.AlreadyPresent = true
		return result, nil
	}

	// Resolve remote call sites only after stopping and revalidating the leader;
	// pre-attach addresses can refer to a replaced process image after exec/PID reuse.
	syscallAddr, err := resolveProcessSymbol(leader, "syscall", isAllocatorRuntimeMapping)
	if err != nil {
		return result, fmt.Errorf("resolve libc syscall: %w", err)
	}
	dlopenAddr, err := resolveProcessSymbol(leader, "dlopen", isAllocatorRuntimeMapping)
	if err != nil {
		return result, fmt.Errorf("resolve dlopen: %w", err)
	}

	fdValue, err := session.CallWithData(syscallAddr,
		[]uint64{remoteSysMemfdCreate, 0, remoteMfdFlags}, 1,
		[]byte("prophiler-heap-shim\x00"))
	if err != nil {
		return result, fmt.Errorf("remote memfd_create: %w", err)
	}
	fd := int64(fdValue)
	if fd < 0 || fd > 1<<20 {
		return result, fmt.Errorf("remote memfd_create returned invalid fd %d", fd)
	}

	fdPath := fmt.Sprintf("/proc/%d/fd/%d", leader, fd)
	remoteFile, err := os.OpenFile(fdPath, os.O_WRONLY, 0)
	if err != nil {
		return result, fmt.Errorf("open target memfd %s: %w", fdPath, err)
	}
	var remoteStat unix.Stat_t
	identityErr := validateOpenedShimMemfd(remoteFile, &remoteStat)
	truncateErr := error(nil)
	if identityErr == nil {
		truncateErr = remoteFile.Truncate(int64(len(i.shim)))
	}
	var copyErr error
	if identityErr == nil && truncateErr == nil {
		var written int
		written, copyErr = remoteFile.Write(i.shim)
		if copyErr == nil && written != len(i.shim) {
			copyErr = io.ErrShortWrite
		}
	}
	var sealErr error
	if identityErr == nil && truncateErr == nil && copyErr == nil {
		sealErr = sealOpenedShimMemfd(remoteFile)
	}
	closeErr := remoteFile.Close()
	if identityErr != nil || truncateErr != nil || copyErr != nil || sealErr != nil || closeErr != nil {
		return result, fmt.Errorf("populate target memfd: %w",
			errors.Join(identityErr, truncateErr, copyErr, sealErr, closeErr))
	}
	injectedShimMapping := func(mapping processMapping) bool {
		return isExperimentalShimMapping(mapping) &&
			mapping.device == uint64(remoteStat.Dev) && mapping.inode == remoteStat.Ino
	}

	fdOpen := true
	defer func() {
		if fdOpen && session != nil && !session.closed && len(session.unsafeToDetach) == 0 {
			if _, err := session.Call(syscallAddr, remoteSysClose, uint64(fd)); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close target shim memfd: %w", err))
			}
		}
	}()

	handle, err := session.CallWithData(dlopenAddr,
		[]uint64{0, remoteRtldNow}, 0,
		[]byte(fmt.Sprintf("/proc/self/fd/%d\x00", fd)))
	if err != nil {
		return result, fmt.Errorf("remote dlopen: %w", err)
	}
	if handle == 0 {
		return result, errors.New("remote dlopen returned NULL")
	}

	setSamplingInterval, err := resolveProcessSymbol(
		leader, "prophiler_heap_set_sampling_interval", injectedShimMapping)
	if err != nil {
		return result, fmt.Errorf("resolve injected sampling configuration: %w", err)
	}
	if _, err := session.Call(setSamplingInterval, i.samplingInterval); err != nil {
		return result, fmt.Errorf("configure injected sampling interval: %w", err)
	}

	installGOT, err := resolveProcessSymbol(
		leader, "prophiler_heap_install_got", injectedShimMapping)
	if err != nil {
		return result, fmt.Errorf("resolve injected GOT installer: %w", err)
	}
	requireFree := uint64(0)
	if i.requireFree {
		requireFree = 1
	}
	status, err := session.Call(installGOT, requireFree)
	if err != nil {
		return result, fmt.Errorf("invoke injected GOT installer: %w", err)
	}
	var installInline uint64
	if i.mode == InjectionGOTThenInline {
		installInline, err = resolveProcessSymbol(
			leader, "prophiler_heap_install_inline", injectedShimMapping)
		if err != nil {
			return result, fmt.Errorf("resolve injected inline installer: %w", err)
		}
	}
	result.GOTMallocPatched = status&shimGOTMallocBit != 0
	result.GOTFreePatched = status&shimGOTFreeBit != 0
	result.PatchedSlots = uint32(status >> 32)
	if _, err := session.Call(syscallAddr, remoteSysClose, uint64(fd)); err != nil {
		return result, fmt.Errorf("close target shim memfd: %w", err)
	}
	fdOpen = false
	gotSufficient := requiredAllocatorPatchesPresent(status, i.requireFree,
		shimGOTMallocBit, shimGOTFreeBit)
	if gotSufficient {
		return result, nil
	}
	if i.mode != InjectionGOTThenInline {
		return result, fmt.Errorf("shim loaded but required malloc/free GOT/PLT relocations were not patched (status=%#x)", status)
	}

	// The fallback overwrites executable allocator text. Suspend every thread to
	// reduce (not eliminate) the chance of another CPU executing a half-written
	// jump. The shim validates and installs architecture-specific trampolines.
	if err := session.Close(); err != nil {
		return result, fmt.Errorf("detach loader session before inline fallback: %w", err)
	}
	session = nil

	allSession, err := attachAllThreads(leader)
	if err != nil {
		return result, fmt.Errorf("stop target for inline fallback: %w", err)
	}
	defer func() {
		if closeErr := allSession.Close(); closeErr != nil {
			retErr = errors.Join(retErr, closeErr)
		}
	}()

	// Detaching the loader session creates an exec window. Revalidate both the
	// selected executable and the exact injected memfd mapping while every target
	// thread is stopped before calling the previously resolved inline installer.
	inlineIdentity, err := readTargetExecutableIdentity(leader)
	if err != nil {
		return result, fmt.Errorf("verify inline target identity: %w", err)
	}
	if !sameTargetExecutable(initialIdentity, inlineIdentity) {
		return result, errors.New("target executable changed before inline mutation")
	}
	inlineMappings, err := readProcessMappings(leader)
	if err != nil {
		return result, fmt.Errorf("read stopped target mappings before inline mutation: %w", err)
	}
	installerStillMapped := false
	for _, mapping := range inlineMappings {
		if injectedShimMapping(mapping) && installInline >= mapping.start &&
			installInline < mapping.end {
			installerStillMapped = true
			break
		}
	}
	if !installerStillMapped {
		return result, errors.New("injected inline installer mapping changed before mutation")
	}

	inlineStatus, err := allSession.Call(installInline, requireFree)
	if err != nil {
		return result, fmt.Errorf("invoke injected inline installer: %w", err)
	}
	result.InlineMallocPatched = inlineStatus&shimInlineMallocBit != 0
	result.InlineFreePatched = inlineStatus&shimInlineFreeBit != 0
	inlineSufficient := requiredAllocatorPatchesPresent(inlineStatus, i.requireFree,
		shimInlineMallocBit, shimInlineFreeBit)
	if !inlineSufficient {
		return result, fmt.Errorf(
			"shim failed required direct allocator text patches (status=%#x, require_free=%t)",
			inlineStatus, i.requireFree)
	}
	return result, nil
}

type ptraceSession struct {
	leader         int
	threads        []int
	detachSignals  map[int][]unix.Signal
	unsafeToDetach map[int]struct{}
	closed         bool
}

func attachThreads(leader int, tids []int) (*ptraceSession, error) {
	s := &ptraceSession{leader: leader}
	for _, tid := range tids {
		if err := s.attachThread(tid); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

// attachAllThreads repeatedly snapshots /proc/<pid>/task. Once every listed
// thread is ptrace-stopped, none can clone another thread, making the final
// no-missing-thread pass stable enough to patch process-wide executable text.
func attachAllThreads(leader int) (*ptraceSession, error) {
	s, err := attachThreads(leader, []int{leader})
	if err != nil {
		return nil, err
	}
	for pass := 0; pass < maxThreadAttachPasses; pass++ {
		tids, err := listThreadIDs(leader)
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("list target threads: %w", err)
		}
		missing := false
		for _, tid := range tids {
			if s.hasThread(tid) {
				continue
			}
			missing = true
			if err := s.attachThread(tid); err != nil {
				if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ECHILD) {
					continue
				}
				_ = s.Close()
				return nil, err
			}
		}
		if !missing {
			return s, nil
		}
	}
	_ = s.Close()
	return nil, fmt.Errorf("target thread list did not stabilize after %d passes",
		maxThreadAttachPasses)
}

func (s *ptraceSession) hasThread(tid int) bool {
	for _, attached := range s.threads {
		if attached == tid {
			return true
		}
	}
	return false
}

func (s *ptraceSession) attachThread(tid int) error {
	if s.hasThread(tid) {
		return nil
	}
	if err := unix.PtraceAttach(tid); err != nil {
		return fmt.Errorf("ptrace attach tid %d: %w", tid, err)
	}
	// Track the relationship immediately so error cleanup at least attempts to
	// detach a thread whose stop notification is delayed or lost.
	s.threads = append(s.threads, tid)

	timeout := remoteCallTimeout
	recoveryStopSent := false
	for range 6 {
		status, stopped, err := pollWaitStatus(tid, timeout)
		if err != nil {
			return fmt.Errorf("wait for ptrace stop tid %d: %w", tid, err)
		}
		if !stopped {
			if recoveryStopSent {
				return fmt.Errorf("timed out waiting for ptrace stop tid %d", tid)
			}
			// PTRACE_ATTACH normally supplies SIGSTOP. Retry explicitly but never
			// follow a timed wait with an unbounded Wait4.
			if err := unix.Tgkill(s.leader, tid, unix.SIGSTOP); err != nil {
				return fmt.Errorf("send recovery ptrace stop tid %d: %w", tid, err)
			}
			recoveryStopSent = true
			timeout = ptraceStopRecoveryTime
			continue
		}
		if status.Exited() || status.Signaled() {
			return fmt.Errorf("tid %d exited while attaching: %v", tid, status)
		}
		if !status.Stopped() {
			return fmt.Errorf("tid %d did not enter ptrace stop: %v", tid, status)
		}
		if status.StopSignal() == unix.SIGSTOP {
			return nil
		}

		// A workload signal can win the race with PTRACE_ATTACH's SIGSTOP.
		// Retain every such signal for detach, and continue with signal zero
		// until the attach/recovery stop itself has been consumed.
		s.preserveSignalOnDetach(tid, status.StopSignal())
		if err := unix.PtraceCont(tid, 0); err != nil {
			return fmt.Errorf("continue tid %d while consuming attach stop: %w", tid, err)
		}
		timeout = ptraceStopRecoveryTime
	}
	return fmt.Errorf("ptrace stop tid %d was starved by target signals", tid)
}

func (s *ptraceSession) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	for n := len(s.threads) - 1; n >= 0; n-- {
		tid := s.threads[n]
		if _, unsafe := s.unsafeToDetach[tid]; unsafe {
			errs = append(errs, fmt.Errorf(
				"refusing to detach tid %d with unrestored remote-call state", tid))
			continue
		}
		if err := s.detachThread(tid); err != nil {
			errs = append(errs, fmt.Errorf("ptrace detach tid %d: %w", tid, err))
		}
	}
	return errors.Join(errs...)
}

func terminateUnsafeTracee(tgid, tid int, reason string) (terminated bool, retErr error) {
	// Use a process-directed fatal signal. The traced leader can exit while
	// sibling threads remain alive; tgkill(leader) would then report ESRCH and
	// leave a potentially partially mutated process running.
	if err := unix.Kill(tgid, unix.SIGKILL); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return true, nil
		}
		return false, fmt.Errorf("%s; terminate target: %w", reason, err)
	}

	terminationErr := errors.Join(errUnsafeTraceeTerminated, fmt.Errorf(
		"%s; sent SIGKILL rather than detach with injector state installed", reason))
	status, observed, err := pollWaitStatus(tid, ptraceStopRecoveryTime)
	if err != nil {
		return false, errors.Join(terminationErr,
			fmt.Errorf("wait for target termination: %w", err))
	}
	if !observed {
		return false, errors.Join(terminationErr,
			errors.New("target termination was not observed"))
	}
	if !status.Exited() && !status.Signaled() {
		return false, errors.Join(terminationErr,
			fmt.Errorf("unexpected target termination wait status: %v", status))
	}
	return true, terminationErr
}

func ptraceDetachWithSignal(tid int, signal unix.Signal) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_DETACH),
		uintptr(tid), 0, uintptr(signal), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (s *ptraceSession) markUnsafeToDetach(tid int) {
	if s.unsafeToDetach == nil {
		s.unsafeToDetach = make(map[int]struct{})
	}
	s.unsafeToDetach[tid] = struct{}{}
	delete(s.detachSignals, tid)
}

func (s *ptraceSession) forgetTerminatedThread(tid int) {
	for idx, attachedTID := range s.threads {
		if attachedTID == tid {
			s.threads = append(s.threads[:idx], s.threads[idx+1:]...)
			break
		}
	}
	delete(s.detachSignals, tid)
	delete(s.unsafeToDetach, tid)
	if len(s.threads) == 0 {
		s.closed = true
	}
}

func (s *ptraceSession) preserveSignalOnDetach(tid int, signal unix.Signal) {
	if signal == 0 || signal == unix.SIGSTOP {
		return
	}
	if s.detachSignals == nil {
		s.detachSignals = make(map[int][]unix.Signal)
	}
	s.detachSignals[tid] = append(s.detachSignals[tid], signal)
}

func (s *ptraceSession) requeueSignalsAfterDetach(tid int, signals []unix.Signal) error {
	var errs []error
	for _, signal := range signals {
		if err := unix.Tgkill(s.leader, tid, signal); err != nil {
			if errors.Is(err, unix.ESRCH) {
				break
			}
			errs = append(errs, fmt.Errorf("requeue target signal %s after detach: %w",
				signal, err))
		}
	}
	return errors.Join(errs...)
}

func (s *ptraceSession) detachThread(tid int) error {
	preserved := s.detachSignals[tid]
	var detachSignal unix.Signal
	var remaining []unix.Signal
	if len(preserved) > 0 {
		detachSignal = preserved[0]
		remaining = preserved[1:]
	}
	detachErr := ptraceDetachWithSignal(tid, detachSignal)
	if detachErr == nil {
		delete(s.detachSignals, tid)
		return s.requeueSignalsAfterDetach(tid, remaining)
	}
	// PTRACE_DETACH reports ESRCH when a still-live tracee is running rather
	// than ptrace-stopped. Force one bounded stop and retry instead of silently
	// leaving the target attached until the profiler exits.
	if !errors.Is(detachErr, unix.ESRCH) && !errors.Is(detachErr, unix.EBUSY) &&
		!errors.Is(detachErr, unix.EIO) {
		return detachErr
	}
	stopErr := unix.Tgkill(s.leader, tid, unix.SIGSTOP)
	if errors.Is(stopErr, unix.ESRCH) {
		delete(s.detachSignals, tid)
		return nil // The thread exited before cleanup.
	}
	if stopErr != nil {
		return errors.Join(detachErr, fmt.Errorf("stop running tracee: %w", stopErr))
	}
	status, observed, waitErr := pollWaitStatus(tid, ptraceStopRecoveryTime)
	if waitErr != nil {
		return errors.Join(detachErr, fmt.Errorf("wait for detach stop: %w", waitErr))
	}
	if !observed {
		return errors.Join(detachErr, errors.New("timed out waiting for detach stop"))
	}
	if status.Exited() || status.Signaled() {
		delete(s.detachSignals, tid)
		return nil
	}
	if !status.Stopped() {
		return errors.Join(detachErr, fmt.Errorf("unexpected detach wait status: %v", status))
	}

	// Linux only guarantees PTRACE_DETACH signal injection from a
	// signal-delivery stop. If cleanup observed its own SIGSTOP/group-stop,
	// detach with zero and requeue every preserved workload signal afterward.
	observedSignal := status.StopSignal()
	if observedSignal == unix.SIGSTOP {
		detachSignal = 0
		remaining = preserved
	} else if len(preserved) == 0 {
		detachSignal = observedSignal
	} else {
		// Deliver the oldest retained signal atomically and requeue the newer
		// signal that won the cleanup race after detach.
		detachSignal = preserved[0]
		remaining = append(remaining, observedSignal)
	}
	if err := ptraceDetachWithSignal(tid, detachSignal); err != nil {
		return errors.Join(detachErr, fmt.Errorf("detach after recovery stop: %w", err))
	}
	delete(s.detachSignals, tid)
	return s.requeueSignalsAfterDetach(tid, remaining)
}

func (s *ptraceSession) Call(fn uint64, args ...uint64) (uint64, error) {
	return s.call(fn, args, -1, nil)
}

func (s *ptraceSession) CallWithData(fn uint64, args []uint64, dataArg int, data []byte) (uint64, error) {
	return s.call(fn, args, dataArg, data)
}

func (s *ptraceSession) call(fn uint64, args []uint64, dataArg int, data []byte) (result uint64, retErr error) {
	if len(args) > 6 {
		return 0, fmt.Errorf("remote call supports at most 6 arguments, got %d", len(args))
	}
	if dataArg < -1 || (len(data) > 0 && dataArg < 0) {
		return 0, fmt.Errorf("remote data argument %d is invalid for %d data bytes",
			dataArg, len(data))
	}
	if dataArg >= len(args) {
		return 0, fmt.Errorf("remote data argument %d outside %d arguments", dataArg, len(args))
	}
	if s == nil || s.closed || len(s.threads) == 0 {
		return 0, errors.New("ptrace session is closed")
	}
	if len(s.unsafeToDetach) != 0 {
		return 0, errors.New("ptrace session has unrestored remote-call state")
	}

	tid := s.threads[0]
	var recoveryStopPending bool
	var recoveryResumeSignal int
	// Register this before the stack/register restoration defers below so it
	// runs last: consuming the recovery SIGSTOP briefly resumes the tracee.
	defer func() {
		if recoveryStopPending {
			if err := consumePendingRecoveryStop(
				s.leader, tid, recoveryResumeSignal,
			); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("consume pending recovery stop: %w", err))
			}
		}
	}()
	var saved unix.PtraceRegs
	if err := unix.PtraceGetRegs(tid, &saved); err != nil {
		return 0, fmt.Errorf("get registers: %w", err)
	}
	regs := saved

	// Return through the unmapped zero page instead of planting INT3 in the
	// interrupted instruction. Text is shared by every target thread: patching
	// it while dlopen runs can let an untraced sibling hit the breakpoint and
	// terminate the process. Ptrace observes the leader's instruction-fetch
	// SIGSEGV before target signal handling; the register checks below distinguish
	// this intentional return fault from a fault inside the remote function.
	const returnAddress uint64 = 0
	mappings, err := readProcessMappings(s.leader)
	if err != nil {
		return 0, fmt.Errorf("check remote return address: %w", err)
	}
	for _, mapping := range mappings {
		if mapping.start == returnAddress && mapping.end > returnAddress {
			return 0, errors.New("remote return address zero is mapped in target")
		}
	}
	// Enter the remote function with a synthetic SysV call frame well below the
	// interrupted stack pointer. Preserve the bytes we explicitly overwrite.
	callRSP := (saved.Rsp - 8192) &^ uint64(15)
	callRSP += 8 // SysV function entry expects RSP % 16 == 8.
	dataAddr := callRSP + 256
	spanLen := 256 + len(data)
	if spanLen < 512 {
		spanLen = 512
	}
	scratch := make([]byte, spanLen)
	if _, err := unix.PtracePeekData(tid, uintptr(callRSP), scratch); err != nil {
		return 0, fmt.Errorf("read remote stack scratch: %w", err)
	}
	restoreRequired := false
	traceeStopped := true
	defer func() {
		if !restoreRequired {
			return
		}
		if !traceeStopped {
			terminated, terminationErr := terminateUnsafeTracee(s.leader, tid,
				"remote call state could not be restored because timeout recovery did not regain a ptrace stop")
			if terminated {
				s.forgetTerminatedThread(tid)
			} else {
				s.markUnsafeToDetach(tid)
			}
			retErr = errors.Join(retErr, terminationErr)
			return
		}

		var restoreErrs []error
		if _, err := unix.PtracePokeData(tid, uintptr(callRSP), scratch); err != nil {
			restoreErrs = append(restoreErrs, fmt.Errorf("restore remote stack scratch: %w", err))
		}
		if err := unix.PtraceSetRegs(tid, &saved); err != nil {
			restoreErrs = append(restoreErrs, fmt.Errorf("restore registers: %w", err))
		}
		if restoreErr := errors.Join(restoreErrs...); restoreErr != nil {
			terminated, terminationErr := terminateUnsafeTracee(
				s.leader, tid, "remote call state restoration failed")
			if terminated {
				s.forgetTerminatedThread(tid)
			} else {
				s.markUnsafeToDetach(tid)
			}
			retErr = errors.Join(retErr, restoreErr, terminationErr)
		}
	}()

	frame := append([]byte(nil), scratch...)
	binary.LittleEndian.PutUint64(frame[:8], returnAddress)
	if len(data) > 0 {
		copy(frame[256:], data)
		args[dataArg] = dataAddr
	}
	restoreRequired = true
	if _, err := unix.PtracePokeData(tid, uintptr(callRSP), frame); err != nil {
		return 0, fmt.Errorf("write remote call frame: %w", err)
	}

	regs.Rip = fn
	regs.Rsp = callRSP
	regs.Rax = 0
	argRegs := []*uint64{&regs.Rdi, &regs.Rsi, &regs.Rdx, &regs.Rcx, &regs.R8, &regs.R9}
	for idx, value := range args {
		*argRegs[idx] = value
	}
	if err := unix.PtraceSetRegs(tid, &regs); err != nil {
		return 0, fmt.Errorf("set remote call registers: %w", err)
	}
	if err := unix.PtraceCont(tid, 0); err != nil {
		return 0, fmt.Errorf("continue remote call: %w", err)
	}
	traceeStopped = false

	status, pendingStop, err := waitForPtraceStop(s.leader, tid, remoteCallTimeout)
	traceeStopped = status.Stopped()
	recoveryStopPending = pendingStop
	if status.Stopped() && status.StopSignal() != unix.SIGSTOP &&
		!isInjectorFaultSignal(status.StopSignal()) {
		// Preserve an asynchronous target signal (for example SIGTERM). If a
		// recovery SIGSTOP remains pending, consumePendingRecoveryStop requeues
		// it after restoration. Otherwise PTRACE_DETACH must deliver the signal
		// atomically instead of silently suppressing its signal-delivery stop.
		if pendingStop {
			recoveryResumeSignal = int(status.StopSignal())
		} else {
			s.preserveSignalOnDetach(tid, status.StopSignal())
		}
	}
	if err != nil {
		return 0, err
	}
	if !status.Stopped() || status.StopSignal() != unix.SIGSEGV {
		return 0, fmt.Errorf("remote call stopped unexpectedly: %v", status)
	}
	if err := unix.PtraceGetRegs(tid, &regs); err != nil {
		return 0, fmt.Errorf("read remote return registers: %w", err)
	}
	if regs.Rip != returnAddress || regs.Rsp != callRSP+8 {
		return 0, fmt.Errorf(
			"remote function faulted before returning (rip=%#x rsp=%#x, want rip=%#x rsp=%#x)",
			regs.Rip, regs.Rsp, returnAddress, callRSP+8)
	}
	return regs.Rax, nil
}

func waitForPtraceStop(tgid, tid int, timeout time.Duration) (
	unix.WaitStatus, bool, error,
) {
	status, stopped, err := pollWaitStatus(tid, timeout)
	if err != nil {
		return 0, false, fmt.Errorf("wait for remote call: %w", err)
	}
	if stopped {
		return status, false, nil
	}

	stopErr := unix.Tgkill(tgid, tid, unix.SIGSTOP)
	recoveredStatus, recovered, recoveryErr := pollWaitStatus(tid, ptraceStopRecoveryTime)
	pendingStop := false
	if recovered {
		status = recoveredStatus
		// If another ptrace stop won the race after SIGSTOP was sent, the
		// job-control stop remains pending. call() consumes it only after the
		// target stack and registers have been restored.
		pendingStop = stopErr == nil && status.Stopped() && status.StopSignal() != unix.SIGSTOP
		// The function may have returned through the intentional null-page fault
		// just after the deadline. Let call() validate RIP/RSP and retain RAX
		// rather than reporting a completed mutation as a permanent failure.
		if potentialRemoteReturnStop(status) {
			return status, pendingStop, nil
		}
	}
	if recoveryCause := errors.Join(stopErr, recoveryErr); recoveryCause != nil {
		return status, pendingStop, fmt.Errorf(
			"remote call timed out after %s; recovery stop=%t: %w",
			timeout, recovered, recoveryCause)
	}
	return status, pendingStop, fmt.Errorf("remote call timed out after %s; recovery stop=%t",
		timeout, recovered)
}

func potentialRemoteReturnStop(status unix.WaitStatus) bool {
	return status.Stopped() && status.StopSignal() == unix.SIGSEGV
}

func isInjectorFaultSignal(signal unix.Signal) bool {
	switch signal {
	case unix.SIGSEGV, unix.SIGBUS, unix.SIGILL, unix.SIGFPE, unix.SIGTRAP, unix.SIGSYS:
		return true
	default:
		return false
	}
}

func consumePendingRecoveryStop(tgid, tid, resumeSignal int) error {
	// The tracee is currently in a different ptrace stop. Resume with signal 0
	// until the timeout-recovery SIGSTOP is observed, thereby suppressing it
	// instead of leaving an untraced process job-control-stopped after detach.
	// Requeue asynchronous signals only after SIGSTOP is consumed: injecting one
	// on PTRACE_CONT can lose it when the pending group stop wins. Registers have
	// already been restored, so preserve every additional signal observed here.
	pendingSignals := make([]unix.Signal, 0, 5)
	if resumeSignal != 0 {
		pendingSignals = append(pendingSignals, unix.Signal(resumeSignal))
	}
	rememberSignal := func(status unix.WaitStatus) {
		if status.Stopped() && status.StopSignal() != unix.SIGSTOP {
			pendingSignals = append(pendingSignals, status.StopSignal())
		}
	}
	requeueSignals := func() error {
		var errs []error
		for _, signal := range pendingSignals {
			if err := unix.Tgkill(tgid, tid, signal); err != nil {
				if errors.Is(err, unix.ESRCH) {
					// The target exited; remaining signal delivery is moot.
					break
				}
				errs = append(errs, fmt.Errorf("requeue signal %s: %w", signal, err))
			}
		}
		return errors.Join(errs...)
	}
	clearRecoveryStop := func(context string) error {
		if err := unix.Tgkill(tgid, tid, unix.SIGCONT); err != nil &&
			!errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("%s: %w", context, err)
		}
		return nil
	}

	currentlyStopped := true
	for range 4 {
		if err := unix.PtraceCont(tid, 0); err != nil {
			if errors.Is(err, unix.ESRCH) {
				return nil
			}
			return errors.Join(err,
				clearRecoveryStop("clear original recovery stop after continue error"),
				requeueSignals())
		}
		currentlyStopped = false
		status, observed, err := pollWaitStatus(tid, ptraceStopRecoveryTime)
		if err != nil {
			return errors.Join(err,
				clearRecoveryStop("clear original recovery stop after wait error"),
				requeueSignals())
		}
		if !observed {
			break
		}
		if status.Exited() || status.Signaled() {
			return nil
		}
		currentlyStopped = status.Stopped()
		if currentlyStopped && status.StopSignal() == unix.SIGSTOP {
			return requeueSignals()
		}
		rememberSignal(status)
	}

	// The bounded loop can exhaust while the original recovery SIGSTOP is still
	// pending. Cancel it before sending a fresh stop; otherwise the original can
	// win immediately and leave the fresh SIGSTOP pending after detach.
	if err := clearRecoveryStop("cancel original recovery stop before fallback"); err != nil {
		return errors.Join(err, requeueSignals())
	}
	if currentlyStopped {
		if err := unix.PtraceCont(tid, 0); err != nil {
			if errors.Is(err, unix.ESRCH) {
				return nil
			}
			return errors.Join(err, requeueSignals())
		}
	}
	if err := unix.Tgkill(tgid, tid, unix.SIGSTOP); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return errors.Join(err, requeueSignals())
	}

	// SIGCONT above is itself observable under ptrace and sorts before SIGSTOP.
	// Suppress that injector-generated stop, while retaining any workload signal
	// that also wins the race, until the fresh recovery SIGSTOP is consumed.
	for range 4 {
		status, observed, err := pollWaitStatus(tid, ptraceStopRecoveryTime)
		if err != nil {
			return errors.Join(err,
				clearRecoveryStop("clear fallback recovery stop after wait error"),
				requeueSignals())
		}
		if !observed {
			return errors.Join(
				errors.New("timed out waiting to consume fallback recovery stop"),
				clearRecoveryStop("clear unobserved fallback recovery stop"),
				requeueSignals(),
			)
		}
		if status.Exited() || status.Signaled() {
			return nil
		}
		if !status.Stopped() {
			return errors.Join(
				fmt.Errorf("unexpected fallback recovery status: %v", status),
				clearRecoveryStop("clear unexpected fallback recovery stop"),
				requeueSignals(),
			)
		}
		if status.StopSignal() == unix.SIGSTOP {
			return requeueSignals()
		}
		if status.StopSignal() != unix.SIGCONT {
			rememberSignal(status)
		}
		if err := unix.PtraceCont(tid, 0); err != nil {
			if errors.Is(err, unix.ESRCH) {
				return nil
			}
			return errors.Join(err,
				clearRecoveryStop("clear fallback recovery stop after continue error"),
				requeueSignals())
		}
	}
	return errors.Join(
		errors.New("fallback recovery stop was starved by target signals"),
		clearRecoveryStop("clear starved fallback recovery stop"),
		requeueSignals(),
	)
}

// pollWaitStatus bounds every ptrace wait. The boolean reports whether Wait4
// returned an event for tid; a timeout is not itself an error so callers can
// attempt a bounded SIGSTOP recovery.
func pollWaitStatus(tid int, timeout time.Duration) (unix.WaitStatus, bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		var status unix.WaitStatus
		waited, err := unix.Wait4(tid, &status, unix.WNOHANG, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, false, err
		}
		if waited == tid {
			return status, true, nil
		}
		if !time.Now().Before(deadline) {
			return 0, false, nil
		}
		time.Sleep(time.Millisecond)
	}
}

type processMapping struct {
	start  uint64
	end    uint64
	offset uint64
	device uint64
	inode  uint64
	path   string
}

func readProcessMappings(pid int) ([]processMapping, error) {
	contents, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	var mappings []processMapping
	for line := range strings.SplitSeq(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, startErr := strconv.ParseUint(bounds[0], 16, 64)
		end, endErr := strconv.ParseUint(bounds[1], 16, 64)
		offset, offsetErr := strconv.ParseUint(fields[2], 16, 64)
		deviceParts := strings.SplitN(fields[3], ":", 2)
		if len(deviceParts) != 2 {
			continue
		}
		deviceMajor, majorErr := strconv.ParseUint(deviceParts[0], 16, 32)
		deviceMinor, minorErr := strconv.ParseUint(deviceParts[1], 16, 32)
		inode, inodeErr := strconv.ParseUint(fields[4], 10, 64)
		if startErr != nil || endErr != nil || offsetErr != nil ||
			majorErr != nil || minorErr != nil || inodeErr != nil {
			continue
		}
		path := ""
		if len(fields) > 5 {
			path = strings.Join(fields[5:], " ")
		}
		mappings = append(mappings, processMapping{
			start: start, end: end, offset: offset,
			device: unix.Mkdev(uint32(deviceMajor), uint32(deviceMinor)), inode: inode,
			path: path,
		})
	}
	return mappings, nil
}

func isNumericVersion(version string) bool {
	if version == "" {
		return false
	}
	for _, component := range strings.Split(version, ".") {
		if component == "" {
			return false
		}
		for _, char := range component {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func isVersionedSharedObject(base, name string) bool {
	if base == name {
		return true
	}
	version, ok := strings.CutPrefix(base, name+".")
	return ok && isNumericVersion(version)
}

func isGlibcSharedObject(base, stem string) bool {
	if isVersionedSharedObject(base, stem+".so") {
		return true
	}
	versioned, ok := strings.CutPrefix(base, stem+"-")
	if !ok {
		return false
	}
	version, ok := strings.CutSuffix(versioned, ".so")
	return ok && isNumericVersion(version)
}

func isAllocatorRuntimeMapping(mapping processMapping) bool {
	base := path.Base(strings.TrimSuffix(mapping.path, " (deleted)"))
	return isGlibcSharedObject(base, "libc") || isGlibcSharedObject(base, "libdl")
}

func isExperimentalShimMapping(mapping processMapping) bool {
	// A filesystem-backed shim may be deliberately preloaded from any path.
	// Match its exact package basename and fail closed rather than risking a
	// second mutation; post-injection symbol calls additionally require the
	// exact device/inode of the memfd created by this injector.
	mappingPath := strings.TrimSuffix(mapping.path, " (deleted)")
	if mappingPath == "/memfd:prophiler-heap-shim" || mappingPath == "memfd:prophiler-heap-shim" {
		return true
	}
	base := path.Base(mappingPath)
	return base == "libprophiler-heap-shim.so" || base == "libprophiler-heap-shim-test.so"
}

func resolveProcessSymbol(pid int, name string, acceptsMapping func(processMapping) bool) (uint64, error) {
	mappings, err := readProcessMappings(pid)
	if err != nil {
		return 0, err
	}
	seen := make(map[string]struct{})
	for _, mapping := range mappings {
		if mapping.path == "" || strings.HasPrefix(mapping.path, "[") ||
			(acceptsMapping != nil && !acceptsMapping(mapping)) {
			continue
		}
		identity := fmt.Sprintf("%x-%x", mapping.start-mapping.offset, mapping.end-mapping.offset)
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}

		file, err := openMappedELF(pid, mapping)
		if err != nil {
			continue
		}
		parsed, err := elf.NewFile(file)
		if err != nil {
			_ = file.Close()
			continue
		}
		symbols, symErr := parsed.DynamicSymbols()
		if symErr != nil && !errors.Is(symErr, elf.ErrNoSymbols) {
			_ = parsed.Close()
			_ = file.Close()
			continue
		}
		if staticSymbols, staticErr := parsed.Symbols(); staticErr == nil {
			symbols = append(symbols, staticSymbols...)
		}
		for _, symbol := range symbols {
			if symbol.Name != name || symbol.Section == elf.SHN_UNDEF ||
				elf.ST_TYPE(symbol.Info) != elf.STT_FUNC {
				continue
			}
			base := mapping.start - mapping.offset
			address := symbol.Value
			if parsed.Type == elf.ET_DYN {
				address += base
			}
			_ = parsed.Close()
			_ = file.Close()
			return address, nil
		}
		_ = parsed.Close()
		_ = file.Close()
	}
	return 0, fmt.Errorf("symbol %q not found in accepted pid %d executable mappings", name, pid)
}

func openedFileMatchesMapping(file *os.File, mapping processMapping) bool {
	if file == nil {
		return false
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return false
	}
	return uint64(stat.Dev) == mapping.device && stat.Ino == mapping.inode
}

func openMappedELF(pid int, mapping processMapping) (*os.File, error) {
	mapFile := fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, mapping.start, mapping.end)
	file, mapErr := os.Open(mapFile)
	if mapErr == nil {
		if openedFileMatchesMapping(file, mapping) {
			return file, nil
		}
		_ = file.Close()
		mapErr = errors.New("map_files object identity differs from process mapping")
	}

	// map_files can require CAP_CHECKPOINT_RESTORE on newer kernels. Ordinary
	// filesystem-backed mappings remain reachable through the target root, but
	// only while that path still names the exact mapped device and inode.
	path := strings.TrimSuffix(mapping.path, " (deleted)")
	if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "/memfd:") {
		rootPath := fmt.Sprintf("/proc/%d/root%s", pid, path)
		if file, err := os.Open(rootPath); err == nil {
			if openedFileMatchesMapping(file, mapping) {
				return file, nil
			}
			_ = file.Close()
		}
	}

	// During injection only, the target fd stays open through symbol resolution,
	// allowing restricted environments to find the exact memfd by device/inode.
	// After remote close, later reconciliation requires map_files permission.
	if strings.Contains(path, "prophiler-heap-shim") {
		entries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		for _, entry := range entries {
			fdPath := fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())
			target, err := os.Readlink(fdPath)
			if err != nil || !strings.Contains(target, "prophiler-heap-shim") {
				continue
			}
			if file, err := os.Open(fdPath); err == nil {
				if openedFileMatchesMapping(file, mapping) {
					return file, nil
				}
				_ = file.Close()
			}
		}
	}
	return nil, mapErr
}

func listThreadIDs(pid int) ([]int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	tids := make([]int, 0, len(entries))
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err == nil {
			tids = append(tids, tid)
		}
	}
	sort.Ints(tids)
	if len(tids) == 0 {
		return nil, io.EOF
	}
	return tids, nil
}
