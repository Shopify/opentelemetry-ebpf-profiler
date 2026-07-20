// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package memory

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

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

const (
	remoteCallTimeout       = 5 * time.Second
	ptraceStopRecoveryTime  = time.Second
	maxThreadAttachPasses   = 16
	maxExperimentalShimSize = 16 << 20
	remoteSysMemfdCreate    = 319
	remoteSysClose          = 3
	remoteMfdCloexec        = 1
	remoteRtldNow           = 2

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
	if os.Geteuid() == 0 && stat.Uid != 0 {
		return nil, fmt.Errorf("experimental allocator shim %q must be root-owned when profiler runs as root", path)
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
	return &ptraceAllocatorInjector{
		shim: shim, mode: mode, samplingInterval: samplingInterval,
		requireFree: requireFree,
	}, nil
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
		if _, wanted := required[symbol.Name]; wanted && symbol.Section != elf.SHN_UNDEF {
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

func (i *ptraceAllocatorInjector) Inject(pid libpf.PID) (result InjectionResult, retErr error) {
	// Linux records ptrace ownership at thread granularity. Keep every attach,
	// wait, register operation, and detach on one tracer thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	leader := int(pid)
	mappings, err := readProcessMappings(leader)
	if err != nil {
		return result, fmt.Errorf("read target mappings before injection: %w", err)
	}
	for _, mapping := range mappings {
		if strings.Contains(mapping.path, "prophiler-heap-shim") {
			result.AlreadyPresent = true
			return result, nil
		}
	}

	syscallAddr, err := resolveProcessSymbol(leader, "syscall", isAllocatorRuntimeMapping)
	if err != nil {
		return result, fmt.Errorf("resolve libc syscall: %w", err)
	}
	dlopenAddr, err := resolveProcessSymbol(leader, "dlopen", isAllocatorRuntimeMapping)
	if err != nil {
		return result, fmt.Errorf("resolve dlopen: %w", err)
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

	fdValue, err := session.CallWithData(syscallAddr,
		[]uint64{remoteSysMemfdCreate, 0, remoteMfdCloexec}, 1,
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
	_, copyErr := remoteFile.Write(i.shim)
	closeErr := remoteFile.Close()
	if copyErr != nil || closeErr != nil {
		return result, fmt.Errorf("populate target memfd: %w", errors.Join(copyErr, closeErr))
	}

	fdOpen := true
	defer func() {
		if fdOpen && session != nil && !session.closed {
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
		leader, "prophiler_heap_set_sampling_interval", isExperimentalShimMapping)
	if err != nil {
		return result, fmt.Errorf("resolve injected sampling configuration: %w", err)
	}
	if _, err := session.Call(setSamplingInterval, i.samplingInterval); err != nil {
		return result, fmt.Errorf("configure injected sampling interval: %w", err)
	}

	installGOT, err := resolveProcessSymbol(
		leader, "prophiler_heap_install_got", isExperimentalShimMapping)
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
			leader, "prophiler_heap_install_inline", isExperimentalShimMapping)
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
	leader  int
	threads []int
	closed  bool
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
	status, stopped, err := pollWaitStatus(tid, remoteCallTimeout)
	if err != nil {
		return fmt.Errorf("wait for ptrace stop tid %d: %w", tid, err)
	}
	if !stopped {
		// PTRACE_ATTACH normally supplies SIGSTOP. Retry explicitly but never
		// follow a timed wait with an unbounded Wait4.
		_ = unix.Tgkill(s.leader, tid, unix.SIGSTOP)
		status, stopped, err = pollWaitStatus(tid, ptraceStopRecoveryTime)
		if err != nil {
			return fmt.Errorf("recover ptrace stop tid %d: %w", tid, err)
		}
	}
	if !stopped {
		return fmt.Errorf("timed out waiting for ptrace stop tid %d", tid)
	}
	if !status.Stopped() {
		return fmt.Errorf("tid %d did not enter ptrace stop: %v", tid, status)
	}
	return nil
}

func (s *ptraceSession) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	for n := len(s.threads) - 1; n >= 0; n-- {
		if err := unix.PtraceDetach(s.threads[n]); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("ptrace detach tid %d: %w", s.threads[n], err))
		}
	}
	return errors.Join(errs...)
}

func (s *ptraceSession) Call(fn uint64, args ...uint64) (uint64, error) {
	return s.call(fn, args, -1, nil)
}

func (s *ptraceSession) CallWithData(fn uint64, args []uint64, dataArg int, data []byte) (uint64, error) {
	return s.call(fn, args, dataArg, data)
}

func (s *ptraceSession) call(fn uint64, args []uint64, dataArg int, data []byte) (result uint64, retErr error) {
	if s == nil || s.closed || len(s.threads) == 0 {
		return 0, errors.New("ptrace session is closed")
	}
	if len(args) > 6 {
		return 0, fmt.Errorf("remote call supports at most 6 arguments, got %d", len(args))
	}
	if dataArg >= len(args) {
		return 0, fmt.Errorf("remote data argument %d outside %d arguments", dataArg, len(args))
	}

	tid := s.threads[0]
	var saved unix.PtraceRegs
	if err := unix.PtraceGetRegs(tid, &saved); err != nil {
		return 0, fmt.Errorf("get registers: %w", err)
	}
	regs := saved

	trapAddress := saved.Rip &^ uint64(7)
	trapOffset := int(saved.Rip - trapAddress)
	trap := make([]byte, 8)
	if _, err := unix.PtracePeekData(tid, uintptr(trapAddress), trap); err != nil {
		return 0, fmt.Errorf("read return trap instruction at %#x (rip=%#x): %w",
			trapAddress, saved.Rip, err)
	}
	patchedTrap := append([]byte(nil), trap...)
	patchedTrap[trapOffset] = 0xcc
	if _, err := unix.PtracePokeData(tid, uintptr(trapAddress), patchedTrap); err != nil {
		return 0, fmt.Errorf("install return trap: %w", err)
	}
	defer func() {
		if _, err := unix.PtracePokeData(tid, uintptr(trapAddress), trap); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("restore return trap instruction: %w", err))
		}
		if err := unix.PtraceSetRegs(tid, &saved); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("restore registers: %w", err))
		}
	}()

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
	defer func() {
		if _, err := unix.PtracePokeData(tid, uintptr(callRSP), scratch); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("restore remote stack scratch: %w", err))
		}
	}()

	frame := append([]byte(nil), scratch...)
	binary.LittleEndian.PutUint64(frame[:8], saved.Rip)
	if len(data) > 0 {
		copy(frame[256:], data)
		args[dataArg] = dataAddr
	}
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

	status, err := waitForPtraceStop(s.leader, tid, remoteCallTimeout)
	if err != nil {
		return 0, err
	}
	if !status.Stopped() || status.StopSignal() != unix.SIGTRAP {
		return 0, fmt.Errorf("remote call stopped unexpectedly: %v", status)
	}
	if err := unix.PtraceGetRegs(tid, &regs); err != nil {
		return 0, fmt.Errorf("read remote return registers: %w", err)
	}
	return regs.Rax, nil
}

func waitForPtraceStop(tgid, tid int, timeout time.Duration) (unix.WaitStatus, error) {
	status, stopped, err := pollWaitStatus(tid, timeout)
	if err != nil {
		return 0, fmt.Errorf("wait for remote call: %w", err)
	}
	if stopped {
		return status, nil
	}

	stopErr := unix.Tgkill(tgid, tid, unix.SIGSTOP)
	recoveredStatus, recovered, recoveryErr := pollWaitStatus(tid, ptraceStopRecoveryTime)
	if recovered {
		status = recoveredStatus
	}
	if recoveryCause := errors.Join(stopErr, recoveryErr); recoveryCause != nil {
		return status, fmt.Errorf(
			"remote call timed out after %s; recovery stop=%t: %w",
			timeout, recovered, recoveryCause)
	}
	return status, fmt.Errorf("remote call timed out after %s; recovery stop=%t",
		timeout, recovered)
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
		if startErr != nil || endErr != nil || offsetErr != nil {
			continue
		}
		path := ""
		if len(fields) > 5 {
			path = strings.Join(fields[5:], " ")
		}
		mappings = append(mappings, processMapping{start: start, end: end, offset: offset, path: path})
	}
	return mappings, nil
}

func isAllocatorRuntimeMapping(mappingPath string) bool {
	base := path.Base(strings.TrimSuffix(mappingPath, " (deleted)"))
	return base == "libc.so" || strings.HasPrefix(base, "libc.so.") ||
		base == "libdl.so" || strings.HasPrefix(base, "libdl.so.")
}

func isExperimentalShimMapping(mappingPath string) bool {
	return strings.Contains(mappingPath, "prophiler-heap-shim")
}

func resolveProcessSymbol(pid int, name string, acceptsMapping func(string) bool) (uint64, error) {
	mappings, err := readProcessMappings(pid)
	if err != nil {
		return 0, err
	}
	seen := make(map[string]struct{})
	for _, mapping := range mappings {
		if mapping.path == "" || strings.HasPrefix(mapping.path, "[") ||
			(acceptsMapping != nil && !acceptsMapping(mapping.path)) {
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
			if symbol.Name != name || symbol.Section == elf.SHN_UNDEF {
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

func openMappedELF(pid int, mapping processMapping) (*os.File, error) {
	mapFile := fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, mapping.start, mapping.end)
	file, mapErr := os.Open(mapFile)
	if mapErr == nil {
		return file, nil
	}

	// map_files can require CAP_CHECKPOINT_RESTORE on newer kernels. Ordinary
	// filesystem-backed mappings remain reachable through the target root.
	path := strings.TrimSuffix(mapping.path, " (deleted)")
	if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "/memfd:") {
		rootPath := fmt.Sprintf("/proc/%d/root%s", pid, path)
		if file, err := os.Open(rootPath); err == nil {
			return file, nil
		}
	}

	// Keep the injected memfd open through symbol resolution so environments
	// lacking map_files permission can still parse the exact backing object.
	if strings.Contains(path, "prophiler-heap-shim") {
		entries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		for _, entry := range entries {
			fdPath := fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())
			target, err := os.Readlink(fdPath)
			if err != nil || !strings.Contains(target, "prophiler-heap-shim") {
				continue
			}
			if file, err := os.Open(fdPath); err == nil {
				return file, nil
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
