// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
	"golang.org/x/sys/unix"
)

// Records all the "global" pointers we've seen.
type vmMap map[libpf.Address]struct{}

// Records all the JIT regions we've seen, value is SynchronizeMappings
// generation.
type regionMap map[process.RawMapping]int

type regionKey struct {
	start, end uint64
}

const (
	// Prefer dropping exact LuaJIT trace overlays for a VM over exhausting the
	// shared pid_page_to_mapping_info map and starving the whole node of profiles.
	luajitTracePrefixBudgetPerVM         = 1 << 17 // 131072
	luajitTracePrefixBudgetPerPID        = 1 << 18 // 262144
	pidPageToMappingInfoSoftLimitPercent = 50
)

type luajitData struct {
	// The distance from the "g" pointer in the GG_State struct to the start of the dispatch table.
	g2Dispatch uint16
	// The distance from the "g" pointer in the GG_State struct to the start of the trace array
	// in the jit_State struct.
	g2Traces uint16
	// Offset of cur_L field in the global_State struct.
	currentLOffset uint16
}

type luajitInstance struct {
	rm         remotememory.RemoteMemory
	protos     map[libpf.Address]*proto
	jitRegions regionMap
	pid        libpf.PID
	ebpf       interpreter.EbpfHandler
	// Map of g's we've seen, populated by the symbolizer goroutine and
	// consumed in SynchronizeMappings so needs to be protected by a mutex.
	mu  sync.Mutex
	vms vmMap

	// Currently mapped prefixes for each vms traces
	prefixesByG map[libpf.Address][]lpm.Prefix

	// Currently mapped prefixes for entire memory regions
	prefixes map[regionKey][]lpm.Prefix

	// Hash of the traces for each vm
	traceHashes map[libpf.Address]uint64
	cycle       int

	g2Traces uint16
}

var (
	_ interpreter.Data     = &luajitData{}
	_ interpreter.Instance = &luajitInstance{}
)

func (d *luajitData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	cdata := support.LuaJITProcInfo{
		G2dispatch:      d.g2Dispatch,
		Cur_L_offset:    d.currentLOffset,
		Cframe_size_jit: uint16(cframeSizeJIT),
	}
	if err := ebpf.UpdateProcData(libpf.LuaJIT, pid, unsafe.Pointer(&cdata)); err != nil {
		return nil, err
	}

	return &luajitInstance{rm: rm,
		pid:         pid,
		ebpf:        ebpf,
		protos:      make(map[libpf.Address]*proto),
		jitRegions:  make(regionMap),
		prefixes:    make(map[regionKey][]lpm.Prefix),
		prefixesByG: make(map[libpf.Address][]lpm.Prefix),
		vms:         make(vmMap),
		traceHashes: make(map[libpf.Address]uint64),
		g2Traces:    d.g2Traces,
	}, nil
}

func (d *luajitData) Unload(_ interpreter.EbpfHandler) {}

func (l *luajitInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	// Clear memory ranges
	for _, prefixes := range l.prefixes {
		for _, prefix := range prefixes {
			_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		}
	}
	// Clear trace ranges
	for _, prefixes := range l.prefixesByG {
		for _, prefix := range prefixes {
			_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		}
	}
	return ebpf.DeleteProcData(libpf.LuaJIT, pid)
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	base := path.Base(info.FileName())
	if !strings.HasPrefix(base, "libluajit-5.1.so") &&
		base != "luajit" && base != "nginx" && base != "openresty" {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	luaInterp, err := extractInterpreterBounds(info.Deltas(), cframeSize)
	if err != nil {
		return nil, err
	}
	logf("lj: interp range %v", luaInterp)

	ljd := &luajitData{}

	if err = extractOffsets(ef, ljd, luaInterp); err != nil {
		return nil, err
	}

	logf("lj: offsets %+v", ljd)

	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindLuaJIT, info.FileID(),
		[]util.Range{luaInterp}); err != nil {
		return nil, err
	}

	return ljd, nil
}

// LuaJIT's interpreter isn't a function, its a raw chunk of assembly code with direct threaded
// jumps at end of each opcode. The public entrypoints (lua_pcall/lua_resume) call the lj_vm_pcall
// function at the end of this blob which set up the interpreter and starts executing.
// Even though its not a normal function an eh_frame entry is created for it, its really
// big and has a somewhat unique FDE we can pick out. We could tighten this up by looking for
// direct jumps to the start of the interpreter (one can be found lj_dispatch_update) but we'd
// still need to consult the stack deltas to get the end of the interpreter.
func extractInterpreterBounds(deltas sdtypes.StackDeltaArray, param int32) (util.Range,
	error) {
	for i := 0; i < len(deltas)-1; i++ {
		d, next := &deltas[i], &deltas[i+1]
		if next.Address-d.Address > 10_000 {
			// The first case covers x86 w/ dwarf and old versions of luajit ARM that used dwarf and
			// the second covers more recent arm versions that use frame pointers.
			if d.Info.BaseReg == support.UnwindRegSp && d.Info.Param == param ||
				d.Info.BaseReg == support.UnwindRegFp && d.Info.Param == 16 {
				return util.Range{Start: d.Address, End: next.Address}, nil
			}
		}
	}

	return util.Range{}, errors.New("failed to find interpreter range")
}

func (l *luajitInstance) getVMList() []libpf.Address {
	l.mu.Lock()
	defer l.mu.Unlock()
	gs := make([]libpf.Address, 0, len(l.vms))
	for g := range l.vms {
		gs = append(gs, g)
	}
	return gs
}

func rollbackPrefixes(ebpf interpreter.EbpfHandler, pid libpf.PID, prefixes []lpm.Prefix) {
	for _, prefix := range prefixes {
		_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
	}
}

func formatPidPageToMappingInfoStats(stats interpreter.PidPageToMappingInfoStats) string {
	return fmt.Sprintf("approx_entries=%d approx_entries_for_pid=%d max_entries=%d",
		stats.ApproxEntries, stats.ApproxEntriesForPID, stats.MaxEntries)
}

func pidPageToMappingInfoSoftLimit(stats interpreter.PidPageToMappingInfoStats) uint64 {
	if stats.MaxEntries == 0 {
		return 0
	}
	return uint64(stats.MaxEntries) * pidPageToMappingInfoSoftLimitPercent / 100
}

func (l *luajitInstance) clearTraceMappings(ebpf interpreter.EbpfHandler, pid libpf.PID,
	g libpf.Address) {
	rollbackPrefixes(ebpf, pid, l.prefixesByG[g])
	delete(l.prefixesByG, g)
	delete(l.traceHashes, g)
}

func (l *luajitInstance) addJITRegion(ebpf interpreter.EbpfHandler, pid libpf.PID,
	start, end uint64) error {
	prefixes, err := lpm.CalculatePrefixList(start, end)
	if err != nil {
		logf("lj: failed to calculate lpm: %v", err)
		return err
	}
	logf("lj: add JIT region pid(%v) %#x:%#x", pid, start, end)
	inserted := make([]lpm.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		// TODO: fix these: WARN[0267] Failed to lookup file ID 0x2a00000000
		fileID := support.LJFileId << 32
		if err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindLuaJIT,
			host.FileID(fileID), 0); err != nil {
			rollbackPrefixes(ebpf, pid, inserted)
			return err
		}
		inserted = append(inserted, prefix)
	}
	k := regionKey{start: start, end: end}
	l.prefixes[k] = inserted
	return nil
}

func traceMappingPrefixes(t trace) ([]lpm.Prefix, error) {
	start, end := t.mcode, t.mcode+uint64(t.szmcode)
	prefixes, err := lpm.CalculatePrefixList(start, end)
	if err != nil {
		logf("lj: failed to calculate lpm: %v", err)
		return nil, err
	}
	return prefixes, nil
}

func (l *luajitInstance) mapTracePrefixes(ebpf interpreter.EbpfHandler, pid libpf.PID,
	prefixes []lpm.Prefix, g, spadjust uint64) ([]lpm.Prefix, error) {
	inserted := make([]lpm.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		fileID := support.LJFileId<<32 | spadjust
		if err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindLuaJIT,
			host.FileID(fileID), g); err != nil {
			rollbackPrefixes(ebpf, pid, inserted)
			return nil, err
		}
		inserted = append(inserted, prefix)
	}
	return inserted, nil
}

func (l *luajitInstance) addTrace(ebpf interpreter.EbpfHandler, pid libpf.PID, t trace, g,
	spadjust uint64) ([]lpm.Prefix, error) {
	prefixes, err := traceMappingPrefixes(t)
	if err != nil {
		return nil, err
	}
	logf("lj: add trace mapping for pid(%v) %x:%x", pid, t.mcode, t.mcode+uint64(t.szmcode))
	return l.mapTracePrefixes(ebpf, pid, prefixes, g, spadjust)
}

func (l *luajitInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler,
	_ reporter.ExecutableReporter, pr process.Process, mappings []process.RawMapping) error {
	return l.synchronizeMappings(ebpf, pr.PID(), mappings)
}

func (l *luajitInstance) synchronizeMappings(ebpf interpreter.EbpfHandler, pid libpf.PID,
	mappings []process.RawMapping) error {
	cycle := l.cycle
	l.cycle++
	for i := range mappings {
		m := &mappings[i]
		if !m.IsAnonymous() || !m.IsExecutable() {
			continue
		}
		l.jitRegions[*m] = cycle
	}

	// Remove old ones
	for m, c := range l.jitRegions {
		k := regionKey{start: m.Vaddr, end: m.Vaddr + m.Length}
		if c != cycle {
			for _, prefix := range l.prefixes[k] {
				if err := ebpf.DeletePidInterpreterMapping(pid, prefix); err != nil {
					return errors.Join(err, fmt.Errorf("failed to delete prefix %v", prefix))
				}
			}
			delete(l.jitRegions, m)
			delete(l.prefixes, k)
		}
	}

	// Add new ones
	for m := range l.jitRegions {
		k := regionKey{start: m.Vaddr, end: m.Vaddr + m.Length}
		if _, ok := l.prefixes[k]; !ok {
			if err := l.addJITRegion(ebpf, pid, m.Vaddr, m.Vaddr+m.Length); err != nil {
				return errors.Join(err, fmt.Errorf("failed to add JIT region %v", m))
			}
		}
	}

	return l.processVMs(ebpf, pid)
}

func (l *luajitInstance) processVMs(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	var badVMs []libpf.Address
	for _, g := range l.getVMList() {
		hash, traces, err := loadTraces(g+libpf.Address(l.g2Traces), l.rm)
		if err != nil {
			// if g is bad remove it
			log.Warnf("LuaJIT instance (%v) deleted: %v", g, err)
			badVMs = append(badVMs, g)
			continue
		}
		// Don't do anything if nothing changed.
		if hash == l.traceHashes[g] {
			continue
		}

		// We don't bother trying to keep things in sync, just delete them all and re-add them.
		removedPrefixes := len(l.prefixesByG[g])
		l.clearTraceMappings(ebpf, pid, g)

		baseStats := ebpf.GetPidPageToMappingInfoStats(pid)
		softLimit := pidPageToMappingInfoSoftLimit(baseStats)

		newPrefixes := []lpm.Prefix{}
		seenPrefixes := make(map[lpm.Prefix]struct{})
		duplicatePrefixes := 0
		invalidTraces := 0
		otherAddErrors := 0
		keyExistsErrors := 0
		noSpaceErrors := 0
		mappedTraces := 0
		fallbackReason := ""
		fallbackTrace := uint16(0)
		var firstAddErr error

	traceLoop:
		for i := range traces {
			t := traces[i]
			// Validate the trace
			foundRegion := false
			for reg := range l.jitRegions {
				if t.mcode >= reg.Vaddr && t.mcode < reg.Vaddr+reg.Length {
					foundRegion = true
					end := t.mcode + uint64(t.szmcode)
					if end > reg.Vaddr+reg.Length {
						log.Errorf("trace %v end goes beyond JIT region, bad szmcode", t)
						invalidTraces++
						continue traceLoop
					}
					break
				}
			}

			if !foundRegion {
				log.Errorf("trace %v not in a JIT region", t)
				invalidTraces++
				continue
			}

			prefixes, err := traceMappingPrefixes(t)
			if err != nil {
				otherAddErrors++
				if firstAddErr == nil {
					firstAddErr = fmt.Errorf("trace(%d): %w", t.traceno, err)
				}
				continue
			}

			uniqueTracePrefixes := make([]lpm.Prefix, 0, len(prefixes))
			for _, prefix := range prefixes {
				if _, ok := seenPrefixes[prefix]; ok {
					duplicatePrefixes++
					continue
				}
				prospectiveVMEntries := uint64(len(newPrefixes) + len(uniqueTracePrefixes) + 1)
				prospectivePIDEntries := baseStats.ApproxEntriesForPID + prospectiveVMEntries
				prospectiveTotalEntries := baseStats.ApproxEntries + prospectiveVMEntries
				switch {
				case prospectiveVMEntries > luajitTracePrefixBudgetPerVM:
					fallbackReason = fmt.Sprintf("exact LuaJIT trace prefix budget per VM exceeded (%d > %d)",
						prospectiveVMEntries, luajitTracePrefixBudgetPerVM)
				case prospectivePIDEntries > luajitTracePrefixBudgetPerPID:
					fallbackReason = fmt.Sprintf("exact LuaJIT trace prefix budget per PID exceeded (%d > %d)",
						prospectivePIDEntries, luajitTracePrefixBudgetPerPID)
				case softLimit > 0 && prospectiveTotalEntries > softLimit:
					fallbackReason = fmt.Sprintf("pid_page_to_mapping_info soft limit exceeded (%d > %d)",
						prospectiveTotalEntries, softLimit)
				}
				if fallbackReason != "" {
					fallbackTrace = t.traceno
					break
				}
				uniqueTracePrefixes = append(uniqueTracePrefixes, prefix)
			}
			if fallbackReason != "" {
				rollbackPrefixes(ebpf, pid, newPrefixes)
				newPrefixes = nil
				break
			}

			stackDelta := uint64(t.spadjust) + uint64(cframeSizeJIT)
			// If this is a side trace, we need to add the spadjust of the root trace but
			// only if they are different.
			//https://github.com/openresty/luajit2/blob/7952882d/src/lj_gdbjit.c#L597
			if t.root != 0 && traces[t.root].spadjust != t.spadjust {
				stackDelta += uint64(traces[t.root].spadjust) + uint64(cframeSizeJIT)
			}
			inserted, err := l.mapTracePrefixes(ebpf, pid, uniqueTracePrefixes, uint64(g), stackDelta)
			if err != nil {
				switch {
				case errors.Is(err, unix.ENOSPC):
					noSpaceErrors++
					fallbackReason = fmt.Sprintf("map full while adding trace(%d): %v", t.traceno, err)
					fallbackTrace = t.traceno
					rollbackPrefixes(ebpf, pid, newPrefixes)
					newPrefixes = nil
					break traceLoop
				case errors.Is(err, unix.EEXIST):
					keyExistsErrors++
				default:
					otherAddErrors++
					if firstAddErr == nil {
						firstAddErr = fmt.Errorf("trace(%d): %w", t.traceno, err)
					}
				}
				continue
			}
			for _, prefix := range inserted {
				seenPrefixes[prefix] = struct{}{}
			}
			newPrefixes = append(newPrefixes, inserted...)
			mappedTraces++
		}

		stats := ebpf.GetPidPageToMappingInfoStats(pid)
		if fallbackReason != "" {
			log.Warnf("LuaJIT exact trace mappings skipped for pid(%v) g(%v): traces=%d mapped=%d unique_prefixes=%d duplicate_prefixes=%d invalid_traces=%d removed_prefixes=%d fallback_trace=%d reason=%s (%s)",
				pid, g, len(traces), mappedTraces, len(newPrefixes), duplicatePrefixes,
				invalidTraces, removedPrefixes, fallbackTrace, fallbackReason,
				formatPidPageToMappingInfoStats(stats))
			l.traceHashes[g] = hash
			continue
		}

		if keyExistsErrors > 0 || noSpaceErrors > 0 || otherAddErrors > 0 {
			log.Warnf("LuaJIT traces for pid(%v) g(%v) added: %d mapped=%d unique_prefixes=%d duplicate_prefixes=%d invalid_traces=%d removed_prefixes=%d key_exists=%d no_space=%d other_errors=%d first_error=%v (%s)",
				pid, g, len(traces), mappedTraces, len(newPrefixes), duplicatePrefixes,
				invalidTraces, removedPrefixes, keyExistsErrors, noSpaceErrors,
				otherAddErrors, firstAddErr, formatPidPageToMappingInfoStats(stats))
		} else {
			log.Infof("LuaJIT traces for pid(%v) g(%v) added: %d mapped=%d with %d unique prefixes (%d duplicate prefixes skipped) and removed %d prefixes (%s)",
				pid, g, len(traces), mappedTraces, len(newPrefixes), duplicatePrefixes,
				removedPrefixes, formatPidPageToMappingInfoStats(stats))
		}

		l.prefixesByG[g] = newPrefixes
		if otherAddErrors == 0 {
			l.traceHashes[g] = hash
		}
	}
	l.removeVMs(ebpf, pid, badVMs)
	return nil
}

func (l *luajitInstance) removeVMs(ebpf interpreter.EbpfHandler, pid libpf.PID, gs []libpf.Address) {
	for _, g := range gs {
		l.clearTraceMappings(ebpf, pid, g)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, g := range gs {
		delete(l.vms, g)
	}
}

func (l *luajitInstance) getGCproto(pt libpf.Address) (*proto, error) {
	if pt == 0 {
		return nil, nil
	}
	if gc, ok := l.protos[pt]; ok {
		return gc, nil
	}
	gc, err := newProto(l.rm, pt)
	if err != nil {
		return nil, err
	}
	l.protos[pt] = gc
	return gc, nil
}

// symbolizeFrame symbolizes the previous (up the stack)
func (l *luajitInstance) symbolizeFrame(funcName string, ptAddr libpf.Address,
	pc uint32, frames *libpf.Frames) error {
	pt, err := l.getGCproto(ptAddr)
	if err != nil {
		return err
	}
	line := pt.getLine(pc)
	fileName := pt.getName()
	logf("lj: [%x] %v+%v at %v:%v", ptAddr, funcName, pc, fileName, line)
	frames.Append(&libpf.Frame{
		Type:           libpf.LuaJITFrame,
		FunctionOffset: pc,
		FunctionName:   libpf.Intern(funcName),
		SourceFile:     libpf.Intern(fileName),
		SourceLine:     libpf.SourceLineno(line),
	})
	return nil
}

func (l *luajitInstance) addVM(g libpf.Address) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.vms[g]
	if !ok {
		l.vms[g] = struct{}{}
	}
	return !ok
}

func (l *luajitInstance) Symbolize(frame libpf.EbpfFrame, frames *libpf.Frames, fm libpf.FrameMapping) error {
	if !frame.Type().IsInterpType(libpf.LuaJIT) {
		return interpreter.ErrMismatchInterpreterType
	}

	var funcName string
	ljkind := frame.Data()
	switch ljkind {
	case support.LJNormalFrame:
		if frame.NumVariables() < 3 {
			return errors.New("LuaJIT normal frame not large enough")
		}
		callerPT := libpf.Address(frame.Variable(1))

		pt, err := l.getGCproto(callerPT)
		if err != nil {
			return err
		}

		var2 := frame.Variable(2)
		callerPC := uint32(var2 & 0xFFFFFFFF)
		calleePC := uint32(var2 >> 32)
		funcName = pt.getFunctionName(callerPC)
		calleePT := libpf.Address(frame.Variable(0))
		if err := l.symbolizeFrame(funcName, calleePT,
			calleePC, frames); err != nil {
			return err
		}

		return nil
	case support.LJFFIFunc:
		if frame.NumVariables() < 1 {
			return errors.New("LuaJIT FFI frame not large enough")
		}
		funcId := libpf.Address(frame.Variable(0)) & 7
		switch funcId {
		case 0:
			funcName = "lua-frame"
		case 1:
			funcName = "c-frame"
		case 2:
			funcName = "cont-frame"
		case 3:
			return errors.New("unexpected frame type 3")
		case 4:
			funcName = "lua-pframe"
		case 5:
			funcName = "cpcall"
		case 6:
			funcName = "ff-pcall"
		case 7:
			funcName = "ff-pcall-hook"
		}
		frames.Append(&libpf.Frame{
			Type:         libpf.LuaJITFrame,
			FunctionName: libpf.Intern(funcName),
		})
		return nil
	case support.LJGReport:
		if frame.NumVariables() < 1 {
			return errors.New("LuaJIT G report frame not large enough")
		}
		g := libpf.Address(frame.Variable(0))
		if g != 0 {
			unseen := l.addVM(g)
			if unseen {
				log.Infof("New LuaJIT instance detected: %v", g)
				if l.ebpf.CoredumpTest() {
					return interpreter.ErrLJRestart
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("Unrecognized LuaJIT frame kind: %d", ljkind)
	}

	return nil
}

func (l *luajitInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	return nil, nil
}

func (l *luajitInstance) ReleaseResources() error {
	return nil
}

func (l *luajitInstance) UpdateLibcInfo(ebpf interpreter.EbpfHandler, pid libpf.PID, info libc.LibcInfo) error {
	return nil
}
