// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usertarget // import "go.opentelemetry.io/ebpf-profiler/probes/usertarget"

import (
	"debug/elf"
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type resolvedPoint struct {
	fileOffset uint64
	source     string
}

func executableFileOffset(file *pfelf.File, virtualAddress uint64) (uint64, bool) {
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 {
			continue
		}
		if virtualAddress < program.Vaddr {
			continue
		}
		delta := virtualAddress - program.Vaddr
		if delta >= program.Filesz || delta > ^uint64(0)-program.Off {
			continue
		}
		return program.Off + delta, true
	}
	return 0, false
}

func executableOffset(file *pfelf.File, fileOffset uint64) bool {
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 {
			continue
		}
		if fileOffset >= program.Off && fileOffset-program.Off < program.Filesz {
			return true
		}
	}
	return false
}

func findSymbols(file *pfelf.File, candidates []string) (map[string]libpf.Symbol, error) {
	wanted := make(map[libpf.SymbolName]string, len(candidates))
	for _, candidate := range candidates {
		wanted[libpf.SymbolName(candidate)] = candidate
	}
	found := make(map[string]libpf.Symbol, len(candidates))
	visit := func(symbol libpf.Symbol) bool {
		candidate, ok := wanted[symbol.Name]
		if !ok || symbol.Address == 0 {
			return true
		}
		if _, executable := executableFileOffset(file, uint64(symbol.Address)); !executable {
			return true
		}
		found[candidate] = symbol
		return len(found) < len(wanted)
	}
	for _, visitTable := range []func(func(libpf.Symbol) bool) error{
		file.VisitSymbols,
		file.VisitDynamicSymbols,
	} {
		if len(found) == len(wanted) {
			break
		}
		if err := visitTable(visit); err != nil && !errors.Is(err, pfelf.ErrSectionNotPresent) {
			return nil, err
		}
	}
	return found, nil
}

func resolvePoints(file *pfelf.File, target Target) ([]resolvedPoint, string, error) {
	if file.Machine != pfelf.CurrentMachine {
		return nil, "", fmt.Errorf("ELF machine %s does not match profiler machine %s",
			file.Machine, pfelf.CurrentMachine)
	}

	needBuildID := target.Object.BuildID != "" || len(target.Offsets) > 0
	buildID := ""
	if needBuildID {
		var err error
		buildID, err = file.GetBuildID()
		if err == nil {
			buildID, err = normalizeBuildID(buildID)
		}
		if err != nil && (target.Object.BuildID != "" || len(target.SymbolCandidates) == 0) {
			return nil, "", fmt.Errorf("read ELF build ID: %w", err)
		}
		if target.Object.BuildID != "" && buildID != target.Object.BuildID {
			return nil, buildID, fmt.Errorf("%w: ELF build ID %q does not match %q",
				errObjectMismatch, buildID, target.Object.BuildID)
		}
	}

	byOffset := make(map[uint64]resolvedPoint,
		len(target.SymbolCandidates)+len(target.Offsets))
	symbols, err := findSymbols(file, target.SymbolCandidates)
	if err != nil {
		return nil, buildID, fmt.Errorf("read ELF symbols: %w", err)
	}
	for _, candidate := range target.SymbolCandidates {
		symbol, ok := symbols[candidate]
		if !ok {
			continue
		}
		fileOffset, ok := executableFileOffset(file, uint64(symbol.Address))
		// cilium/ebpf reserves Address == 0 for symbol lookup. We attach
		// resolved points with an empty symbol, so offset zero is unusable.
		if !ok || fileOffset == 0 {
			continue
		}
		if _, exists := byOffset[fileOffset]; !exists {
			byOffset[fileOffset] = resolvedPoint{fileOffset: fileOffset, source: candidate}
		}
	}
	for _, configured := range target.Offsets {
		if configured.BuildID != buildID {
			continue
		}
		if !executableOffset(file, configured.FileOffset) {
			return nil, buildID, fmt.Errorf("configured offset %#x is not executable",
				configured.FileOffset)
		}
		if _, exists := byOffset[configured.FileOffset]; !exists {
			byOffset[configured.FileOffset] = resolvedPoint{
				fileOffset: configured.FileOffset,
				source:     fmt.Sprintf("build_id:%s", configured.BuildID),
			}
		}
	}
	if len(byOffset) == 0 {
		if len(target.SymbolCandidates) == 0 && len(target.Offsets) > 0 {
			return nil, buildID, fmt.Errorf("%w: no offset configured for build ID %q",
				errObjectMismatch, buildID)
		}
		return nil, buildID, errors.New("no configured symbol or offset resolved")
	}

	points := make([]resolvedPoint, 0, len(byOffset))
	for _, point := range byOffset {
		points = append(points, point)
	}
	slices.SortFunc(points, func(left, right resolvedPoint) int {
		if left.fileOffset < right.fileOffset {
			return -1
		}
		if left.fileOffset > right.fileOffset {
			return 1
		}
		return 0
	})
	return points, buildID, nil
}

type fdReader interface {
	Fd() uintptr
}

// withResolvedMapping opens the exact mapped inode (map_files first, then a
// namespace-root path verified by device/inode), resolves symbols, and keeps
// the descriptor alive until all links have been attached.
func withResolvedMapping(event tracer.ProcessEvent, mapping process.RawMapping,
	target Target, callback func(*link.Executable, []resolvedPoint, string) error,
) error {
	tid := event.TID
	if tid == 0 {
		tid = event.PID
	}
	proc := process.New(event.PID, tid)
	defer proc.Close()

	mappingFile, err := proc.OpenMappingFile(&mapping)
	if err != nil {
		return fmt.Errorf("open mapped object %q: %w", mapping.Path, err)
	}
	defer mappingFile.Close()

	fd, ok := mappingFile.(fdReader)
	if !ok {
		return errors.New("mapped object does not expose a file descriptor")
	}
	file, err := pfelf.NewFile(mappingFile, 0, false)
	if err != nil {
		return fmt.Errorf("parse mapped ELF %q: %w", mapping.Path, err)
	}
	defer file.Close()

	points, buildID, err := resolvePoints(file, target)
	if err != nil {
		return err
	}

	// /proc/self/fd keeps container and deleted-file resolution tied to the
	// already-verified open inode. The descriptor remains open through callback.
	executable, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", fd.Fd()))
	if err != nil {
		return fmt.Errorf("open mapped executable %q: %w", mapping.Path, err)
	}
	return callback(executable, points, buildID)
}
