// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package memory // import "go.opentelemetry.io/ebpf-profiler/probes/memory"

import (
	"debug/elf"
	"errors"
	"fmt"

	parcausdt "github.com/parca-dev/usdt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// scanMapping resolves configured hooks found in one executable file-backed
// mapping. File contents are parsed once per inode; path-pattern matching is
// applied after the cache lookup because one inode can be mapped through
// different names or mount namespaces.
func (m *Manager) scanMapping(
	pr process.Process,
	mapping *process.RawMapping,
) ([]resolvedHook, error) {
	// A raw-allocator-only configuration can reject unrelated mappings by name
	// before opening or parsing their ELF files. USDT notes have no path selector
	// and therefore still require inspecting each executable file once.
	if !m.needsUSDT && !m.hasMatchingUprobe(mapping.Path) {
		return nil, nil
	}

	fileID := mapping.GetOnDiskFileIdentifier()

	info, ok := m.parseCache.Get(fileID)
	if !ok {
		var err error
		info, err = m.parseMappingFile(pr, mapping)
		if err != nil {
			if errors.Is(err, process.ErrMappingFileUnavailable) || errors.Is(err, pfelf.ErrNotELF) {
				m.parseCache.Add(fileID, parsedFile{})
				return nil, nil
			}
			return nil, err
		}
		m.parseCache.Add(fileID, info)
	}

	return m.resolveHooks(mapping.Path, info), nil
}

func (m *Manager) hasMatchingUprobe(mappingPath string) bool {
	for _, configured := range m.hooks {
		if configured.hook.matchesMappingPath(mappingPath) {
			return true
		}
	}
	return false
}

func (m *Manager) parseMappingFile(
	pr process.Process,
	mapping *process.RawMapping,
) (parsedFile, error) {
	// Open through /proc/<pid>/map_files so deleted files and target mount
	// namespaces are handled correctly.
	ef, err := process.OpenELFMapping(pr, mapping)
	if err != nil {
		return parsedFile{}, fmt.Errorf("open ELF mapping: %w", err)
	}
	defer ef.Close()

	info := parsedFile{}
	if m.needsUSDT {
		probes, err := parcausdt.ParseProbes(&pfelfReader{f: ef})
		if err != nil {
			return parsedFile{}, fmt.Errorf("parse .note.stapsdt: %w", err)
		}
		info.usdtNotes = make([]usdtNote, 0, len(probes))
		for i := range probes {
			probe := &probes[i]
			info.usdtNotes = append(info.usdtNotes, usdtNote{
				Provider:        probe.Provider,
				Name:            probe.Name,
				Location:        probe.Location,
				SemaphoreOffset: probe.SemaphoreOffset,
			})
		}
	}

	if len(m.uprobeSymbols) > 0 {
		if err := ef.LoadSections(); err != nil {
			return parsedFile{}, fmt.Errorf("load ELF sections for uprobe symbols: %w", err)
		}
		info.symbols = make(map[string]uint64)
		visitor := func(symbol libpf.Symbol) bool {
			name := string(symbol.Name)
			if _, wanted := m.uprobeSymbols[name]; wanted {
				if offset, ok := executableFileOffset(ef, uint64(symbol.Address)); ok {
					info.symbols[name] = offset
				}
			}
			return len(info.symbols) < len(m.uprobeSymbols)
		}
		// Stripped objects may have only .dynsym; unstripped objects may keep
		// the desired hook private in .symtab. Absence of either table is normal.
		_ = ef.VisitSymbols(visitor)
		if len(info.symbols) < len(m.uprobeSymbols) {
			_ = ef.VisitDynamicSymbols(visitor)
		}
	}

	return info, nil
}

// executableFileOffset performs the same ELF virtual-address to file-offset
// conversion used by cilium/ebpf's uprobe loader. Resolving it while the target
// mapping is open also supports private symbols and avoids a second ELF parse.
func executableFileOffset(ef *pfelf.File, virtualAddress uint64) (uint64, bool) {
	for i := range ef.Progs {
		prog := &ef.Progs[i]
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		if virtualAddress < prog.Vaddr || virtualAddress >= prog.Vaddr+prog.Filesz {
			continue
		}
		return virtualAddress - prog.Vaddr + prog.Off, true
	}
	return 0, false
}

func (m *Manager) resolveHooks(mappingPath string, info parsedFile) []resolvedHook {
	var resolved []resolvedHook
	for _, configured := range m.hooks {
		switch configured.hook.Type {
		case HookTypeUSDT:
			for _, note := range info.usdtNotes {
				if note.Provider != configured.hook.Provider || note.Name != configured.hook.Name {
					continue
				}
				resolved = append(resolved, resolvedHook{
					HookID:          configured.id,
					Event:           configured.event,
					Type:            HookTypeUSDT,
					ABI:             configured.hook.ABI,
					Location:        note.Location,
					SemaphoreOffset: note.SemaphoreOffset,
				})
			}
		case HookTypeUprobe:
			if !configured.hook.matchesMappingPath(mappingPath) {
				continue
			}
			location, found := info.symbols[configured.hook.Symbol]
			if !found {
				continue
			}
			resolved = append(resolved, resolvedHook{
				HookID:   configured.id,
				Event:    configured.event,
				Type:     HookTypeUprobe,
				ABI:      configured.hook.ABI,
				Location: location,
				Symbol:   configured.hook.Symbol,
			})
		}
	}
	return resolved
}

// pfelfReader adapts *pfelf.File to parcausdt.ELFReader. Only `.note.stapsdt`
// and `.stapsdt.base` need section data populated.
type pfelfReader struct {
	f *pfelf.File
}

func (r *pfelfReader) Sections() ([]parcausdt.ELFSection, error) {
	if err := r.f.LoadSections(); err != nil {
		return nil, err
	}
	out := make([]parcausdt.ELFSection, 0, len(r.f.Sections))
	for i := range r.f.Sections {
		s := &r.f.Sections[i]
		section := parcausdt.ELFSection{Name: s.Name, Addr: s.Addr}
		if s.Name == ".note.stapsdt" || s.Name == ".stapsdt.base" {
			data, err := s.Data(uint(s.Size))
			if err != nil {
				return nil, fmt.Errorf("read section %s: %w", s.Name, err)
			}
			section.Data = data
		}
		out = append(out, section)
	}
	return out, nil
}

func (r *pfelfReader) LoadSegments() []parcausdt.ELFProg {
	var out []parcausdt.ELFProg
	for i := range r.f.Progs {
		prog := &r.f.Progs[i]
		if prog.Type != elf.PT_LOAD {
			continue
		}
		out = append(out, parcausdt.ELFProg{
			Vaddr: prog.Vaddr,
			Memsz: prog.Memsz,
			Off:   prog.Off,
		})
	}
	return out
}
