// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package memory // import "go.opentelemetry.io/ebpf-profiler/probes/memory"

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// attach creates all PID-scoped links needed by one resolved memory hook. The
// map_files path resolves the exact inode mapped by the target process,
// regardless of its mount namespace or whether the original file was deleted.
func (m *Manager) attach(
	pid libpf.PID,
	mapping *process.RawMapping,
	hook resolvedHook,
) ([]link.Link, error) {
	mappingPath := fmt.Sprintf("/proc/%d/map_files/%x-%x",
		pid, mapping.Vaddr, mapping.Vaddr+mapping.Length)
	executable, err := link.OpenExecutable(mappingPath)
	if err != nil {
		return nil, fmt.Errorf("open executable %s: %w", mappingPath, err)
	}

	// Do not set attach cookies: the profiler supports Linux 5.10, while
	// perf-event BPF-link cookies require 5.15. Dedicated adapter programs
	// already encode the source ABI and event meaning.
	options := func(refCtrOffset uint64) *link.UprobeOptions {
		return &link.UprobeOptions{
			PID:          int(pid),
			Address:      hook.Location,
			RefCtrOffset: refCtrOffset,
		}
	}
	attachEntry := func(program ProgramKind, refCtrOffset uint64) (link.Link, error) {
		prog := m.progs[program]
		if prog == nil {
			return nil, fmt.Errorf("no BPF program registered for memory adapter %d", program)
		}
		return executable.Uprobe("", prog, options(refCtrOffset))
	}
	attachReturn := func(program ProgramKind) (link.Link, error) {
		prog := m.progs[program]
		if prog == nil {
			return nil, fmt.Errorf("no BPF program registered for memory adapter %d", program)
		}
		return executable.Uretprobe("", prog, options(0))
	}

	var links []link.Link
	switch hook.ABI {
	case ABIWeightedAllocation:
		var attached link.Link
		attached, err = attachEntry(ProgramWeightedAllocation, hook.SemaphoreOffset)
		if err == nil {
			links = append(links, attached)
		}
	case ABIFree:
		var attached link.Link
		attached, err = attachEntry(ProgramDeallocation, hook.SemaphoreOffset)
		if err == nil {
			links = append(links, attached)
		}
	case ABIMalloc:
		// Attach the return side first. If entry attachment fails, close it so a
		// logical allocator hook is either complete or absent.
		returned, returnErr := attachReturn(ProgramMallocReturn)
		if returnErr != nil {
			err = returnErr
			break
		}
		entered, entryErr := attachEntry(ProgramMallocEnter, 0)
		if entryErr != nil {
			err = errors.Join(entryErr, returned.Close())
			break
		}
		links = append(links, returned, entered)
	default:
		err = fmt.Errorf("unknown memory hook ABI %q", hook.ABI)
	}
	if err != nil {
		description := fmt.Sprintf("%s/%s", hook.Type, hook.ABI)
		if hook.Symbol != "" {
			description += ":" + hook.Symbol
		}
		return nil, fmt.Errorf("attach %s at %s+%#x: %w",
			description, mappingPath, hook.Location, err)
	}
	return links, nil
}
