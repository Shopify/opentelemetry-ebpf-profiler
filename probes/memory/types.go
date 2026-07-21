// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package memory implements process-scoped typed memory probes.
//
// Hook points are configuration-driven. USDT hooks are discovered by scanning
// `.note.stapsdt`; allocator hooks are discovered by matching executable
// mappings and function symbols. Both are reconciled on process mapping updates
// so libraries loaded after process startup are supported.
package memory // import "go.opentelemetry.io/ebpf-profiler/probes/memory"

import (
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// EventKind identifies the typed memory event emitted after a hook adapter has
// decoded or correlated its source-specific arguments.
type EventKind uint8

const (
	EventUnknown EventKind = iota

	// EventAllocation carries (pointer, size, unbiased byte weight).
	EventAllocation
	// EventDeallocation carries (pointer).
	EventDeallocation
)

// ProgramKind identifies a dedicated eBPF adapter entry point.
type ProgramKind uint8

const (
	ProgramUnknown ProgramKind = iota
	ProgramWeightedAllocation
	ProgramMallocEnter
	ProgramMallocReturn
	ProgramDeallocation
)

// AttachmentKey uniquely identifies one logical PID-scoped hook. A logical
// malloc hook owns both its entry and return links under one key.
type AttachmentKey struct {
	PID    libpf.PID
	FileID util.OnDiskFileIdentifier
	Event  EventKind
	HookID uint32
	// Offset distinguishes multiple sites from one configured hook in one file.
	Offset uint64
}

// AttachedHook owns every kernel link needed by one logical hook.
type AttachedHook struct {
	Key   AttachmentKey
	Links []link.Link
}

// configuredHook binds an operator hook point to its typed memory event.
type configuredHook struct {
	id    uint32
	event EventKind
	hook  Hook
}

// resolvedHook is a normalized configured hook found in one mapped ELF file.
type resolvedHook struct {
	HookID          uint32
	Event           EventKind
	Type            HookType
	ABI             HookABI
	Location        uint64 // absolute ELF file offset for USDT or raw uprobe
	SemaphoreOffset uint64 // USDT semaphore file offset, 0 if none
	Symbol          string // set for raw uprobes
}

// usdtNote is the subset of a parsed `.note.stapsdt` entry needed for matching.
type usdtNote struct {
	Provider        string
	Name            string
	Location        uint64
	SemaphoreOffset uint64
}

// parsedFile caches process-independent discovery information for one ELF.
type parsedFile struct {
	usdtNotes []usdtNote
	// symbols maps configured function names found in .symtab/.dynsym to their
	// absolute ELF file offsets.
	symbols map[string]uint64
}
