// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package memory // import "go.opentelemetry.io/ebpf-profiler/probes/memory"

import (
	"fmt"

	cebpf "github.com/cilium/ebpf"
	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// parseCacheSize bounds the number of distinct backing files for which we
// cache discovery results. It matches processmanager's ELF cache size.
const parseCacheSize = 16384

// Manager holds process-independent state for process-scoped memory hooks.
// One Manager exists per profiler instance and is immutable after construction.
type Manager struct {
	config Config

	// progs holds the dedicated eBPF programs used by source-specific adapters.
	progs map[ProgramKind]*cebpf.Program

	// hooks is the normalized set of enabled attachment points. Hook IDs are
	// stable for the lifetime of this manager and distinguish attachment keys.
	hooks []configuredHook

	needsUSDT     bool
	uprobeSymbols map[string]struct{}

	// parseCache deduplicates ELF note/symbol inspection across processes.
	parseCache *lru.SyncedLRU[util.OnDiskFileIdentifier, parsedFile]

	// injector is non-nil only after an operator explicitly enables destructive
	// allocator interposition. Normal memory profiling never constructs it.
	injector allocatorInjector
}

// NewManager constructs the process-scoped memory hook manager. It returns
// (nil, nil) when memory profiling is disabled.
func NewManager(cfg Config, progs map[ProgramKind]*cebpf.Program) (*Manager, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("memory probe config: %w", err)
	}
	if !cfg.Enabled {
		return nil, nil
	}

	parseCache, err := lru.NewSynced[util.OnDiskFileIdentifier, parsedFile](
		parseCacheSize, util.OnDiskFileIdentifier.Hash32)
	if err != nil {
		return nil, fmt.Errorf("memory probe: build parse cache: %w", err)
	}

	m := &Manager{
		config:        cfg,
		progs:         progs,
		parseCache:    parseCache,
		uprobeSymbols: make(map[string]struct{}),
	}
	if cfg.ExperimentalInjectionMode != InjectionDisabled {
		m.injector, err = newAllocatorInjector(
			cfg.ExperimentalShimPath, cfg.ExperimentalInjectionMode,
			cfg.SamplingIntervalBytes, cfg.Live)
		if err != nil {
			return nil, fmt.Errorf("memory probe: initialize experimental injector: %w", err)
		}
	}

	var nextID uint32 = 1
	addHooks := func(event EventKind, hooks []Hook) error {
		for i, hook := range hooks {
			normalized, err := normalizeHook(event, hook)
			if err != nil {
				return fmt.Errorf("hook %d: %w", i, err)
			}
			m.hooks = append(m.hooks, configuredHook{
				id: nextID, event: event, hook: normalized,
			})
			nextID++
			switch normalized.Type {
			case HookTypeUSDT:
				m.needsUSDT = true
			case HookTypeUprobe:
				m.uprobeSymbols[normalized.Symbol] = struct{}{}
			}
		}
		return nil
	}
	if err := addHooks(EventAllocation, cfg.AllocationHooks); err != nil {
		return nil, fmt.Errorf("memory probe allocation %w", err)
	}
	if cfg.Live {
		if err := addHooks(EventDeallocation, cfg.DeallocationHooks); err != nil {
			return nil, fmt.Errorf("memory probe deallocation %w", err)
		}
	}

	for _, configured := range m.hooks {
		for _, program := range programsForABI(configured.hook.ABI) {
			if progs[program] == nil {
				return nil, fmt.Errorf("memory probe: no BPF program registered for adapter %q (%d)",
					configured.hook.ABI, program)
			}
		}
	}

	return m, nil
}

func (m *Manager) matchesProcess(pr process.Process) (bool, error) {
	if len(m.config.ProcessExecutablePatterns) == 0 {
		return true, nil
	}
	executable, err := pr.GetExe()
	if err != nil {
		return false, fmt.Errorf("read process executable: %w", err)
	}
	for _, pattern := range m.config.ProcessExecutablePatterns {
		if matchesExecutablePattern(pattern, executable.String()) {
			return true, nil
		}
	}
	return false, nil
}

func programsForABI(abi HookABI) []ProgramKind {
	switch abi {
	case ABIWeightedAllocation:
		return []ProgramKind{ProgramWeightedAllocation}
	case ABIMalloc:
		return []ProgramKind{ProgramMallocEnter, ProgramMallocReturn}
	case ABIFree:
		return []ProgramKind{ProgramDeallocation}
	default:
		return nil
	}
}

// ShouldRetry reports whether a PID needs periodic re-discovery. One hook per
// required event is sufficient: multiple configured hooks are alternatives for
// different runtimes, not requirements that every process must expose.
func (m *Manager) ShouldRetry(inst *Instance) bool {
	if m == nil || inst == nil {
		return m != nil
	}
	if evaluated, eligible := inst.Applicability(); evaluated && !eligible {
		return false
	}
	if !inst.HasEvent(EventAllocation) {
		return true
	}
	return m.config.Live && !inst.HasEvent(EventDeallocation)
}

// Close releases manager-owned discovery cache state. Per-PID links are owned
// by Instance and closed through Instance.Detach.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.parseCache.Purge()
	return nil
}
