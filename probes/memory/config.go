// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package memory // import "go.opentelemetry.io/ebpf-profiler/probes/memory"

import (
	"fmt"
	"math"
	"path"
	"strings"
)

const (
	// DefaultUSDTProvider is the provider emitted by libdd-profiling-heap-sampler.
	DefaultUSDTProvider = "ddheap"

	// DefaultMaxEntriesPerPID bounds live allocation correlation state per process.
	DefaultMaxEntriesPerPID = 10_000

	// DefaultSamplingIntervalBytes is the average allocation volume represented
	// by one sample from a directly instrumented allocator.
	DefaultSamplingIntervalBytes = 512 * 1024

	// ExperimentalShimExecutable matches the memfd name used when the profiler
	// injects its allocator shim into another process.
	ExperimentalShimExecutable  = "*prophiler-heap-shim*"
	ExperimentalShimAllocSymbol = "prophiler_heap_alloc"
	ExperimentalShimFreeSymbol  = "prophiler_heap_free"
)

// HookType identifies how a process-local memory event hook is discovered.
type HookType string

// InjectionMode controls experimental mutation of target processes. Every
// non-disabled value can crash or permanently corrupt the target process and
// must be explicitly selected by an operator.
type InjectionMode string

const (
	// InjectionDisabled never mutates target processes.
	InjectionDisabled InjectionMode = "disabled"
	// InjectionGOT asks an injected shim to rewrite allocator GOT/PLT slots.
	InjectionGOT InjectionMode = "got"
	// InjectionGOTThenInline falls back to overwriting allocator function
	// prologues with architecture-specific jumps when GOT rewriting fails.
	InjectionGOTThenInline InjectionMode = "got-then-inline"
)

// Set implements flag.Value. Empty is accepted as the safe disabled value.
func (m *InjectionMode) Set(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = string(InjectionDisabled)
	}
	switch InjectionMode(value) {
	case InjectionDisabled, InjectionGOT, InjectionGOTThenInline:
		*m = InjectionMode(value)
		return nil
	default:
		return fmt.Errorf("unknown experimental allocator injection mode %q", value)
	}
}

func (m InjectionMode) String() string {
	if m == "" {
		return string(InjectionDisabled)
	}
	return string(m)
}

const (
	// HookTypeUSDT discovers an ELF .note.stapsdt provider/name pair and attaches
	// to the note's file offset.
	HookTypeUSDT HookType = "usdt"
	// HookTypeUprobe discovers a function symbol in matching executable mappings.
	HookTypeUprobe HookType = "uprobe"
)

// HookABI identifies the adapter between an attachment point and a typed memory
// event. Attachment configuration never changes the event's meaning.
type HookABI string

const (
	// ABIWeightedAllocation consumes (pointer, size, weight) at function entry.
	// This is the ABI exposed by the default ddheap:alloc USDT producer.
	ABIWeightedAllocation HookABI = "weighted_allocation"
	// ABIMalloc pairs malloc-like (size) entry and (pointer) return probes. The
	// eBPF adapter samples calls and supplies an unbiased weight.
	ABIMalloc HookABI = "malloc"
	// ABIFree consumes (pointer) at function entry.
	ABIFree HookABI = "free"
)

// Hook describes one attachment point and its explicit event adapter.
//
// When ABI is omitted, USDT allocation hooks default to weighted_allocation,
// raw allocation uprobes default to malloc, and deallocation hooks default to
// free. A malloc hook owns both an entry uprobe and a return uprobe.
type Hook struct {
	Type HookType `mapstructure:"type" json:"type"`
	ABI  HookABI  `mapstructure:"abi" json:"abi,omitempty"`

	// Provider and Name select a USDT note when Type is "usdt".
	Provider string `mapstructure:"provider" json:"provider,omitempty"`
	Name     string `mapstructure:"name" json:"name,omitempty"`

	// Executable is a path.Match pattern. Patterns containing '/' match the
	// mapping path; other patterns match its base name. Symbol selects the
	// function when Type is "uprobe".
	Executable string `mapstructure:"executable" json:"executable,omitempty"`
	Symbol     string `mapstructure:"symbol" json:"symbol,omitempty"`
}

// USDTHook constructs a USDT hook specification. Its event-specific default
// ABI is assigned while the configuration is normalized.
func USDTHook(provider, name string) Hook {
	return Hook{Type: HookTypeUSDT, Provider: provider, Name: name}
}

// UprobeHook constructs a raw function hook specification. Allocation hooks
// default to the paired malloc adapter; deallocation hooks default to free.
func UprobeHook(executable, symbol string) Hook {
	return Hook{Type: HookTypeUprobe, Executable: executable, Symbol: symbol}
}

// ParseHook parses the compact CLI form of a hook:
//
//   - usdt:<provider>:<name>
//   - uprobe:<executable-pattern>:<symbol>
//   - weighted-uprobe:<executable-pattern>:<symbol>
//
// The containing allocation/deallocation flag determines the default ABI for
// the first two forms. weighted-uprobe explicitly targets a sampled function
// exposing (pointer, size, weight), such as an LD_PRELOAD shim marker.
func ParseHook(spec string) (Hook, error) {
	typeName, target, found := strings.Cut(spec, ":")
	if !found {
		return Hook{}, fmt.Errorf(
			"invalid memory hook %q: expected usdt:<provider>:<name>, "+
				"uprobe:<executable-pattern>:<symbol>, or weighted-uprobe:<executable-pattern>:<symbol>", spec)
	}

	var hook Hook
	switch HookType(strings.ToLower(strings.TrimSpace(typeName))) {
	case HookTypeUSDT:
		provider, name, ok := strings.Cut(target, ":")
		if !ok {
			return Hook{}, fmt.Errorf("invalid memory hook %q: expected usdt:<provider>:<name>", spec)
		}
		hook = USDTHook(strings.TrimSpace(provider), strings.TrimSpace(name))
	case HookTypeUprobe, HookType("weighted-uprobe"):
		// Split on the final colon so Linux paths containing ':' remain valid.
		separator := strings.LastIndexByte(target, ':')
		if separator < 0 {
			return Hook{}, fmt.Errorf(
				"invalid memory hook %q: expected uprobe:<executable-pattern>:<symbol>", spec)
		}
		hook = UprobeHook(
			strings.TrimSpace(target[:separator]), strings.TrimSpace(target[separator+1:]))
		if HookType(strings.ToLower(strings.TrimSpace(typeName))) == HookType("weighted-uprobe") {
			hook.ABI = ABIWeightedAllocation
		}
	default:
		return Hook{}, fmt.Errorf("invalid memory hook %q: unknown type %q", spec, typeName)
	}
	if err := hook.Validate(); err != nil {
		return Hook{}, fmt.Errorf("invalid memory hook %q: %w", spec, err)
	}
	return hook, nil
}

func (h Hook) String() string {
	switch h.Type {
	case HookTypeUSDT:
		return fmt.Sprintf("usdt:%s:%s", h.Provider, h.Name)
	case HookTypeUprobe:
		return fmt.Sprintf("uprobe:%s:%s", h.Executable, h.Symbol)
	default:
		return string(h.Type)
	}
}

// Validate verifies the attachment fields independently of the event list in
// which the hook appears. Config.Validate checks event/ABI compatibility.
func (h Hook) Validate() error {
	switch h.Type {
	case HookTypeUSDT:
		if h.Provider == "" || h.Name == "" {
			return fmt.Errorf("USDT hooks require non-empty provider and name")
		}
		if h.Executable != "" || h.Symbol != "" {
			return fmt.Errorf("USDT hooks cannot set executable or symbol")
		}
	case HookTypeUprobe:
		if h.Executable == "" || h.Symbol == "" {
			return fmt.Errorf("uprobes require non-empty executable and symbol")
		}
		if h.Provider != "" || h.Name != "" {
			return fmt.Errorf("uprobes cannot set provider or name")
		}
		if _, err := path.Match(h.Executable, "candidate"); err != nil {
			return fmt.Errorf("invalid executable pattern %q: %w", h.Executable, err)
		}
	default:
		return fmt.Errorf("unknown hook type %q", h.Type)
	}

	switch h.ABI {
	case "", ABIWeightedAllocation, ABIMalloc, ABIFree:
		return nil
	default:
		return fmt.Errorf("unknown memory hook ABI %q", h.ABI)
	}
}

func normalizeHook(event EventKind, hook Hook) (Hook, error) {
	if err := hook.Validate(); err != nil {
		return Hook{}, err
	}
	if hook.ABI == "" {
		switch event {
		case EventAllocation:
			if hook.Type == HookTypeUSDT {
				hook.ABI = ABIWeightedAllocation
			} else {
				hook.ABI = ABIMalloc
			}
		case EventDeallocation:
			hook.ABI = ABIFree
		}
	}

	switch event {
	case EventAllocation:
		if hook.ABI != ABIWeightedAllocation && hook.ABI != ABIMalloc {
			return Hook{}, fmt.Errorf("allocation hooks require %q or %q ABI, got %q",
				ABIWeightedAllocation, ABIMalloc, hook.ABI)
		}
		if hook.Type == HookTypeUSDT && hook.ABI == ABIMalloc {
			return Hook{}, fmt.Errorf("malloc ABI requires a function uprobe, not a USDT note")
		}
	case EventDeallocation:
		if hook.ABI != ABIFree {
			return Hook{}, fmt.Errorf("deallocation hooks require %q ABI, got %q", ABIFree, hook.ABI)
		}
	default:
		return Hook{}, fmt.Errorf("unknown memory event %d", event)
	}
	return hook, nil
}

func (h Hook) matchesMappingPath(mappingPath string) bool {
	return h.Type == HookTypeUprobe && matchesExecutablePattern(h.Executable, mappingPath)
}

func matchesExecutablePattern(pattern, executablePath string) bool {
	executablePath = strings.TrimSuffix(executablePath, " (deleted)")
	candidate := path.Base(executablePath)
	if strings.Contains(pattern, "/") {
		candidate = executablePath
	}
	matched, err := path.Match(pattern, candidate)
	return err == nil && matched
}

// Config configures the memory custom probe. The zero value is disabled.
type Config struct {
	Enabled               bool   `mapstructure:"enabled" json:"enabled,omitempty"`
	Live                  bool   `mapstructure:"live" json:"live,omitempty"`
	MaxEntriesPerPID      int    `mapstructure:"max_entries_per_pid" json:"max_entries_per_pid,omitempty"`
	SamplingIntervalBytes uint64 `mapstructure:"sampling_interval_bytes" json:"sampling_interval_bytes,omitempty"`

	// ProcessExecutablePatterns restricts attachment by /proc/<pid>/exe. A
	// pattern containing '/' matches the full path; other patterns match the
	// executable basename. Direct malloc instrumentation requires at least one
	// selector so it cannot accidentally trap every allocator call on a host.
	ProcessExecutablePatterns []string `mapstructure:"process_executables" json:"process_executables,omitempty"`

	AllocationHooks   []Hook `mapstructure:"allocation_hooks" json:"allocation_hooks,omitempty"`
	DeallocationHooks []Hook `mapstructure:"deallocation_hooks" json:"deallocation_hooks,omitempty"`

	// ExperimentalInjectionMode enables progressively more invasive allocator
	// interposition when no configured producer hook exists. The profiler first
	// injects ExperimentalShimPath with ptrace+dlopen and asks it to rewrite
	// GOT/PLT slots. got-then-inline additionally permits direct allocator text
	// patching. Both modes are intentionally disabled by default.
	ExperimentalInjectionMode InjectionMode `mapstructure:"experimental_injection_mode" json:"experimental_injection_mode,omitempty"`
	ExperimentalShimPath      string        `mapstructure:"experimental_shim_path" json:"experimental_shim_path,omitempty"`
}

// DefaultConfig returns the default-off memory probe configuration with the
// libdd heap sampler's weighted USDT ABI preconfigured.
func DefaultConfig() Config {
	return Config{
		MaxEntriesPerPID:      DefaultMaxEntriesPerPID,
		SamplingIntervalBytes: DefaultSamplingIntervalBytes,
		AllocationHooks: []Hook{
			USDTHook(DefaultUSDTProvider, "alloc"),
		},
		DeallocationHooks: []Hook{
			USDTHook(DefaultUSDTProvider, "free"),
		},
	}
}

// ApplyDefaults fills optional values that callers constructing Config structs
// directly commonly omit. A non-empty hook list fully replaces the defaults.
func (cfg *Config) ApplyDefaults() {
	if cfg.ExperimentalInjectionMode == "" {
		cfg.ExperimentalInjectionMode = InjectionDisabled
	}
	if cfg.MaxEntriesPerPID == 0 {
		cfg.MaxEntriesPerPID = DefaultMaxEntriesPerPID
	}
	if cfg.SamplingIntervalBytes == 0 {
		cfg.SamplingIntervalBytes = DefaultSamplingIntervalBytes
	}
	if len(cfg.AllocationHooks) == 0 {
		cfg.AllocationHooks = []Hook{USDTHook(DefaultUSDTProvider, "alloc")}
	}
	if len(cfg.DeallocationHooks) == 0 {
		cfg.DeallocationHooks = []Hook{USDTHook(DefaultUSDTProvider, "free")}
	}
	if cfg.ExperimentalInjectionMode != InjectionDisabled {
		cfg.AllocationHooks = appendHookIfMissing(cfg.AllocationHooks, Hook{
			Type: HookTypeUprobe, ABI: ABIWeightedAllocation,
			Executable: ExperimentalShimExecutable, Symbol: ExperimentalShimAllocSymbol,
		})
		if cfg.Live {
			cfg.DeallocationHooks = appendHookIfMissing(cfg.DeallocationHooks, Hook{
				Type: HookTypeUprobe, ABI: ABIFree,
				Executable: ExperimentalShimExecutable, Symbol: ExperimentalShimFreeSymbol,
			})
		}
	}
}

func appendHookIfMissing(hooks []Hook, candidate Hook) []Hook {
	for _, hook := range hooks {
		if hook.Type == candidate.Type && hook.ABI == candidate.ABI &&
			hook.Executable == candidate.Executable && hook.Symbol == candidate.Symbol {
			return hooks
		}
	}
	return append(hooks, candidate)
}

// Validate checks memory probe configuration and hook adapters.
func (cfg Config) Validate() error {
	mode := cfg.ExperimentalInjectionMode
	if mode == "" {
		mode = InjectionDisabled
	}
	switch mode {
	case InjectionDisabled:
		if cfg.ExperimentalShimPath != "" {
			return fmt.Errorf("experimental shim path requires a non-disabled injection mode")
		}
	case InjectionGOT, InjectionGOTThenInline:
		if !cfg.Enabled {
			return fmt.Errorf("experimental allocator injection requires memory profiling to be enabled")
		}
		if cfg.ExperimentalShimPath == "" {
			return fmt.Errorf("experimental allocator injection requires experimental_shim_path")
		}
		if !path.IsAbs(cfg.ExperimentalShimPath) {
			return fmt.Errorf("experimental allocator shim path must be absolute")
		}
		if len(cfg.ProcessExecutablePatterns) == 0 {
			return fmt.Errorf("experimental allocator injection requires at least one process_executables selector")
		}
	default:
		return fmt.Errorf("unknown experimental allocator injection mode %q", mode)
	}

	if cfg.Live && !cfg.Enabled {
		return fmt.Errorf("live memory profiling requires memory profiling to be enabled")
	}
	if cfg.MaxEntriesPerPID < 0 {
		return fmt.Errorf("max entries per PID must not be negative")
	}
	if cfg.Live && cfg.MaxEntriesPerPID == 0 {
		return fmt.Errorf("live memory profiling requires a non-zero max entries per PID")
	}
	if cfg.Enabled && len(cfg.AllocationHooks) == 0 {
		return fmt.Errorf("memory profiling requires at least one allocation hook")
	}
	if cfg.Live && len(cfg.DeallocationHooks) == 0 {
		return fmt.Errorf("live memory profiling requires at least one deallocation hook")
	}
	if cfg.SamplingIntervalBytes > math.MaxUint32 {
		return fmt.Errorf("sampling interval bytes must not exceed %d", uint64(math.MaxUint32))
	}
	for i, pattern := range cfg.ProcessExecutablePatterns {
		if pattern == "" {
			return fmt.Errorf("process executable pattern %d must not be empty", i)
		}
		if _, err := path.Match(pattern, "candidate"); err != nil {
			return fmt.Errorf("invalid process executable pattern %q: %w", pattern, err)
		}
	}

	seen := make(map[string]string)
	validateHooks := func(eventName string, event EventKind, hooks []Hook) error {
		for i, hook := range hooks {
			normalized, err := normalizeHook(event, hook)
			if err != nil {
				return fmt.Errorf("%s hook %d: %w", eventName, i, err)
			}
			key := normalized.String()
			if previous, ok := seen[key]; ok {
				return fmt.Errorf("duplicate hook %q configured for %s and %s", key, previous, eventName)
			}
			seen[key] = eventName
		}
		return nil
	}
	if err := validateHooks("allocation", EventAllocation, cfg.AllocationHooks); err != nil {
		return err
	}
	if err := validateHooks("deallocation", EventDeallocation, cfg.DeallocationHooks); err != nil {
		return err
	}
	if cfg.Enabled && cfg.UsesMallocAdapter() {
		if cfg.SamplingIntervalBytes == 0 {
			return fmt.Errorf("malloc hooks require a non-zero sampling interval bytes")
		}
		if len(cfg.ProcessExecutablePatterns) == 0 {
			return fmt.Errorf("malloc hooks require at least one process_executables selector")
		}
	}
	return nil
}

// UsesWeightedAllocation reports whether an enabled hook consumes a producer-
// supplied (pointer, size, weight) event.
func (cfg Config) UsesWeightedAllocation() bool {
	if !cfg.Enabled {
		return false
	}
	for _, hook := range cfg.AllocationHooks {
		normalized, err := normalizeHook(EventAllocation, hook)
		if err == nil && normalized.ABI == ABIWeightedAllocation {
			return true
		}
	}
	return false
}

// UsesMallocAdapter reports whether an enabled hook needs paired allocator
// entry/return instrumentation and in-kernel sampling state.
func (cfg Config) UsesMallocAdapter() bool {
	if !cfg.Enabled {
		return false
	}
	for _, hook := range cfg.AllocationHooks {
		normalized, err := normalizeHook(EventAllocation, hook)
		if err == nil && normalized.ABI == ABIMalloc {
			return true
		}
	}
	return false
}

// IsMapEnabled reports whether memory-probe-only eBPF maps should be loaded.
func (cfg Config) IsMapEnabled(mapName string) bool {
	switch mapName {
	case "heap_alloc_live", "heap_live_pids", "heap_pid_alloc_count", "heap_pid_alloc_limit":
		return cfg.Enabled
	case "heap_pending_allocs", "heap_sampling_interval":
		return cfg.UsesMallocAdapter()
	default:
		return true
	}
}
