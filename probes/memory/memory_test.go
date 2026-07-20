// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"debug/elf"
	"testing"

	cebpf "github.com/cilium/ebpf"
	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/util"
)

func TestParseHook(t *testing.T) {
	tests := []struct {
		input string
		want  Hook
	}{
		{"usdt:ddheap:alloc", USDTHook("ddheap", "alloc")},
		{"USDT: ruby: object_alloc", USDTHook("ruby", "object_alloc")},
		{"uprobe:libheap_sampler.so:record_alloc", UprobeHook("libheap_sampler.so", "record_alloc")},
		{"uprobe:/opt/runtime/*/libheap.so:record_free", UprobeHook("/opt/runtime/*/libheap.so", "record_free")},
		{"uprobe:/opt/runtime:v2/libheap.so:record_free", UprobeHook("/opt/runtime:v2/libheap.so", "record_free")},
		{"weighted-uprobe:libheap-shim.so:sampled_alloc", Hook{
			Type: HookTypeUprobe, ABI: ABIWeightedAllocation,
			Executable: "libheap-shim.so", Symbol: "sampled_alloc",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseHook(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	for _, invalid := range []string{
		"", "usdt:alloc", "tracepoint:ddheap:alloc", "usdt::alloc",
		"uprobe:libheap.so:", "uprobe:[:alloc",
	} {
		t.Run("invalid_"+invalid, func(t *testing.T) {
			_, err := ParseHook(invalid)
			require.Error(t, err)
		})
	}
}

func TestHookMatchesMappingPath(t *testing.T) {
	assert.True(t, UprobeHook("libheap*.so", "alloc").matchesMappingPath("/usr/lib/libheap-v2.so"))
	assert.True(t, UprobeHook("/opt/runtime/*/libheap.so", "alloc").matchesMappingPath(
		"/opt/runtime/v2/libheap.so"))
	assert.True(t, UprobeHook("libheap.so", "alloc").matchesMappingPath(
		"/usr/lib/libheap.so (deleted)"))
	assert.False(t, UprobeHook("libheap.so", "alloc").matchesMappingPath("/usr/lib/libother.so"))
	assert.False(t, USDTHook("ddheap", "alloc").matchesMappingPath("/usr/lib/libheap.so"))
	assert.True(t, matchesExecutablePattern("ruby*", "/usr/bin/ruby3.3"))
	assert.True(t, matchesExecutablePattern("/opt/runtime/*/ruby", "/opt/runtime/v2/ruby"))
	assert.False(t, matchesExecutablePattern("tarantool", "/usr/bin/ruby"))
}

func TestConfigDefaultsAndValidation(t *testing.T) {
	cfg := Config{Enabled: true}
	cfg.ApplyDefaults()
	require.NoError(t, cfg.Validate())
	assert.Equal(t, DefaultMaxEntriesPerPID, cfg.MaxEntriesPerPID)
	assert.Equal(t, uint64(DefaultSamplingIntervalBytes), cfg.SamplingIntervalBytes)
	assert.Equal(t, []Hook{USDTHook("ddheap", "alloc")}, cfg.AllocationHooks)
	assert.Equal(t, []Hook{USDTHook("ddheap", "free")}, cfg.DeallocationHooks)

	liveWithoutMemory := DefaultConfig()
	liveWithoutMemory.Live = true
	require.ErrorContains(t, liveWithoutMemory.Validate(), "requires memory profiling")

	duplicate := DefaultConfig()
	duplicate.Enabled = true
	duplicate.DeallocationHooks = duplicate.AllocationHooks
	require.ErrorContains(t, duplicate.Validate(), "duplicate hook")

	invalidUprobe := DefaultConfig()
	invalidUprobe.Enabled = true
	invalidUprobe.AllocationHooks = []Hook{{Type: HookTypeUprobe, Executable: "libheap.so"}}
	require.ErrorContains(t, invalidUprobe.Validate(), "symbol")

	allocator := DefaultConfig()
	allocator.Enabled = true
	allocator.AllocationHooks = []Hook{UprobeHook("libc.so.6", "malloc")}
	require.ErrorContains(t, allocator.Validate(), "process_executables")
	allocator.ProcessExecutablePatterns = []string{"ruby*"}
	require.NoError(t, allocator.Validate())
	assert.True(t, allocator.UsesMallocAdapter())
	assert.False(t, allocator.UsesWeightedAllocation())
	assert.True(t, allocator.IsMapEnabled("heap_pending_allocs"))

	badABI := allocator
	badABI.AllocationHooks[0].ABI = ABIFree
	require.ErrorContains(t, badABI.Validate(), "allocation hooks require")

	experimental := DefaultConfig()
	experimental.Enabled = true
	experimental.ProcessExecutablePatterns = []string{"ruby*"}
	experimental.ExperimentalInjectionMode = InjectionGOTThenInline
	experimental.ExperimentalShimPath = "/opt/prophiler/libprophiler-heap-shim.so"
	experimental.ApplyDefaults()
	require.NoError(t, experimental.Validate())
	assert.Contains(t, experimental.AllocationHooks, Hook{
		Type: HookTypeUprobe, ABI: ABIWeightedAllocation,
		Executable: ExperimentalShimExecutable, Symbol: ExperimentalShimAllocSymbol,
	})
	assert.False(t, experimental.Live, "free hook is only installed for live profiles")

	experimental.Live = true
	experimental.ApplyDefaults()
	require.NoError(t, experimental.Validate())
	assert.Contains(t, experimental.DeallocationHooks, Hook{
		Type: HookTypeUprobe, ABI: ABIFree,
		Executable: ExperimentalShimExecutable, Symbol: ExperimentalShimFreeSymbol,
	})

	missingSelector := experimental
	missingSelector.ProcessExecutablePatterns = nil
	require.ErrorContains(t, missingSelector.Validate(), "process_executables")
	missingShim := experimental
	missingShim.ExperimentalShimPath = ""
	require.ErrorContains(t, missingShim.Validate(), "experimental_shim_path")

	var mode InjectionMode
	require.NoError(t, mode.Set("GOT"))
	assert.Equal(t, InjectionGOT, mode)
	require.Error(t, mode.Set("please-corrupt-everything"))
}

type processWithExecutable struct {
	process.Process
	executable libpf.String
}

func (p processWithExecutable) GetExe() (libpf.String, error) {
	return p.executable, nil
}

func TestManagerProcessSelector(t *testing.T) {
	manager := &Manager{config: Config{
		ProcessExecutablePatterns: []string{"ruby*", "/opt/tarantool/*"},
	}}

	matched, err := manager.matchesProcess(processWithExecutable{
		executable: libpf.Intern("/usr/bin/ruby3.3"),
	})
	require.NoError(t, err)
	assert.True(t, matched)

	matched, err = manager.matchesProcess(processWithExecutable{
		executable: libpf.Intern("/usr/bin/python3"),
	})
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestExecutableFileOffset(t *testing.T) {
	file := &pfelf.File{Progs: []pfelf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Off: 0, Vaddr: 0, Filesz: 0x100}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0x1000, Vaddr: 0x4000, Filesz: 0x500}},
	}}

	offset, ok := executableFileOffset(file, 0x4123)
	require.True(t, ok)
	assert.Equal(t, uint64(0x1123), offset)

	_, ok = executableFileOffset(file, 0x2000)
	assert.False(t, ok, "non-executable and out-of-range addresses are rejected")
	_, ok = executableFileOffset(file, 0x4500)
	assert.False(t, ok, "the end of the file-backed range is exclusive")
}

func TestResolveConfiguredHooks(t *testing.T) {
	weighted, err := normalizeHook(EventAllocation, USDTHook("ddheap", "alloc"))
	require.NoError(t, err)
	other, err := normalizeHook(EventAllocation, USDTHook("other", "alloc"))
	require.NoError(t, err)
	malloc, err := normalizeHook(EventAllocation, UprobeHook("libheap*.so", "record_alloc"))
	require.NoError(t, err)
	free, err := normalizeHook(EventDeallocation, UprobeHook("libheap*.so", "record_free"))
	require.NoError(t, err)
	m := &Manager{hooks: []configuredHook{
		{id: 1, event: EventAllocation, hook: weighted},
		{id: 2, event: EventAllocation, hook: other},
		{id: 3, event: EventAllocation, hook: malloc},
		{id: 4, event: EventDeallocation, hook: free},
	}}
	info := parsedFile{
		usdtNotes: []usdtNote{
			{Provider: "ddheap", Name: "alloc", Location: 0x100, SemaphoreOffset: 0x20},
			{Provider: "ddheap", Name: "unrelated", Location: 0x200},
		},
		symbols: map[string]uint64{"record_alloc": 0x300},
	}

	got := m.resolveHooks("/usr/lib/libheap-v2.so", info)
	require.Len(t, got, 2)
	assert.Equal(t, resolvedHook{
		HookID: 1, Event: EventAllocation, Type: HookTypeUSDT,
		ABI: ABIWeightedAllocation, Location: 0x100, SemaphoreOffset: 0x20,
	}, got[0])
	assert.Equal(t, resolvedHook{
		HookID: 3, Event: EventAllocation, Type: HookTypeUprobe,
		ABI: ABIMalloc, Location: 0x300, Symbol: "record_alloc",
	}, got[1])
}

func TestInstanceAndManagerRetryState(t *testing.T) {
	inst := &Instance{
		pid: 1,
		attached: map[AttachmentKey]AttachedHook{
			{PID: 1, Event: EventAllocation, Offset: 0x10}: {},
		},
	}
	assert.Equal(t, 1, inst.NumAttached())
	assert.True(t, inst.HasEvent(EventAllocation))
	assert.False(t, inst.HasEvent(EventDeallocation))

	allocationOnly := &Manager{config: Config{Enabled: true}}
	assert.False(t, allocationOnly.ShouldRetry(inst))

	live := &Manager{config: Config{Enabled: true, Live: true}}
	assert.True(t, live.ShouldRetry(inst))
	inst.attached[AttachmentKey{PID: 1, Event: EventDeallocation, Offset: 0x20}] = AttachedHook{}
	assert.False(t, live.ShouldRetry(inst))

	var nilInst *Instance
	assert.Equal(t, 0, nilInst.NumAttached())
	assert.False(t, nilInst.HasEvent(EventAllocation))
	assert.True(t, live.ShouldRetry(nilInst))

	excluded := NewInstance(2)
	excluded.setApplicability(false)
	assert.False(t, live.ShouldRetry(excluded),
		"processes excluded by executable selectors need no periodic rescans")
}

func TestNewManager(t *testing.T) {
	disabled := DefaultConfig()
	manager, err := NewManager(disabled, nil)
	require.NoError(t, err)
	assert.Nil(t, manager)

	enabled := DefaultConfig()
	enabled.Enabled = true
	_, err = NewManager(enabled, nil)
	require.ErrorContains(t, err, "no BPF program")

	manager, err = NewManager(enabled, map[ProgramKind]*cebpf.Program{
		ProgramWeightedAllocation: {},
	})
	require.NoError(t, err)
	require.NotNil(t, manager)
	assert.Len(t, manager.hooks, 1)
	assert.True(t, manager.needsUSDT)
	assert.NoError(t, manager.Close())

	allocator := DefaultConfig()
	allocator.Enabled = true
	allocator.AllocationHooks = []Hook{UprobeHook("libc.so.6", "malloc")}
	allocator.ProcessExecutablePatterns = []string{"ruby*"}
	manager, err = NewManager(allocator, map[ProgramKind]*cebpf.Program{
		ProgramMallocEnter:  {},
		ProgramMallocReturn: {},
	})
	require.NoError(t, err)
	require.Len(t, manager.hooks, 1)
	assert.Equal(t, ABIMalloc, manager.hooks[0].hook.ABI)
}

func TestManagerClose(t *testing.T) {
	var manager *Manager
	assert.NoError(t, manager.Close())

	cache, err := lru.NewSynced[util.OnDiskFileIdentifier, parsedFile](
		8, util.OnDiskFileIdentifier.Hash32)
	require.NoError(t, err)
	cache.Add(util.OnDiskFileIdentifier{InodeNum: 1}, parsedFile{})
	require.Equal(t, 1, cache.Len())

	manager = &Manager{parseCache: cache}
	require.NoError(t, manager.Close())
	assert.Zero(t, cache.Len())
}
