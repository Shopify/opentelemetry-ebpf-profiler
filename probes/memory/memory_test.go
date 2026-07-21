// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"debug/elf"
	"errors"
	"os"
	"sync/atomic"
	"testing"

	cebpf "github.com/cilium/ebpf"
	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
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
	for _, selector := range []string{"*", "**"} {
		allocator.ProcessExecutablePatterns = []string{selector}
		require.ErrorContains(t, allocator.Validate(), "too broad")
	}
	allocator.ProcessExecutablePatterns = []string{"ruby*"}
	require.NoError(t, allocator.Validate())
	assert.True(t, allocator.UsesDirectAllocatorAdapter())
	assert.True(t, allocator.UsesMallocAdapter())
	assert.False(t, allocator.UsesWeightedAllocation())
	assert.True(t, allocator.IsMapEnabled("heap_pending_allocs"))

	directFree := DefaultConfig()
	directFree.Enabled = true
	directFree.Live = true
	directFree.DeallocationHooks = []Hook{UprobeHook("libc.so.6", "free")}
	require.ErrorContains(t, directFree.Validate(), "process_executables")
	directFree.ProcessExecutablePatterns = []string{"*"}
	require.ErrorContains(t, directFree.Validate(), "too broad")
	directFree.ProcessExecutablePatterns = []string{"ruby*"}
	require.NoError(t, directFree.Validate())
	assert.True(t, directFree.UsesDirectAllocatorAdapter())
	assert.False(t, directFree.UsesMallocAdapter())

	badABI := allocator
	badABI.AllocationHooks[0].ABI = ABIFree
	require.ErrorContains(t, badABI.Validate(), "allocation hooks require")

	experimental := DefaultConfig()
	experimental.Enabled = true
	experimental.ProcessExecutablePatterns = []string{"/usr/bin/ruby"}
	experimental.ExperimentalInjectionMode = InjectionGOTThenInline
	experimental.ExperimentalShimPath = "/opt/prophiler/libprophiler-heap-shim.so"
	experimental.ApplyDefaults()
	require.NoError(t, experimental.Validate())
	assert.Contains(t, experimental.AllocationHooks, Hook{
		Type: HookTypeUSDT, ABI: ABIWeightedAllocation,
		Provider: ExperimentalShimProvider, Name: "alloc",
	})
	assert.False(t, experimental.Live, "free hook is only installed for live profiles")

	experimental.Live = true
	experimental.ApplyDefaults()
	require.NoError(t, experimental.Validate())
	assert.Contains(t, experimental.DeallocationHooks, Hook{
		Type: HookTypeUSDT, ABI: ABIFree,
		Provider: ExperimentalShimProvider, Name: "free",
	})

	missingSelector := experimental
	missingSelector.ProcessExecutablePatterns = nil
	require.ErrorContains(t, missingSelector.Validate(), "process_executables")
	for _, selector := range []string{"ruby*", "/usr/bin/ruby?", "/usr/bin/ruby[0-9]"} {
		wildcardSelector := experimental
		wildcardSelector.ProcessExecutablePatterns = []string{selector}
		require.ErrorContains(t, wildcardSelector.Validate(),
			"exact absolute process_executables", "selector %q", selector)
	}
	basenameSelector := experimental
	basenameSelector.ProcessExecutablePatterns = []string{"ruby"}
	require.ErrorContains(t, basenameSelector.Validate(), "exact absolute process_executables")
	whitespaceSelector := experimental
	whitespaceSelector.ProcessExecutablePatterns = []string{"/usr/bin/ruby "}
	require.ErrorContains(t, whitespaceSelector.Validate(), "exact absolute process_executables")
	missingShim := experimental
	missingShim.ExperimentalShimPath = ""
	require.ErrorContains(t, missingShim.Validate(), "experimental_shim_path")
	zeroSampling := experimental
	zeroSampling.SamplingIntervalBytes = 0
	require.ErrorContains(t, zeroSampling.Validate(), "non-zero sampling interval")

	hooks := appendHookIfMissing([]Hook{{
		Type: HookTypeUSDT, ABI: ABIWeightedAllocation, Provider: "first", Name: "alloc",
	}}, Hook{
		Type: HookTypeUSDT, ABI: ABIWeightedAllocation, Provider: "second", Name: "alloc",
	})
	assert.Len(t, hooks, 2, "distinct USDT providers are distinct hooks")

	hooks = appendHookIfMissing([]Hook{{
		Type: HookTypeUSDT, Provider: ExperimentalShimProvider, Name: "alloc",
	}}, Hook{
		Type: HookTypeUSDT, ABI: ABIWeightedAllocation,
		Provider: ExperimentalShimProvider, Name: "alloc",
	})
	assert.Len(t, hooks, 1, "an omitted event-default ABI must not duplicate an injected hook")

	var mode InjectionMode
	require.NoError(t, mode.Set("GOT"))
	assert.Equal(t, InjectionGOT, mode)
	require.Error(t, mode.Set("please-corrupt-everything"))
}

type processWithExecutable struct {
	process.Process
	executable     libpf.String
	mappings       []process.RawMapping
	iterateErr     error
	mappingOpenErr error
}

func (p processWithExecutable) GetExe() (libpf.String, error) {
	return p.executable, nil
}

func (p processWithExecutable) IterateMappings(
	callback func(process.RawMapping) bool,
) (uint32, error) {
	for _, mapping := range p.mappings {
		if !callback(mapping) {
			return 0, process.ErrCallbackStopped
		}
	}
	return 0, p.iterateErr
}

func (p processWithExecutable) OpenMappingFile(
	*process.RawMapping,
) (process.ReadAtCloser, error) {
	if p.mappingOpenErr != nil {
		return nil, p.mappingOpenErr
	}
	return nil, errors.New("mapping open not configured by test")
}

func memoryMetricValue(values []metrics.Metric, id metrics.MetricID) metrics.MetricValue {
	for _, value := range values {
		if value.ID == id {
			return value.Value
		}
	}
	return 0
}

type recordingInjector struct {
	calls              int
	expectedExecutable libpf.String
	result             InjectionResult
	err                error
}

func (i *recordingInjector) Inject(_ libpf.PID,
	expectedExecutable libpf.String,
) (InjectionResult, error) {
	i.calls++
	i.expectedExecutable = expectedExecutable
	return i.result, i.err
}

type blockingFailInjector struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (i *blockingFailInjector) Inject(libpf.PID, libpf.String) (InjectionResult, error) {
	if i.calls.Add(1) == 1 {
		close(i.started)
		<-i.release
	}
	return InjectionResult{}, errors.New("synthetic concurrent mutation failure")
}

func TestManagerProcessSelector(t *testing.T) {
	manager := &Manager{config: Config{
		ProcessExecutablePatterns: []string{"ruby*", "/opt/tarantool/*"},
	}}

	matched, executable, err := manager.matchesProcess(processWithExecutable{
		executable: libpf.Intern("/usr/bin/ruby3.3"),
	})
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Equal(t, libpf.Intern("/usr/bin/ruby3.3"), executable)

	matched, executable, err = manager.matchesProcess(processWithExecutable{
		executable: libpf.Intern("/usr/bin/python3"),
	})
	require.NoError(t, err)
	assert.False(t, matched)
	assert.Equal(t, libpf.Intern("/usr/bin/python3"), executable)
}

func TestReconcilePreservesAttachmentsOnMappingIterationError(t *testing.T) {
	manager := &Manager{config: Config{Enabled: true}}
	inst := NewInstance(1234)
	key := AttachmentKey{PID: 1234, Event: EventAllocation, Offset: 0x10}
	inst.attached[key] = AttachedHook{Key: key}

	got, err := manager.Reconcile(1234, processWithExecutable{
		executable: libpf.Intern("/usr/bin/ruby"),
		iterateErr: errors.New("synthetic partial mapping view"),
	}, inst)
	require.ErrorContains(t, err, "synthetic partial mapping view")
	assert.Same(t, inst, got)
	assert.Contains(t, inst.attached, key,
		"a partial mapping view is not evidence that an existing hook disappeared")
}

func TestReconcileDetachesAttachmentsWhenSelectorNoLongerMatches(t *testing.T) {
	manager := &Manager{config: Config{
		Enabled:                   true,
		ProcessExecutablePatterns: []string{"ruby"},
	}}
	inst := NewInstance(1234)
	key := AttachmentKey{PID: 1234, Event: EventAllocation, Offset: 0x10}
	inst.attached[key] = AttachedHook{Key: key}

	got, err := manager.Reconcile(1234, processWithExecutable{
		executable: libpf.Intern("/usr/bin/python"),
	}, inst)
	require.NoError(t, err)
	assert.Same(t, inst, got)
	assert.Empty(t, inst.attached)
	evaluated, eligible := inst.Applicability()
	assert.True(t, evaluated)
	assert.False(t, eligible)
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

func TestAttachmentLifecycleOrder(t *testing.T) {
	assert.Equal(t, [2]EventKind{EventAllocation, EventDeallocation}, attachmentOrder(false))
	assert.Equal(t, [2]EventKind{EventDeallocation, EventAllocation}, attachmentOrder(true))
	assert.Equal(t, [2]EventKind{EventAllocation, EventDeallocation}, detachmentOrder())
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
	assert.Nil(t, manager.injector, "disabled injection never constructs an injector")
	assert.Nil(t, manager.GetAndResetMetrics(),
		"ordinary memory profiling must not report injector-only metrics")
	_, err = manager.Reconcile(1234,
		processWithExecutable{executable: libpf.Intern("/usr/bin/ruby")}, nil)
	require.NoError(t, err)
	assert.Nil(t, manager.GetAndResetMetrics(),
		"ordinary reconciliation must not report injector-only metrics")
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

func TestBeginInjectionRechecksAttachedProducer(t *testing.T) {
	inst := NewInstance(1234)
	inst.attached[AttachmentKey{Event: EventAllocation}] = AttachedHook{}

	assert.False(t, inst.beginInjectionIfNoAllocation())
	assert.False(t, inst.injectionAttempted,
		"a concurrently attached producer must suppress destructive mutation")
}

func TestReconcileExperimentalInjectionPolicy(t *testing.T) {
	for _, test := range []struct {
		name          string
		result        InjectionResult
		outcomeMetric metrics.MetricID
	}{
		{
			name: "does not retry a successful injection", result: InjectionResult{GOTMallocPatched: true},
			outcomeMetric: metrics.IDHeapInjectionSuccesses,
		},
		{
			name: "does not retry an already-present shim", result: InjectionResult{AlreadyPresent: true},
			outcomeMetric: metrics.IDHeapInjectionAlreadyPresent,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			injector := &recordingInjector{result: test.result}
			manager := &Manager{config: Config{
				Enabled: true, ProcessExecutablePatterns: []string{"/usr/bin/ruby"},
			}, injector: injector}
			pr := processWithExecutable{executable: libpf.Intern("/usr/bin/ruby")}

			inst, err := manager.Reconcile(1234, pr, nil)
			require.NoError(t, err)
			require.Equal(t, 1, injector.calls)
			assert.Equal(t, libpf.Intern("/usr/bin/ruby"), injector.expectedExecutable)

			_, err = manager.Reconcile(1234, pr, inst)
			require.NoError(t, err)
			assert.Equal(t, 1, injector.calls, "a completed PID mutation is never retried")

			gotMetrics := manager.GetAndResetMetrics()
			assert.Equal(t, metrics.MetricValue(1),
				memoryMetricValue(gotMetrics, metrics.IDHeapInjectionAttempts))
			assert.Equal(t, metrics.MetricValue(1),
				memoryMetricValue(gotMetrics, test.outcomeMetric))
			assert.Zero(t, memoryMetricValue(gotMetrics, metrics.IDHeapInjectionHalted))
			outcomes := memoryMetricValue(gotMetrics, metrics.IDHeapInjectionSuccesses) +
				memoryMetricValue(gotMetrics, metrics.IDHeapInjectionFailures) +
				memoryMetricValue(gotMetrics, metrics.IDHeapInjectionAlreadyPresent)
			assert.Equal(t, memoryMetricValue(gotMetrics, metrics.IDHeapInjectionAttempts),
				outcomes, "settled attempts must each have one terminal outcome")
			assert.Equal(t, metrics.MetricValue(0),
				memoryMetricValue(manager.GetAndResetMetrics(), metrics.IDHeapInjectionAttempts),
				"injection counters must reset after collection")
		})
	}

	t.Run("halts all injection after a failed partial mutation", func(t *testing.T) {
		injector := &recordingInjector{
			result: InjectionResult{GOTMallocPatched: true},
			err:    errors.New("synthetic mutation failure"),
		}
		manager := &Manager{
			config:   Config{Enabled: true},
			injector: injector,
		}
		pr := processWithExecutable{executable: libpf.Intern("/usr/bin/ruby")}

		inst, err := manager.Reconcile(1234, pr, nil)
		require.ErrorContains(t, err, "synthetic mutation failure")
		require.Equal(t, 1, injector.calls)
		assert.True(t, manager.injectionHalted.Load())

		_, err = manager.Reconcile(1234, pr, inst)
		require.NoError(t, err)
		assert.Equal(t, 1, injector.calls, "a failed PID mutation is never retried")

		haltedInst, err := manager.Reconcile(5678, pr, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, injector.calls,
			"a failure must halt destructive mutation of every later PID")
		assert.False(t, haltedInst.injectionAttempted)

		gotMetrics := manager.GetAndResetMetrics()
		assert.Equal(t, metrics.MetricValue(1),
			memoryMetricValue(gotMetrics, metrics.IDHeapInjectionAttempts))
		assert.Equal(t, metrics.MetricValue(1),
			memoryMetricValue(gotMetrics, metrics.IDHeapInjectionFailures))
		assert.Equal(t, metrics.MetricValue(1),
			memoryMetricValue(gotMetrics, metrics.IDHeapInjectionHalted))
		outcomes := memoryMetricValue(gotMetrics, metrics.IDHeapInjectionSuccesses) +
			memoryMetricValue(gotMetrics, metrics.IDHeapInjectionFailures) +
			memoryMetricValue(gotMetrics, metrics.IDHeapInjectionAlreadyPresent)
		assert.Equal(t, memoryMetricValue(gotMetrics, metrics.IDHeapInjectionAttempts),
			outcomes, "settled attempts must each have one terminal outcome")
		resetMetrics := manager.GetAndResetMetrics()
		for _, id := range []metrics.MetricID{
			metrics.IDHeapInjectionAttempts,
			metrics.IDHeapInjectionSuccesses,
			metrics.IDHeapInjectionFailures,
			metrics.IDHeapInjectionKilledTargets,
			metrics.IDHeapInjectionAlreadyPresent,
			metrics.IDHeapInjectionProbeDiscoveryFailures,
		} {
			assert.Zero(t, memoryMetricValue(resetMetrics, id),
				"injection counter %d must reset after collection", id)
		}
		assert.Equal(t, metrics.MetricValue(1),
			memoryMetricValue(resetMetrics, metrics.IDHeapInjectionHalted),
			"halted is a persistent gauge, not an interval counter")
	})

	t.Run("reports a fail-closed target termination", func(t *testing.T) {
		injector := &recordingInjector{
			err: errors.Join(errUnsafeTraceeTerminated,
				errors.New("synthetic target termination")),
		}
		manager := &Manager{config: Config{Enabled: true}, injector: injector}
		pr := processWithExecutable{executable: libpf.Intern("/usr/bin/ruby")}

		_, err := manager.Reconcile(1234, pr, nil)
		require.ErrorContains(t, err, "synthetic target termination")
		gotMetrics := manager.GetAndResetMetrics()
		assert.Equal(t, metrics.MetricValue(1),
			memoryMetricValue(gotMetrics, metrics.IDHeapInjectionFailures))
		assert.Equal(t, metrics.MetricValue(1),
			memoryMetricValue(gotMetrics, metrics.IDHeapInjectionKilledTargets))
		assert.Equal(t, metrics.MetricValue(1),
			memoryMetricValue(gotMetrics, metrics.IDHeapInjectionHalted))
	})

	t.Run("a concurrent failure halts queued injection", func(t *testing.T) {
		injector := &blockingFailInjector{
			started: make(chan struct{}),
			release: make(chan struct{}),
		}
		manager := &Manager{config: Config{Enabled: true}, injector: injector}
		pr := processWithExecutable{executable: libpf.Intern("/usr/bin/ruby")}

		type reconcileResult struct {
			inst *Instance
			err  error
		}
		firstResult := make(chan reconcileResult, 1)
		secondResult := make(chan reconcileResult, 1)
		go func() {
			inst, err := manager.Reconcile(1234, pr, nil)
			firstResult <- reconcileResult{inst: inst, err: err}
		}()
		<-injector.started
		go func() {
			inst, err := manager.Reconcile(5678, pr, nil)
			secondResult <- reconcileResult{inst: inst, err: err}
		}()
		close(injector.release)

		first := <-firstResult
		require.ErrorContains(t, first.err, "synthetic concurrent mutation failure")
		second := <-secondResult
		require.NoError(t, second.err)
		require.NotNil(t, second.inst)
		assert.False(t, second.inst.injectionAttempted)
		assert.Equal(t, int32(1), injector.calls.Load(),
			"a queued PID must recheck the global halt under the injection lock")
	})

	t.Run("records injected shim discovery failure once per PID", func(t *testing.T) {
		cache, err := lru.NewSynced[util.OnDiskFileIdentifier, parsedFile](
			8, util.OnDiskFileIdentifier.Hash32)
		require.NoError(t, err)
		injector := &recordingInjector{result: InjectionResult{GOTMallocPatched: true}}
		manager := &Manager{
			config:     Config{Enabled: true},
			needsUSDT:  true,
			parseCache: cache,
			injector:   injector,
		}
		initial := processWithExecutable{executable: libpf.Intern("/usr/bin/ruby")}
		inst, err := manager.Reconcile(1234, initial, nil)
		require.NoError(t, err)
		require.Equal(t, 1, injector.calls)

		unreadableShim := processWithExecutable{
			executable:     libpf.Intern("/usr/bin/ruby"),
			mappingOpenErr: os.ErrPermission,
			mappings: []process.RawMapping{{
				Vaddr: 0x1000, Length: 0x1000, Flags: elf.PF_R | elf.PF_X,
				Device: 1, Inode: 2, Path: "/memfd:prophiler-heap-shim (deleted)",
			}},
		}
		_, err = manager.Reconcile(1234, unreadableShim, inst)
		require.ErrorIs(t, err, os.ErrPermission)
		_, err = manager.Reconcile(1234, unreadableShim, inst)
		require.ErrorIs(t, err, os.ErrPermission)

		gotMetrics := manager.GetAndResetMetrics()
		assert.Equal(t, metrics.MetricValue(1), memoryMetricValue(
			gotMetrics, metrics.IDHeapInjectionProbeDiscoveryFailures))
		assert.Equal(t, metrics.MetricValue(1), memoryMetricValue(
			gotMetrics, metrics.IDHeapInjectionAttempts))
		assert.Equal(t, metrics.MetricValue(1), memoryMetricValue(
			gotMetrics, metrics.IDHeapInjectionSuccesses))
	})

	t.Run("mapping scan failure suppresses injection", func(t *testing.T) {
		cache, err := lru.NewSynced[util.OnDiskFileIdentifier, parsedFile](
			8, util.OnDiskFileIdentifier.Hash32)
		require.NoError(t, err)
		injector := &recordingInjector{}
		manager := &Manager{
			config:     Config{Enabled: true},
			needsUSDT:  true,
			parseCache: cache,
			injector:   injector,
		}
		pr := processWithExecutable{
			executable:     libpf.Intern("/usr/bin/ruby"),
			mappingOpenErr: os.ErrPermission,
			mappings: []process.RawMapping{{
				Vaddr: 0x1000, Length: 0x1000, Flags: elf.PF_R | elf.PF_X,
				Device: 1, Inode: 2, Path: "/opt/lib/libexisting-producer.so",
			}},
		}

		inst, err := manager.Reconcile(1234, pr, nil)
		require.ErrorIs(t, err, os.ErrPermission)
		assert.Zero(t, injector.calls)
		assert.False(t, inst.injectionAttempted)
		gotMetrics := manager.GetAndResetMetrics()
		for _, id := range []metrics.MetricID{
			metrics.IDHeapInjectionAttempts,
			metrics.IDHeapInjectionSuccesses,
			metrics.IDHeapInjectionFailures,
			metrics.IDHeapInjectionKilledTargets,
			metrics.IDHeapInjectionAlreadyPresent,
			metrics.IDHeapInjectionProbeDiscoveryFailures,
		} {
			assert.Zero(t, memoryMetricValue(gotMetrics, id),
				"scan suppression must not increment injection counter %d", id)
		}
	})

	t.Run("discovered memfd producer prevents injection", func(t *testing.T) {
		cache, err := lru.NewSynced[util.OnDiskFileIdentifier, parsedFile](
			8, util.OnDiskFileIdentifier.Hash32)
		require.NoError(t, err)
		fileID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
		cache.Add(fileID, parsedFile{usdtNotes: []usdtNote{{
			Provider: ExperimentalShimProvider, Name: "alloc",
			Location: 0x100, SemaphoreOffset: 0x20,
		}}})
		weighted := Hook{
			Type: HookTypeUSDT, ABI: ABIWeightedAllocation,
			Provider: ExperimentalShimProvider, Name: "alloc",
		}
		injector := &recordingInjector{}
		manager := &Manager{
			config:     Config{Enabled: true},
			hooks:      []configuredHook{{id: 1, event: EventAllocation, hook: weighted}},
			needsUSDT:  true,
			parseCache: cache,
			injector:   injector,
		}
		pr := processWithExecutable{
			executable: libpf.Intern("/usr/bin/ruby"),
			mappings: []process.RawMapping{{
				Vaddr: 0x1000, Length: 0x1000, Flags: elf.PF_R | elf.PF_X,
				Device: fileID.DeviceID, Inode: fileID.InodeNum,
				Path: "/memfd:prophiler-heap-shim (deleted)",
			}},
		}

		_, err = manager.Reconcile(999999, pr, nil)
		require.ErrorContains(t, err, "attach")
		assert.Zero(t, injector.calls,
			"producer discovery must suppress mutation even when attachment fails")
	})
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
