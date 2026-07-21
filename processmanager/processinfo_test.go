package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/liveheap"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/probes/memory"
	"go.opentelemetry.io/ebpf-profiler/process"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type TestInstance struct {
	interpreter.InstanceStubs
	info                  libc.LibcInfo
	syncMappings          []process.RawMapping
	usesAnonymousMappings bool
}

func (ti *TestInstance) UpdateLibcInfo(_ interpreter.EbpfHandler, _ libpf.PID, info libc.LibcInfo) error {
	ti.info = info
	return nil
}

func (ti *TestInstance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}

func (ti *TestInstance) UsesAnonymousMappings() bool {
	return ti.usesAnonymousMappings
}

func (ti *TestInstance) SynchronizeMappings(_ interpreter.EbpfHandler,
	_ reporter.ExecutableReporter, _ process.Process, mappings []process.RawMapping,
) error {
	ti.syncMappings = append([]process.RawMapping(nil), mappings...)
	return nil
}

type testInterpreterData struct {
	attach func(interpreter.EbpfHandler, libpf.PID, libpf.Address, remotememory.RemoteMemory) (
		interpreter.Instance, error)
}

func (td *testInterpreterData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	return td.attach(ebpf, pid, bias, rm)
}

func (td *testInterpreterData) Unload(interpreter.EbpfHandler) {}

type testEbpfHandler struct {
	removedReportedPIDs       []libpf.PID
	pidPageMappingInfoUpdates []struct {
		pid    libpf.PID
		prefix lpm.Prefix
		fileID uint64
		bias   uint64
	}
	heapLivePIDUpdates []struct {
		pid     libpf.PID
		enabled bool
	}
	heapLivePIDErr           error
	heapPIDAllocCountDeletes []libpf.PID
	heapPIDAllocCountErr     error
	heapCleanupOperations    []string
	heapDeleteStarted        chan struct{}
	heapDeleteRelease        chan struct{}
	heapDeletePanic          bool
	heapDeleteErr            error
	heapAllocLiveDeletes     []struct {
		pid  libpf.PID
		ptrs []uint64
	}
}

func (h *testEbpfHandler) UpdateInterpreterOffsets(uint16, host.FileID, []util.Range) error {
	return nil
}

func (h *testEbpfHandler) UpdateProcData(libpf.InterpreterType, libpf.PID, unsafe.Pointer) error {
	return nil
}

func (h *testEbpfHandler) DeleteProcData(libpf.InterpreterType, libpf.PID) error {
	return nil
}

func (h *testEbpfHandler) UpdatePidInterpreterMapping(
	libpf.PID, lpm.Prefix, uint8, host.FileID, uint64,
) error {
	return nil
}

func (h *testEbpfHandler) DeletePidInterpreterMapping(libpf.PID, lpm.Prefix) error {
	return nil
}

func (h *testEbpfHandler) RemoveReportedPID(pid libpf.PID) {
	h.removedReportedPIDs = append(h.removedReportedPIDs, pid)
}

func (h *testEbpfHandler) CoredumpTest() bool { return false }

func (h *testEbpfHandler) UpdateUnwindInfo(uint16, sdtypes.UnwindInfo) error {
	return nil
}

func (h *testEbpfHandler) UpdateExeIDToStackDeltas(
	host.FileID, []pmebpf.StackDeltaEBPF,
) (uint16, error) {
	return 0, nil
}

func (h *testEbpfHandler) DeleteExeIDToStackDeltas(host.FileID, uint16) error {
	return nil
}

func (h *testEbpfHandler) UpdateStackDeltaPages(host.FileID, []uint16, uint16, uint64) error {
	return nil
}

func (h *testEbpfHandler) DeleteStackDeltaPage(host.FileID, uint64) error {
	return nil
}

func (h *testEbpfHandler) UpdatePidPageMappingInfo(pid libpf.PID, prefix lpm.Prefix,
	fileID, bias uint64,
) error {
	h.pidPageMappingInfoUpdates = append(h.pidPageMappingInfoUpdates, struct {
		pid    libpf.PID
		prefix lpm.Prefix
		fileID uint64
		bias   uint64
	}{pid: pid, prefix: prefix, fileID: fileID, bias: bias})
	return nil
}

func (h *testEbpfHandler) DeletePidPageMappingInfo(libpf.PID, []lpm.Prefix) (uint64, error) {
	return 0, nil
}

func (h *testEbpfHandler) CollectMetrics() []metrics.Metric {
	return nil
}

func (h *testEbpfHandler) SupportsLPMTrieBatchOperations() bool {
	return false
}

func (h *testEbpfHandler) SetHeapLivePID(pid libpf.PID, enabled bool) error {
	h.heapLivePIDUpdates = append(h.heapLivePIDUpdates, struct {
		pid     libpf.PID
		enabled bool
	}{pid: pid, enabled: enabled})
	return h.heapLivePIDErr
}

func (h *testEbpfHandler) DeleteHeapAllocLiveEntries(pid libpf.PID, ptrs []uint64) error {
	if h.heapDeleteStarted != nil {
		close(h.heapDeleteStarted)
		<-h.heapDeleteRelease
	}
	if h.heapDeletePanic {
		panic("synthetic heap map cleanup panic")
	}
	h.heapCleanupOperations = append(h.heapCleanupOperations, "live entries")
	h.heapAllocLiveDeletes = append(h.heapAllocLiveDeletes, struct {
		pid  libpf.PID
		ptrs []uint64
	}{pid: pid, ptrs: append([]uint64(nil), ptrs...)})
	return h.heapDeleteErr
}

func (h *testEbpfHandler) DeleteHeapPIDAllocCount(pid libpf.PID) error {
	h.heapCleanupOperations = append(h.heapCleanupOperations, "PID count")
	h.heapPIDAllocCountDeletes = append(h.heapPIDAllocCountDeletes, pid)
	return h.heapPIDAllocCountErr
}

func (h *testEbpfHandler) SetHeapPIDAllocLimit(uint32)    {}
func (h *testEbpfHandler) SetHeapSamplingInterval(uint32) {}

type testProcess struct {
	pid           libpf.PID
	exe           libpf.String
	mappings      []process.RawMapping
	beforeIterate func()
}

func (tp *testProcess) PID() libpf.PID {
	return tp.pid
}

func (tp *testProcess) TID() libpf.PID {
	return tp.pid
}

func (tp *testProcess) GetMachineData() process.MachineData {
	return process.MachineData{}
}

func (tp *testProcess) GetProcessMeta(process.MetaConfig) process.ProcessMeta {
	return process.ProcessMeta{}
}

func (tp *testProcess) GetExe() (libpf.String, error) {
	return tp.exe, nil
}

func (tp *testProcess) IterateMappings(callback func(process.RawMapping) bool) (uint32, error) {
	if tp.beforeIterate != nil {
		tp.beforeIterate()
	}
	for _, m := range tp.mappings {
		if !callback(m) {
			return 0, process.ErrCallbackStopped
		}
	}
	return 0, nil
}

func (tp *testProcess) GetThreads() ([]process.ThreadInfo, error) {
	return nil, nil
}

func (tp *testProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{}
}

func (tp *testProcess) OpenMappingFile(*process.RawMapping) (process.ReadAtCloser, error) {
	return nil, errors.New("not implemented")
}

func (tp *testProcess) GetMappingFileLastModified(*process.RawMapping) int64 {
	return 0
}

func (tp *testProcess) CalculateMappingFileID(*process.RawMapping) (libpf.FileID, error) {
	return libpf.FileID{}, errors.New("not implemented")
}

func (tp *testProcess) Close() error {
	return nil
}

func (tp *testProcess) OpenELF(string) (*pfelf.File, error) {
	return nil, errors.New("not implemented")
}

func TestAssignLibcInfoMergesLibcInfo(t *testing.T) {
	assert := assert.New(t)

	pid := libpf.PID(1)
	odid := util.OnDiskFileIdentifier{
		DeviceID: 1,
		InodeNum: 1,
	}

	interp := TestInstance{}

	pm := ProcessManager{
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				odid: &interp,
			},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {},
		},
	}

	libcInfoWithTSD := libc.LibcInfo{
		TSDInfo: libc.TSDInfo{
			Offset:     8,
			Multiplier: 8,
			Indirect:   0,
		},
		DTVInfo: libc.DTVInfo{},
	}
	pm.assignLibcInfo(pid, &libcInfoWithTSD)

	assert.Equal(libcInfoWithTSD, interp.info)

	libcInfoWithDTV := libc.LibcInfo{
		TSDInfo: libc.TSDInfo{},
		DTVInfo: libc.DTVInfo{
			Offset:     -8,
			Multiplier: 16,
		},
	}

	merged := libcInfoWithTSD
	merged.Merge(libcInfoWithDTV)

	pm.assignLibcInfo(pid, &libcInfoWithDTV)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)

	pm.assignLibcInfo(pid, &merged)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)
}

func TestHandleNewInterpreterRecordsAnonymousMappingInterestLocally(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	pm := &ProcessManager{
		ebpf:             &testEbpfHandler{},
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			return &TestInstance{usesAnonymousMappings: true}, nil
		},
	}

	anonymousMappingsWanted, err := pm.handleNewInterpreter(
		process.New(pid, pid), 0, oid, data, false)
	require.NoError(err)
	require.Contains(pm.interpreters[pid], oid)
	require.True(anonymousMappingsWanted)
}

func TestHandleNewInterpreterDoesNotAssignOnAttachFailure(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	attachErr := errors.New("attach failed")
	pm := &ProcessManager{
		ebpf:             &testEbpfHandler{},
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			return nil, attachErr
		},
	}

	anonymousMappingsWanted, err := pm.handleNewInterpreter(
		process.New(pid, pid), 0, oid, data, false)
	require.ErrorIs(err, attachErr)
	require.False(anonymousMappingsWanted)
	require.NotContains(pm.interpreters, pid)
}

func TestHandleNewInterpreterKeepsExistingInterpreter(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oldOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	newOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	pm := &ProcessManager{
		ebpf: &testEbpfHandler{},
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oldOID: &TestInstance{usesAnonymousMappings: true}},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			return &TestInstance{usesAnonymousMappings: true}, nil
		},
	}

	anonymousMappingsWanted, err := pm.handleNewInterpreter(
		process.New(pid, pid), 0, newOID, data, true)
	require.NoError(err)
	require.Contains(pm.interpreters[pid], oldOID)
	require.Contains(pm.interpreters[pid], newOID)
	require.True(anonymousMappingsWanted)
}

func TestProcessRemovedInterpretersClearsAnonymousMappingInterest(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: &TestInstance{usesAnonymousMappings: true}},
		},
	}

	anonymousMappingsWanted := pm.processRemovedInterpreters(
		pid, libpf.Set[util.OnDiskFileIdentifier]{})

	require.NotContains(pm.interpreters, pid)
	require.False(anonymousMappingsWanted)
}

func TestProcessRemovedInterpretersKeepsAnonymousMappingInterestWhenInterpreterRemains(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	keptOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	removedOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				keptOID:    &TestInstance{usesAnonymousMappings: true},
				removedOID: &TestInstance{usesAnonymousMappings: true},
			},
		},
	}

	anonymousMappingsWanted := pm.processRemovedInterpreters(pid,
		libpf.Set[util.OnDiskFileIdentifier]{keptOID: libpf.Void{}})

	require.Contains(pm.interpreters[pid], keptOID)
	require.NotContains(pm.interpreters[pid], removedOID)
	require.True(anonymousMappingsWanted)
}

func TestProcessPIDExitRemovesInterpreters(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				{DeviceID: 1, InodeNum: 2}: &TestInstance{usesAnonymousMappings: true},
			},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
		exitEvents:       make(map[libpf.PID]times.KTime),
	}

	pm.processPIDExit(pid)
	require.NotContains(pm.interpreters, pid)
}

func TestPublishMemoryProbeStateRejectsExitingGeneration(t *testing.T) {
	pid := libpf.PID(123)
	instance := memory.NewInstance(pid)
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                 ebpf,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {}},
		exitEvents:           map[libpf.PID]times.KTime{pid: 1},
		memoryProbeInstances: map[libpf.PID]*memory.Instance{pid: instance},
		liveHeapTracker:      liveheap.NewTracker(0),
	}

	assert.False(t, pm.publishMemoryProbeState(pid, instance))
	assert.NotContains(t, pm.memoryProbeInstances, pid)
	assert.Empty(t, ebpf.heapLivePIDUpdates,
		"a stale reconciliation must not re-enable live tracking after exit")
}

func TestPublishMemoryProbeStatePreservesExecInjectionGuard(t *testing.T) {
	pid := libpf.PID(123)
	instance := memory.NewInstance(pid)
	pm := &ProcessManager{
		ebpf:                 &testEbpfHandler{},
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {}},
		exitEvents:           make(map[libpf.PID]times.KTime),
		heapCleanupPending:   map[libpf.PID]struct{}{pid: {}},
		memoryProbeInstances: map[libpf.PID]*memory.Instance{pid: instance},
		liveHeapTracker:      liveheap.NewTracker(0),
	}

	assert.False(t, pm.publishMemoryProbeState(pid, instance))
	assert.Same(t, instance, pm.memoryProbeInstances[pid],
		"exec cleanup must retain the Instance and its one-shot injection guard")
}

func TestDeleteHeapLiveStatePreservesCountOnPointerCleanupFailure(t *testing.T) {
	ebpf := &testEbpfHandler{heapDeleteErr: errors.New("synthetic delete failure")}
	pm := &ProcessManager{ebpf: ebpf}

	assert.False(t, pm.deleteHeapLiveState(123, []uint64{0xdeadbeef}))
	assert.Empty(t, ebpf.heapPIDAllocCountDeletes,
		"clearing the count after pointer cleanup fails would corrupt PID reuse")
	assert.Equal(t, []string{"live entries"}, ebpf.heapCleanupOperations)
}

func TestDeleteHeapLiveStateReportsCountCleanupFailure(t *testing.T) {
	ebpf := &testEbpfHandler{heapPIDAllocCountErr: errors.New("synthetic count delete failure")}
	pm := &ProcessManager{ebpf: ebpf}

	assert.False(t, pm.deleteHeapLiveState(123, []uint64{0xdeadbeef}))
	assert.Equal(t, []string{"live entries", "PID count"}, ebpf.heapCleanupOperations)
	assert.Equal(t, []libpf.PID{123}, ebpf.heapPIDAllocCountDeletes)
}

func TestPublishMemoryProbeStateCleansLiveStateWhenFreeHookIsLost(t *testing.T) {
	pid := libpf.PID(123)
	instance := memory.NewInstance(pid)
	ebpf := &testEbpfHandler{}
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupport(pid, true)
	tracker.HandleAlloc(pid, 0xdeadbeef, libpf.NewTraceHash(0, 1), 100, nil)
	pm := &ProcessManager{
		ebpf:                 ebpf,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {}},
		exitEvents:           make(map[libpf.PID]times.KTime),
		heapCleanupPending:   make(map[libpf.PID]struct{}),
		memoryProbeInstances: map[libpf.PID]*memory.Instance{pid: instance},
		liveHeapTracker:      tracker,
	}

	assert.True(t, pm.publishMemoryProbeState(pid, instance))
	assert.Empty(t, tracker.Snapshot(),
		"allocations cannot remain live after their free producer detaches")
	assert.Equal(t, []string{"live entries", "PID count"}, ebpf.heapCleanupOperations)
	assert.Same(t, instance, pm.memoryProbeInstances[pid])
	require.Len(t, ebpf.heapLivePIDUpdates, 1)
	assert.False(t, ebpf.heapLivePIDUpdates[0].enabled)
}

func TestProcessPIDExitCleansLiveHeapState(t *testing.T) {
	pid := libpf.PID(123)
	const ptr = uint64(0xdeadbeef)
	ebpf := &testEbpfHandler{}
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupport(pid, true)
	tracker.HandleAlloc(pid, ptr, libpf.NewTraceHash(0, 1), 100, nil)
	require.Equal(t, 1, tracker.LiveCount())
	pm := &ProcessManager{
		ebpf:                 ebpf,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {}},
		exitEvents:           make(map[libpf.PID]times.KTime),
		interpreters:         make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		memoryProbeInstances: map[libpf.PID]*memory.Instance{pid: memory.NewInstance(pid)},
		liveHeapTracker:      tracker,
		cleanupSem:           make(chan struct{}, 1),
	}

	pm.processPIDExit(pid)
	pm.cleanupWG.Wait()

	assert.Zero(t, tracker.LiveCount())
	assert.NotContains(t, pm.memoryProbeInstances, pid,
		"a reused PID must not inherit probe applicability or injection state")
	assert.Equal(t, []struct {
		pid     libpf.PID
		enabled bool
	}{{pid: pid, enabled: false}}, ebpf.heapLivePIDUpdates)
	assert.Equal(t, []libpf.PID{pid}, ebpf.heapPIDAllocCountDeletes)
	assert.Equal(t, []string{"live entries", "PID count"}, ebpf.heapCleanupOperations,
		"stale pointer keys must be deleted before the per-PID count")
	require.Len(t, ebpf.heapAllocLiveDeletes, 1)
	assert.Equal(t, pid, ebpf.heapAllocLiveDeletes[0].pid)
	assert.Equal(t, []uint64{ptr}, ebpf.heapAllocLiveDeletes[0].ptrs)
}

func TestProcessPIDExitSkipsHeapMapScanForUnsupportedPID(t *testing.T) {
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                 ebpf,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {}},
		exitEvents:           make(map[libpf.PID]times.KTime),
		interpreters:         make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		liveHeapTracker:      liveheap.NewTracker(0),
		memoryProbeInstances: make(map[libpf.PID]*memory.Instance),
	}

	pm.processPIDExit(pid)

	assert.Empty(t, ebpf.heapAllocLiveDeletes,
		"unrelated process exits must not scan the global live-allocation map")
	assert.Empty(t, ebpf.heapPIDAllocCountDeletes)
}

func TestProcessPIDExitScansHeapMapWithoutTrackedPointers(t *testing.T) {
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{}
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupport(pid, true)
	pm := &ProcessManager{
		ebpf:                 ebpf,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {}},
		exitEvents:           make(map[libpf.PID]times.KTime),
		interpreters:         make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		liveHeapTracker:      tracker,
		memoryProbeInstances: make(map[libpf.PID]*memory.Instance),
	}

	pm.processPIDExit(pid)

	require.Len(t, ebpf.heapAllocLiveDeletes, 1,
		"process exit must scan eBPF state even when no allocation record reached userspace")
	assert.Equal(t, pid, ebpf.heapAllocLiveDeletes[0].pid)
	assert.Empty(t, ebpf.heapAllocLiveDeletes[0].ptrs)
	assert.Equal(t, []string{"live entries", "PID count"}, ebpf.heapCleanupOperations)
}

func TestProcessPIDExitRetainsBarrierWhenLiveDisableFails(t *testing.T) {
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{heapLivePIDErr: errors.New("synthetic disable failure")}
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupport(pid, true)
	pm := &ProcessManager{
		ebpf:                 ebpf,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {}},
		exitEvents:           make(map[libpf.PID]times.KTime),
		interpreters:         make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		liveHeapTracker:      tracker,
		memoryProbeInstances: make(map[libpf.PID]*memory.Instance),
		heapCleanupPending:   make(map[libpf.PID]struct{}),
	}

	pm.processPIDExit(pid)

	assert.Contains(t, pm.heapCleanupPending, pid)
	assert.Empty(t, ebpf.heapAllocLiveDeletes)
	assert.Empty(t, ebpf.heapPIDAllocCountDeletes)
	pm.ProcessedUntil(times.GetKTime())
	assert.Contains(t, pm.pidToProcessInfo, pid,
		"PID generation must remain tombstoned when insertion could not be disabled")
}

func TestProcessPIDExitCleanupPanicLeavesManagerMutexUsable(t *testing.T) {
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{heapDeletePanic: true}
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupport(pid, true)
	pm := &ProcessManager{
		ebpf:                 ebpf,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {}},
		exitEvents:           make(map[libpf.PID]times.KTime),
		interpreters:         make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		liveHeapTracker:      tracker,
		memoryProbeInstances: make(map[libpf.PID]*memory.Instance),
	}

	assert.PanicsWithValue(t, "synthetic heap map cleanup panic", func() {
		pm.processPIDExit(pid)
	})
	pm.mu.Lock()
	pm.mu.Unlock()
	assert.Contains(t, pm.heapCleanupPending, pid,
		"panic recovery must fail closed for the affected PID generation")
	pm.ProcessedUntil(times.GetKTime())
	assert.Contains(t, pm.pidToProcessInfo, pid,
		"a cleanup panic must not release the PID generation for reuse")
}

func TestResetMemoryProbeStateForExecClearsOldAddressSpace(t *testing.T) {
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{}
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupport(pid, true)
	tracker.HandleAlloc(pid, 0xdeadbeef, libpf.NewTraceHash(0, 1), 100, nil)
	previous := memory.NewInstance(pid)
	pm := &ProcessManager{
		ebpf:                 ebpf,
		memoryProbeInstances: map[libpf.PID]*memory.Instance{pid: previous},
		heapCleanupPending:   make(map[libpf.PID]struct{}),
		liveHeapTracker:      tracker,
	}

	assert.True(t, pm.resetMemoryProbeStateForExec(pid))

	assert.Same(t, previous, pm.memoryProbeInstances[pid],
		"exec cleanup must preserve the PID's one-shot injection guard")
	assert.NotContains(t, pm.heapCleanupPending, pid)
	assert.Empty(t, tracker.Snapshot(), "pre-exec allocations belong to the old address space")
	assert.Equal(t, []string{"live entries", "PID count"}, ebpf.heapCleanupOperations)
	require.Len(t, ebpf.heapLivePIDUpdates, 1)
	assert.False(t, ebpf.heapLivePIDUpdates[0].enabled)
}

func TestResetMemoryProbeStateForExecRetainsBarrierOnMapFailure(t *testing.T) {
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{heapDeleteErr: errors.New("synthetic delete failure")}
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupport(pid, true)
	tracker.HandleAlloc(pid, 0xdeadbeef, libpf.NewTraceHash(0, 1), 100, nil)
	pm := &ProcessManager{
		ebpf:                 ebpf,
		memoryProbeInstances: map[libpf.PID]*memory.Instance{pid: memory.NewInstance(pid)},
		heapCleanupPending:   make(map[libpf.PID]struct{}),
		liveHeapTracker:      tracker,
	}

	assert.False(t, pm.resetMemoryProbeStateForExec(pid))
	assert.Contains(t, pm.heapCleanupPending, pid,
		"failed cleanup must block the replacement image from publishing live state")
	assert.Empty(t, ebpf.heapPIDAllocCountDeletes)
}

func TestResetMemoryProbeStateForExecRetainsBarrierOnDisableFailure(t *testing.T) {
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{heapLivePIDErr: errors.New("synthetic disable failure")}
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupport(pid, true)
	tracker.HandleAlloc(pid, 0xdeadbeef, libpf.NewTraceHash(0, 1), 100, nil)
	pm := &ProcessManager{
		ebpf:                 ebpf,
		memoryProbeInstances: map[libpf.PID]*memory.Instance{pid: memory.NewInstance(pid)},
		heapCleanupPending:   make(map[libpf.PID]struct{}),
		liveHeapTracker:      tracker,
	}

	assert.False(t, pm.resetMemoryProbeStateForExec(pid))
	assert.Contains(t, pm.heapCleanupPending, pid)
	assert.Empty(t, ebpf.heapAllocLiveDeletes,
		"pointer cleanup cannot be race-free until kernel insertion is disabled")
	assert.Empty(t, ebpf.heapPIDAllocCountDeletes)
}

func TestSynchronizeProcessDefersMemoryProbesWithoutImageIdentity(t *testing.T) {
	pid := libpf.PID(99_999_999)
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                 ebpf,
		memoryProbeManager:   &memory.Manager{},
		pidToProcessInfo:     make(map[libpf.PID]*processInfo),
		exitEvents:           make(map[libpf.PID]times.KTime),
		interpreters:         make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		memoryProbeInstances: make(map[libpf.PID]*memory.Instance),
		heapCleanupPending:   make(map[libpf.PID]struct{}),
	}

	pm.SynchronizeProcess(&testProcess{pid: pid})
	assert.Contains(t, ebpf.removedReportedPIDs, pid)
	assert.Contains(t, pm.pidToProcessInfo, pid,
		"identity failures must not suppress generic process synchronization")
	assert.NotContains(t, pm.memoryProbeInstances, pid,
		"an unverified process generation must not publish memory hooks")
}

func TestSynchronizeProcessRejectsExecDuringMappingScan(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process image identity is read from Linux procfs")
	}

	cmd := exec.Command("sh", "-c", "read _; exec sleep 30")
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	pid := libpf.PID(cmd.Process.Pid)
	initialIdentity, err := readProcessImageIdentity(pid)
	require.NoError(t, err)
	initialExecutable, err := os.Readlink("/proc/" + stringPID(pid) + "/exe")
	require.NoError(t, err)
	if strings.Contains(initialExecutable, "rosetta") || strings.Contains(initialExecutable, "qemu") {
		t.Skip("userspace architecture emulation masks exec identity in /proc/PID/exe")
	}

	sentinelMappings := []Mapping{{Vaddr: 0x1234, Length: 0x1000}}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:               ebpf,
		memoryProbeManager: &memory.Manager{},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {
			meta:     process.ProcessMeta{Executable: libpf.Intern(initialExecutable)},
			mappings: sentinelMappings, imageIdentity: initialIdentity,
		}},
		exitEvents: make(map[libpf.PID]times.KTime),
	}
	pr := &testProcess{
		pid: pid,
		exe: libpf.Intern(initialExecutable),
		beforeIterate: func() {
			_, writeErr := stdin.Write([]byte("go\n"))
			require.NoError(t, writeErr)
			require.NoError(t, stdin.Close())
			require.Eventually(t, func() bool {
				target, readErr := os.Readlink("/proc/" + stringPID(pid) + "/exe")
				return readErr == nil && strings.HasSuffix(target, "/sleep")
			}, 2*time.Second, time.Millisecond)
		},
	}

	pm.SynchronizeProcess(pr)
	assert.Contains(t, ebpf.removedReportedPIDs, pid)
	require.Equal(t, sentinelMappings, pm.pidToProcessInfo[pid].mappings,
		"a mapping view spanning exec must not replace the prior generation")
	assert.Equal(t, initialIdentity, pm.pidToProcessInfo[pid].imageIdentity)
}

func stringPID(pid libpf.PID) string {
	return fmt.Sprintf("%d", pid)
}

func TestReadProcessImageIdentityIsStable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process image identity is read from Linux procfs")
	}
	first, err := readProcessImageIdentity(libpf.PID(os.Getpid()))
	require.NoError(t, err)
	second, err := readProcessImageIdentity(libpf.PID(os.Getpid()))
	require.NoError(t, err)
	assert.True(t, first.valid)
	assert.NotZero(t, first.processStartTime)
	assert.Equal(t, first, second)
}

func TestProcessPIDExitReleasesManagerLockDuringHeapMapCleanup(t *testing.T) {
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{
		heapDeleteStarted: make(chan struct{}),
		heapDeleteRelease: make(chan struct{}),
	}
	tracker := liveheap.NewTracker(0)
	tracker.SetPIDLiveHeapSupport(pid, true)
	tracker.HandleAlloc(pid, 0xdeadbeef, libpf.NewTraceHash(0, 1), 100, nil)
	pm := &ProcessManager{
		ebpf:                 ebpf,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {}},
		exitEvents:           make(map[libpf.PID]times.KTime),
		heapCleanupPending:   make(map[libpf.PID]struct{}),
		interpreters:         make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		liveHeapTracker:      tracker,
		memoryProbeInstances: make(map[libpf.PID]*memory.Instance),
	}

	exitDone := make(chan struct{})
	go func() {
		pm.processPIDExit(pid)
		close(exitDone)
	}()
	<-ebpf.heapDeleteStarted

	pm.mu.RLock()
	exitKTime := pm.exitEvents[pid]
	_, cleanupPending := pm.heapCleanupPending[pid]
	pm.mu.RUnlock()
	assert.True(t, cleanupPending, "heap cleanup tombstone must protect the PID generation")

	processed := make(chan struct{})
	go func() {
		pm.ProcessedUntil(exitKTime)
		close(processed)
	}()
	select {
	case <-processed:
	case <-time.After(time.Second):
		t.Fatal("heap map cleanup held the process-manager lock")
	}
	assert.Contains(t, pm.exitEvents, pid,
		"ProcessedUntil must retain a PID while heap cleanup is pending")

	close(ebpf.heapDeleteRelease)
	<-exitDone
	pm.ProcessedUntil(exitKTime)
	assert.NotContains(t, pm.exitEvents, pid)
	assert.NotContains(t, pm.pidToProcessInfo, pid)
}

func TestSynchronizeProcessUpdatesAnonymousMappingInterest(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: &TestInstance{usesAnonymousMappings: true}},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
		exitEvents:       make(map[libpf.PID]times.KTime),
	}

	pm.SynchronizeProcess(&testProcess{pid: pid})

	require.Equal([]struct {
		pid    libpf.PID
		prefix lpm.Prefix
		fileID uint64
		bias   uint64
	}{{pid: pid, prefix: dummyPrefix}}, ebpf.pidPageMappingInfoUpdates)
}

func TestSynchronizeProcessSkipsDllMappingsWithoutAnonymousMappingInterest(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	instance := &TestInstance{}
	interpreterMapping := process.RawMapping{
		Vaddr:  0x1000,
		Length: 0x1000,
		Flags:  elf.PF_R | elf.PF_X,
		Device: oid.DeviceID,
		Inode:  oid.InodeNum,
		Path:   "/tmp/interpreter",
	}
	pm := &ProcessManager{
		ebpf:                     &testEbpfHandler{},
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: instance},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {
				mappings: []Mapping{
					{
						Vaddr:  libpf.Address(interpreterMapping.Vaddr),
						Length: interpreterMapping.Length,
						Device: interpreterMapping.Device,
						Inode:  interpreterMapping.Inode,
						FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
							File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
								FileID:   libpf.NewFileID(1, 0),
								FileName: libpf.Intern("interpreter"),
							}),
							Start: 0,
							End:   libpf.Address(interpreterMapping.Length),
						}),
					},
				},
			},
		},
		exitEvents: make(map[libpf.PID]times.KTime),
	}

	pm.SynchronizeProcess(&testProcess{
		pid: pid,
		mappings: []process.RawMapping{
			interpreterMapping,
			{
				Vaddr:  0x3000,
				Length: 0x1000,
				Flags:  elf.PF_R,
				Device: 3,
				Inode:  4,
				Path:   "/tmp/assembly.dll",
			},
		},
	})

	require.Empty(instance.syncMappings)
}

func TestIsInterpreterMapping(t *testing.T) {
	tests := []struct {
		name string
		m    process.RawMapping
		want bool
	}{
		{
			name: "anonymous executable",
			m:    process.RawMapping{Flags: elf.PF_R | elf.PF_X},
			want: true,
		},
		{
			name: "anonymous non-executable",
			m:    process.RawMapping{Flags: elf.PF_R},
			want: true,
		},
		{
			name: "dll",
			m:    process.RawMapping{Flags: elf.PF_R, Path: "/tmp/assembly.dll"},
			want: true,
		},
		{
			name: "file backed executable",
			m:    process.RawMapping{Flags: elf.PF_R | elf.PF_X, Path: "/tmp/interpreter"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, isInterpreterMapping(&test.m))
		})
	}
}

func TestInterpreterMappingCollectorFlushesFirstPassMappingsAfterEnable(t *testing.T) {
	collector := newInterpreterMappingCollector(8)
	pending := []process.RawMapping{
		{Vaddr: 0x1000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x2000, Flags: elf.PF_R},
		{Vaddr: 0x3000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x4000, Flags: elf.PF_R | elf.PF_X, Path: "/tmp/interpreter"},
	}
	for _, m := range pending {
		collector.add(m, false)
	}
	require.Empty(t, collector.mappings())

	collector.enable()
	collector.add(process.RawMapping{
		Vaddr: 0x5000,
		Flags: elf.PF_R,
		Path:  "/tmp/assembly.dll",
	}, true)

	require.Equal(t, []process.RawMapping{
		{Vaddr: 0x1000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x2000, Flags: elf.PF_R},
		{Vaddr: 0x3000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x5000, Flags: elf.PF_R, Path: "/tmp/assembly.dll"},
	}, collector.mappings())
}
