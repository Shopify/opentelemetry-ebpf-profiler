package processmanager

import (
	"os"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	golang "go.opentelemetry.io/ebpf-profiler/interpreter/go"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/probes/memory"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
)

func TestReconcileMemoryProbesMarksIneligibleProcessComplete(t *testing.T) {
	manager, err := memory.NewManager(memory.Config{
		Enabled:                   true,
		ProcessExecutablePatterns: []string{"definitely-not-this-test-process"},
	}, map[memory.ProgramKind]*ebpf.Program{
		memory.ProgramWeightedAllocation: {},
	})
	require.NoError(t, err)
	defer manager.Close()

	pid := libpf.PID(os.Getpid())
	pm := &ProcessManager{
		memoryProbeManager:   manager,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {lastSeenTID: pid}},
		memoryProbeInstances: make(map[libpf.PID]*memory.Instance),
		cleanupSem:           make(chan struct{}, 1),
	}

	pm.ReconcileMemoryProbes(1)
	inst := pm.memoryProbeInstances[pid]
	require.NotNil(t, inst)
	evaluated, eligible := inst.Applicability()
	assert.True(t, evaluated)
	assert.False(t, eligible)
	assert.False(t, manager.ShouldRetry(inst))
}

func TestReconcileMemoryProbesSkipsPendingHeapCleanup(t *testing.T) {
	manager, err := memory.NewManager(memory.Config{Enabled: true},
		map[memory.ProgramKind]*ebpf.Program{memory.ProgramWeightedAllocation: {}})
	require.NoError(t, err)
	defer manager.Close()

	pid := libpf.PID(os.Getpid())
	pm := &ProcessManager{
		memoryProbeManager:   manager,
		pidToProcessInfo:     map[libpf.PID]*processInfo{pid: {lastSeenTID: pid}},
		memoryProbeInstances: make(map[libpf.PID]*memory.Instance),
		heapCleanupPending:   map[libpf.PID]struct{}{pid: {}},
		cleanupSem:           make(chan struct{}, 1),
	}

	pm.ReconcileMemoryProbes(1)
	assert.NotContains(t, pm.memoryProbeInstances, pid,
		"a cleanup-failed generation must not attach fresh producers")
}

func TestCloseDrainsDeferredCleanup(t *testing.T) {
	pm := &ProcessManager{cleanupSem: make(chan struct{}, 2)}
	var completed atomic.Uint32
	for range 32 {
		pm.deferCleanup(func() { completed.Add(1) })
	}

	pm.Close()
	assert.Equal(t, uint32(32), completed.Load())
}

type traceCapture struct {
	traces    []*libpf.Trace
	extraMeta any
}

func (tc *traceCapture) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	tc.traces = append(tc.traces, trace)
	meta.ExtraMeta = tc.extraMeta
	return nil
}

func TestHandleTraceWithMetadataReturnsReporterMetadata(t *testing.T) {
	capture := &traceCapture{extraMeta: "pod-a"}
	pm := &ProcessManager{traceReporter: capture}

	_, _, extraMeta := pm.HandleTraceWithMetadata(&libpf.EbpfTrace{
		PID: 1, TID: 1, Origin: support.TraceOriginHeapAlloc,
	})
	assert.Equal(t, "pod-a", extraMeta)
}

func TestFrameCacheCrossProcessPollution(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}

	exec, err := os.Executable()
	require.NoError(t, err)

	pc, _, _, ok := runtime.Caller(0)
	require.True(t, ok)

	goPID := libpf.PID(1000)
	catPID := libpf.PID(2000)

	goHostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)
	catHostFileID, err := host.FileIDFromBytes(
		[]byte{0xCA, 0x7C, 0xA7, 0xCA, 0x7C, 0xA7, 0xCA, 0x7C})
	require.NoError(t, err)
	libcHostFileID, err := host.FileIDFromBytes(
		[]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	require.NoError(t, err)

	realPID := libpf.PID(os.Getpid())
	pid := process.New(realPID, realPID)
	elfRef := pfelf.NewReference(exec, pid)
	loaderInfo := interpreter.NewLoaderInfo(goHostFileID, elfRef, nil)
	rm := remotememory.NewProcessVirtualMemory(realPID)

	goData, err := golang.GetLoader(golang.Config{})(nil, loaderInfo)
	require.NoError(t, err)
	goInstance, err := goData.Attach(nil, realPID, 0x0, rm)
	require.NoError(t, err)

	goODID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}

	frameCache, err := lru.New[frameCacheKey, libpf.Frames](1024, hashFrameCacheKey)
	require.NoError(t, err)
	frameCache.SetLifetime(frameCacheLifetime)

	goMappings := []Mapping{
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(goHostFileID), 0),
				FileName: libpf.Intern("go-binary"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(libcHostFileID), 0),
				FileName: libpf.Intern("libc.so.6"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
	}
	slices.SortFunc(goMappings, compareMapping)

	catMappings := []Mapping{
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(catHostFileID), 0),
				FileName: libpf.Intern("cat"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(libcHostFileID), 0),
				FileName: libpf.Intern("libc.so.6"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
	}
	slices.SortFunc(catMappings, compareMapping)

	capture := &traceCapture{}
	pm := &ProcessManager{
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			goPID: {goODID: goInstance},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			goPID:  {mappings: goMappings},
			catPID: {mappings: catMappings},
		},
		frameCache:    frameCache,
		traceReporter: capture,
	}

	libcFrame := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, uint64(pc))
	libcFrame[1] = uint64(libcHostFileID)

	pm.HandleTrace(&libpf.EbpfTrace{
		PID:       goPID,
		TID:       goPID,
		NumFrames: 1,
		FrameData: libcFrame,
	})

	require.Len(t, capture.traces, 1)
	goTrace := capture.traces[0]
	require.NotEmpty(t, goTrace.Frames)

	goFrame := goTrace.Frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, goFrame.Type)
	assert.Equal(t, "", goFrame.FunctionName.String())

	pm.HandleTrace(&libpf.EbpfTrace{
		PID:       catPID,
		TID:       catPID,
		NumFrames: 1,
		FrameData: libcFrame,
	})

	require.Len(t, capture.traces, 2)
	catTrace := capture.traces[1]
	require.NotEmpty(t, catTrace.Frames)

	catFrame := catTrace.Frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, catFrame.Type)
	assert.Equal(t, "", catFrame.FunctionName.String())
}

func TestFrameCacheSharesNativeFallbackFramesAcrossProcesses(t *testing.T) {
	firstPID := libpf.PID(1000)
	secondPID := libpf.PID(2000)
	fileID, err := host.FileIDFromBytes(
		[]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	require.NoError(t, err)

	frameCache, err := lru.New[frameCacheKey, libpf.Frames](1024, hashFrameCacheKey)
	require.NoError(t, err)
	frameCache.SetLifetime(frameCacheLifetime)

	mappings := []Mapping{
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(fileID), 0),
				FileName: libpf.Intern("libc.so.6"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
	}
	capture := &traceCapture{}
	pm := &ProcessManager{
		pidToProcessInfo: map[libpf.PID]*processInfo{
			firstPID:  {mappings: mappings},
			secondPID: {mappings: mappings},
		},
		frameCache:    frameCache,
		traceReporter: capture,
	}

	nativeFrame := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, 0x222a0)
	nativeFrame[1] = uint64(fileID)

	pm.HandleTrace(&libpf.EbpfTrace{
		PID:       firstPID,
		TID:       firstPID,
		NumFrames: 1,
		FrameData: nativeFrame,
	})
	pm.HandleTrace(&libpf.EbpfTrace{
		PID:       secondPID,
		TID:       secondPID,
		NumFrames: 1,
		FrameData: nativeFrame,
	})

	require.Len(t, capture.traces, 2)

	require.NotEmpty(t, capture.traces[0].Frames)
	frame0 := capture.traces[0].Frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, frame0.Type)
	assert.Equal(t, "", frame0.FunctionName.String())

	require.NotEmpty(t, capture.traces[1].Frames)
	frame1 := capture.traces[1].Frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, frame1.Type)
	assert.Equal(t, "", frame1.FunctionName.String())

	assert.Equal(t, uint64(1), pm.frameCacheMiss.Load())
	assert.Equal(t, uint64(1), pm.frameCacheHit.Load())
}
