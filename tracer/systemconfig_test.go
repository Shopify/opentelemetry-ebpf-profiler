// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"testing"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestGetCurrentNS_FileNotFound(t *testing.T) {
	_, _, err := getCurrentNS("/nonexistent/path/pid")
	require.Error(t, err)
	require.True(t, errors.Is(err, fs.ErrNotExist))
}

func TestGetCurrentNS_ProcSelfNsPid(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping: /proc/self/ns/pid is Linux-specific (GOOS=%s)", runtime.GOOS)
	}
	const procSelfNsPid = "/proc/self/ns/pid"
	if _, err := os.Stat(procSelfNsPid); err != nil {
		t.Skipf("skipping: %s not available: %v", procSelfNsPid, err)
	}
	dev, ino, err := getCurrentNS(procSelfNsPid)
	require.NoError(t, err)
	require.NotZero(t, dev, "pid namespace device should be non-zero")
	require.NotZero(t, ino, "pid namespace inode should be non-zero")
}

func TestValidateSystemAnalysisResult(t *testing.T) {
	address := libpf.SymbolValue(0x1234)

	t.Run("not handled", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{Pid: 77}, address)
		require.Error(t, err)
		require.ErrorIs(t, err, errSystemAnalysisNotHandled)
		require.ErrorContains(t, err, "pid 77")
	})

	t.Run("helper failure", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{Err: -14}, address)
		require.Error(t, err)
		require.True(t, errors.Is(err, errSystemAnalysisFailed))
		require.ErrorContains(t, err, "helper err=-14")
	})

	t.Run("success", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{}, address)
		require.NoError(t, err)
	})
}

func TestCalculateFieldOffsetFindsAnonymousCompositeMembers(t *testing.T) {
	u64Type := &btf.Int{Name: "u64", Size: 8}
	vmArea := &btf.Struct{
		Name: "vm_area_struct",
		Size: 64,
		Members: []btf.Member{
			{
				Name:   "vm_start",
				Type:   u64Type,
				Offset: btf.Bits(0),
			},
			{
				Type: &btf.Union{
					Size: 16,
					Members: []btf.Member{
						{
							Type: &btf.Struct{
								Size: 16,
								Members: []btf.Member{
									{
										Name:   "vm_flags",
										Type:   u64Type,
										Offset: btf.Bits(64),
									},
								},
							},
						},
					},
				},
				Offset: btf.Bits(128),
			},
		},
	}

	offset, err := calculateFieldOffset(vmArea, "vm_flags")
	require.NoError(t, err)
	require.Equal(t, uint(24), offset)
}

func TestSetOriginIDsSamplingEvents(t *testing.T) {
	type source struct {
		variable string
		program  string
		enabled  func(*Config) bool
		metadata samples.TypeMetadata
	}

	sources := []source{
		{
			variable: "origin_id_sampling",
			program:  "native_tracer_entry_sw_cpu_clock",
			enabled:  func(cfg *Config) bool { return cfg.EnableSWCPUClock },
			metadata: samples.TypeMetadata{
				PeriodType: "cpu",
				PeriodUnit: "nanoseconds",
				SampleType: "samples",
				SampleUnit: "count",
			},
		},
		{
			variable: "origin_id_hw_cpu_cycles",
			program:  "native_tracer_entry_hw_cpu_cycles",
			enabled:  func(cfg *Config) bool { return cfg.EnableHWCPUCycles },
			metadata: samples.TypeMetadata{
				PeriodType: "cpu",
				PeriodUnit: "cycles",
				SampleType: "samples",
				SampleUnit: "count",
			},
		},
		{
			variable: "origin_id_hw_instructions",
			program:  "native_tracer_entry_hw_instructions",
			enabled:  func(cfg *Config) bool { return cfg.EnableHWInstructions },
			metadata: samples.TypeMetadata{
				PeriodType: "cpu",
				PeriodUnit: "instructions",
				SampleType: "samples",
				SampleUnit: "count",
			},
		},
	}

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "all sampling sources",
			cfg: Config{
				EnableSWCPUClock:     true,
				EnableHWCPUCycles:    true,
				EnableHWInstructions: true,
			},
		},
		{
			name: "cycles and instructions without software clock",
			cfg: Config{
				EnableHWCPUCycles:    true,
				EnableHWInstructions: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coll, err := support.LoadCollectionSpec()
			require.NoError(t, err)

			origins := &originRegistry{}
			reservedID, err := origins.Register(&samples.TypeMetadata{SampleType: "reserved"})
			require.NoError(t, err)
			require.Equal(t, uint16(1), reservedID)

			require.NoError(t, setOriginIDs(coll, &tt.cfg, origins))
			require.Nil(t, origins.lookup(0), "origin zero must remain unregistered")

			seen := map[uint16]string{reservedID: "reserved"}
			enabledCount := 0
			for _, src := range sources {
				variable := coll.Variables[src.variable]
				require.NotNil(t, variable)
				program := coll.Programs[src.program]
				require.NotNil(t, program)
				require.NotEmpty(t, program.Instructions)

				// Each entry point's first instruction must load its origin from the
				// corresponding RODATA slot. This prevents a fixed origin constant
				// from bypassing the registry.
				originLoad := program.Instructions[0]
				require.Equal(t, variable.SectionName, originLoad.Reference())
				require.Equal(t, uint64(variable.Offset), uint64(originLoad.Constant)>>32)

				var origin uint16
				require.NoError(t, variable.Get(&origin))
				if !src.enabled(&tt.cfg) {
					require.Zero(t, origin, "%s must remain unset when disabled", src.variable)
					continue
				}

				enabledCount++
				require.NotZero(t, origin)
				require.NotContains(t, seen, origin,
					"%s must have a distinct dynamic origin", src.variable)
				seen[origin] = src.variable

				metadata := origins.lookup(origin)
				require.NotNil(t, metadata, "%s must use a registered origin", src.variable)
				require.Equal(t, src.metadata, *metadata)
			}
			require.Equal(t, uint32(enabledCount+1), origins.lastID.Load())
		})
	}
}

func TestLoadBpfTraceRejectsUnregisteredOrigin(t *testing.T) {
	origins := &originRegistry{}
	registered, err := origins.Register(&samples.TypeMetadata{SampleType: "registered"})
	require.NoError(t, err)

	tracer := &Tracer{
		origins:   origins,
		tracePool: newTracePool(),
	}
	rawTrace := support.Trace{
		Origin:             registered,
		Cycles_delta:       123456,
		Instructions_delta: 654321,
	}
	raw := unsafe.Slice(
		(*byte)(unsafe.Pointer(&rawTrace)),
		int(unsafe.Offsetof(rawTrace.Frame_data)),
	)

	parsed, err := tracer.loadBpfTrace(raw)
	require.NoError(t, err)
	require.Equal(t, registered, parsed.Origin)
	require.Equal(t, uint64(123456), parsed.CyclesDelta)
	require.Equal(t, uint64(654321), parsed.InstructionsDelta)
	tracer.tracePool.Put(parsed)

	rawTrace.Origin = registered + 1 // Simulate a stale fixed origin ID.
	parsed, err = tracer.loadBpfTrace(raw)
	require.Nil(t, parsed)
	require.ErrorIs(t, err, errOriginUnexpected)
}

func TestPerSampleCounterOriginMetadata(t *testing.T) {
	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	origins := &originRegistry{}
	cfg := &Config{EnableSWCPUClock: true, EnablePerSampleCounters: true}
	require.NoError(t, setOriginIDs(coll, cfg, origins))
	require.Equal(t, uint32(1), origins.lastID.Load(), "derived profiles must not consume BPF origins")

	var origin uint16
	require.NoError(t, coll.Variables["origin_id_sampling"].Get(&origin))
	metadata := origins.lookup(origin)
	require.NotNil(t, metadata)
	require.Len(t, metadata.DerivedProfiles, 2)

	cycles := metadata.DerivedProfiles[0]
	require.Equal(t, samples.SampleValueSourceCyclesDelta, cycles.ValueSource)
	require.Equal(t, &samples.TypeMetadata{
		PeriodType:      "cpu",
		PeriodUnit:      "nanoseconds",
		SampleType:      "cycles",
		SampleUnit:      "cycles",
		ReportValues:    true,
		AggregateValues: true,
	}, cycles.ProfileType)

	instructions := metadata.DerivedProfiles[1]
	require.Equal(t, samples.SampleValueSourceInstructionsDelta, instructions.ValueSource)
	require.Equal(t, "instructions", instructions.ProfileType.SampleType)
	require.Equal(t, "instructions", instructions.ProfileType.SampleUnit)
}

func TestPerSampleCounterBPFMaps(t *testing.T) {
	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	for _, name := range []string{perSampleCyclesMapName, perSampleInstructionsMapName} {
		m := coll.Maps[name]
		require.NotNil(t, m, name)
		require.Equal(t, cebpf.PerfEventArray, m.Type, name)
	}
	state := coll.Maps["per_sample_counter_state"]
	require.NotNil(t, state)
	require.Equal(t, cebpf.PerCPUArray, state.Type)
	require.Equal(t, uint32(1), state.MaxEntries)

	flag := coll.Variables["enable_per_sample_counters"]
	require.NotNil(t, flag)
	var enabled bool
	require.NoError(t, flag.Get(&enabled))
	require.False(t, enabled)
}
