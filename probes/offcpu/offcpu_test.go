// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package offcpu

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestNewDefaults(t *testing.T) {
	created, err := New(map[string]any{})
	require.NoError(t, err)

	probe := created.(*offCPUTimeProbe)
	require.Equal(t, defaultMinDuration, probe.minDuration)
	require.Equal(t, uint32(math.MaxUint32), probe.sampleThreshold)
	require.Equal(t, defaultMaxEntries, probe.maxEntries)

	metadata := probe.ReportMetadata()
	require.Equal(t, "off_cpu_time", metadata.SampleType)
	require.Equal(t, "nanoseconds", metadata.SampleUnit)
	require.True(t, metadata.ReportValues)
}

func TestNewAllowsExplicitExhaustiveCapture(t *testing.T) {
	created, err := New(map[string]any{"min_duration": "0s"})
	require.NoError(t, err)
	require.Zero(t, created.(*offCPUTimeProbe).minDuration)
}

func TestNewConfigured(t *testing.T) {
	created, err := New(map[string]any{
		"min_duration": "5ms",
		"sample_rate":  0.5,
		"max_entries":  128 * 1024,
	})
	require.NoError(t, err)

	probe := created.(*offCPUTimeProbe)
	require.Equal(t, 5*time.Millisecond, probe.minDuration)
	require.Equal(t, uint32(math.MaxUint32/2), probe.sampleThreshold)
	require.Equal(t, uint32(128*1024), probe.maxEntries)
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	tests := map[string]struct {
		config    any
		errorText string
	}{
		"not a map": {
			config:    "bad",
			errorText: "off-cpu time configuration must be a map, got string",
		},
		"unknown field": {
			config:    map[string]any{"unknown": true},
			errorText: "unknown off-cpu time configuration field \"unknown\"",
		},
		"bad duration": {
			config:    map[string]any{"min_duration": "soon"},
			errorText: "invalid min_duration \"soon\"",
		},
		"negative duration": {
			config:    map[string]any{"min_duration": -time.Second},
			errorText: "min_duration must not be negative",
		},
		"zero sample rate": {
			config:    map[string]any{"sample_rate": 0.0},
			errorText: "sample_rate must be in the range (0, 1]",
		},
		"sample rate above one": {
			config:    map[string]any{"sample_rate": 1.1},
			errorText: "sample_rate must be in the range (0, 1]",
		},
		"zero max entries": {
			config:    map[string]any{"max_entries": 0},
			errorText: "max_entries must be in the range",
		},
		"too many entries": {
			config:    map[string]any{"max_entries": float64(maximumMaxEntries + 1)},
			errorText: "max_entries must be in the range",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(test.config)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

func withKallsymsFixture(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kallsyms")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	previous := kallsymsPath
	kallsymsPath = path
	t.Cleanup(func() { kallsymsPath = previous })
}

func TestResolveSwitchInSymbolsMatchesVariants(t *testing.T) {
	withKallsymsFixture(t, `ffffffff81000000 T _stext
ffffffff810bd2a0 t finish_task_switch.isra.0
ffffffff810bd2a0 t finish_task_switch.isra.0
ffffffff810be000 T finish_task_switch
ffffffff810bf000 t finish_task_switching_helper
ffffffff810c0000 d finish_task_switch.data
ffffffff810c1000 t prefix_finish_task_switch
`)

	symbols, err := resolveSwitchInSymbols()
	require.NoError(t, err)
	require.Equal(t, []string{"finish_task_switch.isra.0", "finish_task_switch"}, symbols)
}

func TestResolveSwitchInSymbolsEmptyWhenAbsent(t *testing.T) {
	withKallsymsFixture(t, `ffffffff81000000 T _stext
ffffffff810bd2a0 t some_other_symbol
`)

	symbols, err := resolveSwitchInSymbols()
	require.NoError(t, err)
	require.Empty(t, symbols)
}

func TestThreadStateName(t *testing.T) {
	expected := map[uint64]string{
		0x0000: "running",
		0x0001: "interruptible",
		0x0002: "uninterruptible",
		0x0004: "stopped",
		0x0008: "traced",
		0x0010: "exit_dead",
		0x0020: "zombie",
		0x0040: "parked",
		0x0080: "idle",
		0x0100: "preempted",
		0x0003: "other",
		0x0200: "other",
	}
	for state, name := range expected {
		require.Equal(t, name, threadStateName(state), "state 0x%x", state)
	}
}

func TestLabelTraceAttachesThreadState(t *testing.T) {
	probe := &offCPUTimeProbe{}
	key := libpf.Intern("thread.state")

	trace := &libpf.EbpfTrace{ProbeUserData: 0x0001}
	probe.LabelTrace(trace)
	require.Equal(t, libpf.Intern("interruptible"), trace.CustomLabels[key])

	// Merges with runtime labels instead of replacing them.
	existing := libpf.Intern("request_id")
	trace = &libpf.EbpfTrace{
		ProbeUserData: 0x0100,
		CustomLabels: map[libpf.String]libpf.String{
			existing: libpf.Intern("abc"),
		},
	}
	probe.LabelTrace(trace)
	require.Equal(t, libpf.Intern("preempted"), trace.CustomLabels[key])
	require.Equal(t, libpf.Intern("abc"), trace.CustomLabels[existing])

	// No label when the state was unavailable.
	trace = &libpf.EbpfTrace{ProbeUserData: stateUnavailable}
	probe.LabelTrace(trace)
	require.NotContains(t, trace.CustomLabels, key)
}

const schedSwitchFormatFixture = `name: sched_switch
ID: 315
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;

	field:char prev_comm[16];	offset:8;	size:16;	signed:0;
	field:pid_t prev_pid;	offset:24;	size:4;	signed:1;
	field:int prev_prio;	offset:28;	size:4;	signed:1;
	field:long prev_state;	offset:32;	size:8;	signed:1;
	field:char next_comm[16];	offset:40;	size:16;	signed:0;
`

func withTracefsFixture(t *testing.T, roots []string) {
	t.Helper()
	previous := tracefsRoots
	tracefsRoots = roots
	t.Cleanup(func() { tracefsRoots = previous })
}

func writeFormatFixture(t *testing.T, root, content string) {
	t.Helper()
	dir := filepath.Join(root, "events", "sched", "sched_switch")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "format"), []byte(content), 0o600))
}

func TestResolveSchedSwitchStateField(t *testing.T) {
	root := t.TempDir()
	writeFormatFixture(t, root, schedSwitchFormatFixture)
	// The first root is missing; resolution falls back to the second.
	withTracefsFixture(t, []string{filepath.Join(t.TempDir(), "absent"), root})

	offset, size, err := resolveSchedSwitchStateField()
	require.NoError(t, err)
	require.Equal(t, uint32(32), offset)
	require.Equal(t, uint32(8), size)
}

func TestResolveSchedSwitchStateFieldMissingField(t *testing.T) {
	root := t.TempDir()
	writeFormatFixture(t, root, "name: sched_switch\n\tfield:pid_t prev_pid;\toffset:24;\tsize:4;\tsigned:1;\n")
	withTracefsFixture(t, []string{root})

	_, _, err := resolveSchedSwitchStateField()
	require.ErrorContains(t, err, "prev_state")
}

func TestParseTracepointFieldIgnoresNameSuffixMatches(t *testing.T) {
	root := t.TempDir()
	// prev_state_extra must not satisfy a prev_state lookup.
	writeFormatFixture(t, root,
		"\tfield:long prev_state_extra;\toffset:48;\tsize:8;\tsigned:1;\n"+
			"\tfield:long prev_state;\toffset:32;\tsize:8;\tsigned:1;\n")
	withTracefsFixture(t, []string{root})

	offset, size, err := resolveSchedSwitchStateField()
	require.NoError(t, err)
	require.Equal(t, uint32(32), offset)
	require.Equal(t, uint32(8), size)
}

func TestResolveSwitchInSymbolsMissingFile(t *testing.T) {
	previous := kallsymsPath
	kallsymsPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { kallsymsPath = previous })

	_, err := resolveSwitchInSymbols()
	require.Error(t, err)
}
