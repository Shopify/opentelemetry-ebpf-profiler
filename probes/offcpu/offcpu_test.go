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
)

func TestNewDefaults(t *testing.T) {
	created, err := New(map[string]any{})
	require.NoError(t, err)

	probe := created.(*offCPUTimeProbe)
	require.Zero(t, probe.minDuration)
	require.Equal(t, uint32(math.MaxUint32), probe.sampleThreshold)
	require.Equal(t, defaultMaxEntries, probe.maxEntries)

	metadata := probe.ReportMetadata()
	require.Equal(t, "off_cpu_time", metadata.SampleType)
	require.Equal(t, "nanoseconds", metadata.SampleUnit)
	require.True(t, metadata.ReportValues)
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

func TestResolveSwitchInSymbolsMissingFile(t *testing.T) {
	previous := kallsymsPath
	kallsymsPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { kallsymsPath = previous })

	_, err := resolveSwitchInSymbols()
	require.Error(t, err)
}
