// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package functionlatency

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testDefinition = Definition{
	Symbol:     "tcp_sendmsg",
	SampleType: "tcp_send_latency",
}

func TestNewDefaults(t *testing.T) {
	created, err := New(testDefinition, map[string]any{})
	require.NoError(t, err)

	probe := created.(*functionLatencyProbe)
	require.Equal(t, testDefinition, probe.definition)
	require.Zero(t, probe.minDuration)
	require.Equal(t, uint32(math.MaxUint32), probe.sampleThreshold)
	require.Equal(t, defaultMaxEntries, probe.maxEntries)

	metadata := probe.ReportMetadata()
	require.Equal(t, "tcp_send_latency", metadata.SampleType)
	require.Equal(t, "nanoseconds", metadata.SampleUnit)
	require.True(t, metadata.ReportValues)
}

func TestNewConfigured(t *testing.T) {
	created, err := New(testDefinition, map[string]any{
		"min_duration": "250us",
		"sample_rate":  0.5,
		"max_entries":  4096,
	})
	require.NoError(t, err)

	probe := created.(*functionLatencyProbe)
	require.Equal(t, 250*time.Microsecond, probe.minDuration)
	require.Equal(t, uint32(math.MaxUint32/2), probe.sampleThreshold)
	require.Equal(t, uint32(4096), probe.maxEntries)
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	tests := map[string]struct {
		definition Definition
		config     any
		errorText  string
	}{
		"missing symbol": {
			definition: Definition{SampleType: "latency"},
			errorText:  "kernel symbol is empty",
		},
		"missing sample type": {
			definition: Definition{Symbol: "tcp_sendmsg"},
			errorText:  "sample type is empty",
		},
		"not a map": {
			definition: testDefinition,
			config:     "bad",
			errorText:  "function latency configuration must be a map, got string",
		},
		"unknown field": {
			definition: testDefinition,
			config:     map[string]any{"unknown": true},
			errorText:  "unknown function latency configuration field \"unknown\"",
		},
		"bad duration": {
			definition: testDefinition,
			config:     map[string]any{"min_duration": "soon"},
			errorText:  "invalid min_duration \"soon\"",
		},
		"negative duration": {
			definition: testDefinition,
			config:     map[string]any{"min_duration": -time.Second},
			errorText:  "min_duration must not be negative",
		},
		"zero sample rate": {
			definition: testDefinition,
			config:     map[string]any{"sample_rate": 0.0},
			errorText:  "sample_rate must be in the range (0, 1]",
		},
		"sample rate above one": {
			definition: testDefinition,
			config:     map[string]any{"sample_rate": 1.1},
			errorText:  "sample_rate must be in the range (0, 1]",
		},
		"NaN sample rate": {
			definition: testDefinition,
			config:     map[string]any{"sample_rate": math.NaN()},
			errorText:  "sample_rate must be in the range (0, 1]",
		},
		"fractional max entries": {
			definition: testDefinition,
			config:     map[string]any{"max_entries": 3.5},
			errorText:  "max_entries must be a non-negative integer",
		},
		"too many entries": {
			definition: testDefinition,
			config:     map[string]any{"max_entries": float64(maximumMaxEntries + 1)},
			errorText:  "max_entries must be in the range",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(test.definition, test.config)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}
