// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package biostacks

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewDefaults(t *testing.T) {
	created, err := New(map[string]any{})
	require.NoError(t, err)

	probe := created.(*blockIOStacksProbe)
	require.Zero(t, probe.minDuration)
	require.Equal(t, uint32(math.MaxUint32), probe.sampleThreshold)
	require.Equal(t, defaultMaxEntries, probe.maxEntries)

	metadata := probe.ReportMetadata()
	require.Equal(t, SampleType, metadata.SampleType)
	require.Equal(t, "nanoseconds", metadata.SampleUnit)
	require.True(t, metadata.ReportValues)
}

func TestNewConfigured(t *testing.T) {
	created, err := New(map[string]any{
		"min_duration": "250us",
		"sample_rate":  0.5,
		"max_entries":  4096,
	})
	require.NoError(t, err)

	probe := created.(*blockIOStacksProbe)
	require.Equal(t, 250*time.Microsecond, probe.minDuration)
	require.Equal(t, uint32(math.MaxUint32/2), probe.sampleThreshold)
	require.Equal(t, uint32(4096), probe.maxEntries)
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	tests := map[string]struct {
		config    any
		errorText string
	}{
		"not a map": {
			config:    "bad",
			errorText: "block I/O stacks configuration must be a map, got string",
		},
		"unknown field": {
			config:    map[string]any{"unknown": true},
			errorText: "unknown block I/O stacks configuration field \"unknown\"",
		},
		"negative duration": {
			config:    map[string]any{"min_duration": -time.Second},
			errorText: "min_duration must not be negative",
		},
		"zero sample rate": {
			config:    map[string]any{"sample_rate": 0.0},
			errorText: "sample_rate must be in the range (0, 1]",
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
