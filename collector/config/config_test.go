// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/ebpf-profiler/collector/config"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/xconfmap"

	"go.opentelemetry.io/ebpf-profiler/probes/memory"
)

// validConfig returns a config with valid defaults for testing.
func validConfig() *Config {
	return &Config{
		SamplesPerSecond:       20,
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		NoKernelVersionCheck:   true,
	}
}

func TestValidate(t *testing.T) {
	cfg := &Config{
		SamplesPerSecond: 0,
		ErrorMode:        PropagateError,
	}
	err := xconfmap.Validate(cfg)
	require.Error(t, err)
	require.Equal(t, "invalid sampling frequency: 0", err.Error())
}

func TestUnmarshalText(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    ErrorMode
		wantErr bool
	}{
		{
			name:  "ignore",
			input: "ignore",
			want:  IgnoreError,
		},
		{
			name:  "propagate",
			input: "propagate",
			want:  PropagateError,
		},
		{
			name:  "case insensitive",
			input: "IGNORE",
			want:  IgnoreError,
		},
		{
			name:    "invalid value",
			input:   "INVALID",
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var e ErrorMode
			err := e.UnmarshalText([]byte(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, e)
		})
	}
}

func TestMemoryProbeConfigUnmarshal(t *testing.T) {
	cfg := validConfig()
	configuration := confmap.NewFromStringMap(map[string]any{
		"probes": map[string]any{
			"memory": map[string]any{
				"enabled":                 true,
				"sampling_interval_bytes": 262144,
				"process_executables":     []any{"ruby*", "tarantool"},
				"allocation_hooks": []any{
					map[string]any{
						"type":     "usdt",
						"provider": "ruby",
						"name":     "object_alloc",
					},
					map[string]any{
						"type":       "uprobe",
						"abi":        "weighted_allocation",
						"executable": "libheap*.so",
						"symbol":     "record_alloc",
					},
				},
			},
		},
	})

	require.NoError(t, configuration.Unmarshal(cfg))
	cfg.ErrorMode = PropagateError
	cfg.SamplesPerSecond = 20
	cfg.ProbabilisticInterval = time.Minute
	cfg.ProbabilisticThreshold = 100
	cfg.NoKernelVersionCheck = true
	require.NoError(t, cfg.Validate())
	require.True(t, cfg.Probes.Memory.Enabled)
	weightedUprobe := memory.UprobeHook("libheap*.so", "record_alloc")
	weightedUprobe.ABI = memory.ABIWeightedAllocation
	require.Equal(t, []memory.Hook{
		memory.USDTHook("ruby", "object_alloc"),
		weightedUprobe,
	}, cfg.Probes.Memory.AllocationHooks)
	require.Equal(t, uint64(262144), cfg.Probes.Memory.SamplingIntervalBytes)
	require.Equal(t, []string{"ruby*", "tarantool"},
		cfg.Probes.Memory.ProcessExecutablePatterns)
	// Omitted values are filled by typed memory-probe defaults.
	require.Equal(t, memory.DefaultMaxEntriesPerPID, cfg.Probes.Memory.MaxEntriesPerPID)
	require.Equal(t, []memory.Hook{
		memory.USDTHook(memory.DefaultUSDTProvider, "free"),
	}, cfg.Probes.Memory.DeallocationHooks)
}

func TestValidateErrorMode(t *testing.T) {
	for _, tt := range []struct {
		name      string
		errorMode ErrorMode
		want      ErrorMode
		wantErr   bool
	}{
		{
			name:      "empty error mode is invalid",
			errorMode: "",
			wantErr:   true,
		},
		{
			name:      "ignore is valid",
			errorMode: IgnoreError,
			want:      IgnoreError,
		},
		{
			name:      "propagate is valid",
			errorMode: PropagateError,
			want:      PropagateError,
		},
		{
			name:      "invalid error mode",
			errorMode: "INVALID",
			wantErr:   true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.ErrorMode = tt.errorMode
			err := xconfmap.Validate(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.ErrorMode)
		})
	}
}
