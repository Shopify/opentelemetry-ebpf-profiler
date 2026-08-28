// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package config // import "go.opentelemetry.io/ebpf-profiler/collector/config"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
)

// validConfig returns a config with valid defaults for testing.
func validConfig() *Config {
	return &Config{
		SamplesPerSecond:       20,
		FrameCacheSize:         minFrameCacheSize,
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		NoKernelVersionCheck:   true,
		ErrorMode:              PropagateError,
		EnableSWCPUClock:       true,
	}
}

func TestValidate(t *testing.T) {
	cfg := &Config{
		SamplesPerSecond: 0,
		ErrorMode:        PropagateError,
	}
	err := confmap.Validate(cfg)
	require.Error(t, err)
	require.Equal(t, "invalid sampling frequency: 0", err.Error())
}

func TestValidateFrameCacheSize(t *testing.T) {
	for _, tt := range []struct {
		name           string
		frameCacheSize uint
		wantErr        bool
	}{
		{
			name:           "zero is invalid",
			frameCacheSize: 0,
			wantErr:        true,
		},
		{
			name:           "below minimum is invalid",
			frameCacheSize: minFrameCacheSize - 1,
			wantErr:        true,
		},
		{
			name:           "minimum is valid",
			frameCacheSize: minFrameCacheSize,
		},
		{
			name:           "maximum is valid",
			frameCacheSize: maxFrameCacheSize,
		},
		{
			name:           "above maximum is invalid",
			frameCacheSize: maxFrameCacheSize + 1,
			wantErr:        true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.FrameCacheSize = tt.frameCacheSize
			err := confmap.Validate(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateSamplingEvents(t *testing.T) {
	cfg := validConfig()
	cfg.EnableSWCPUClock = false

	err := confmap.Validate(cfg)
	require.EqualError(t, err,
		"at least one perf event type must be enabled: use --enable-sw-cpu-clock, --enable-hw-cpu-cycles, and/or --enable-hw-instructions")

	cfg.EnableHWCPUCycles = true
	require.NoError(t, confmap.Validate(cfg))

	cfg.EnableHWCPUCycles = false
	cfg.EnableHWInstructions = true
	require.NoError(t, confmap.Validate(cfg))
}

func TestValidatePerSampleCountersMatrix(t *testing.T) {
	tests := []struct {
		name         string
		sw, cycles   bool
		instructions bool
		perSample    bool
		wantErr      string
	}{
		{name: "software clock only", sw: true},
		{name: "per-sample mode", sw: true, perSample: true},
		{
			name:      "per-sample mode without any trigger",
			perSample: true,
			wantErr:   "per-sample counters require software cpu-clock sampling (--enable-sw-cpu-clock)",
		},
		{
			name:      "cycles trigger without software clock",
			cycles:    true,
			perSample: true,
			wantErr:   "per-sample counters require software cpu-clock sampling (--enable-sw-cpu-clock)",
		},
		{
			name:         "instructions trigger without software clock",
			instructions: true,
			perSample:    true,
			wantErr:      "per-sample counters require software cpu-clock sampling (--enable-sw-cpu-clock)",
		},
		{
			name:         "both hardware triggers without software clock",
			cycles:       true,
			instructions: true,
			perSample:    true,
			wantErr:      "per-sample counters require software cpu-clock sampling (--enable-sw-cpu-clock)",
		},
		{
			name:      "software clock plus cycles trigger",
			sw:        true,
			cycles:    true,
			perSample: true,
			wantErr:   "per-sample counters cannot be combined with --enable-hw-cpu-cycles or --enable-hw-instructions",
		},
		{
			name:         "software clock plus instructions trigger",
			sw:           true,
			instructions: true,
			perSample:    true,
			wantErr:      "per-sample counters cannot be combined with --enable-hw-cpu-cycles or --enable-hw-instructions",
		},
		{
			name:         "all triggers",
			sw:           true,
			cycles:       true,
			instructions: true,
			perSample:    true,
			wantErr:      "per-sample counters cannot be combined with --enable-hw-cpu-cycles or --enable-hw-instructions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.EnableSWCPUClock = tt.sw
			cfg.EnableHWCPUCycles = tt.cycles
			cfg.EnableHWInstructions = tt.instructions
			cfg.EnablePerSampleCounters = tt.perSample

			err := confmap.Validate(cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestValidatePerSampleExtraCounters(t *testing.T) {
	cfg := validConfig()
	cfg.PerSampleExtraCounters = "   "
	require.NoError(t, confmap.Validate(cfg))
	require.False(t, cfg.PerSampleBranchMissesEnabled())

	cfg.PerSampleExtraCounters = "branch-misses"
	require.EqualError(t, confmap.Validate(cfg),
		"per-sample extra counters require --enable-per-sample-counters")

	cfg.EnablePerSampleCounters = true
	require.NoError(t, confmap.Validate(cfg))
	require.True(t, cfg.PerSampleBranchMissesEnabled())

	cfg.PerSampleExtraCounters = " branch-misses,branch-misses "
	require.NoError(t, confmap.Validate(cfg))
	require.True(t, cfg.PerSampleBranchMissesEnabled())

	cfg.PerSampleExtraCounters = "unknown"
	require.EqualError(t, confmap.Validate(cfg),
		"unknown per-sample extra counter \"unknown\"")
}

func TestValidateBranchSamplingRequiresCycles(t *testing.T) {
	cfg := validConfig()
	cfg.EnableBranchSampling = true

	err := confmap.Validate(cfg)
	require.EqualError(t, err, "branch sampling requires hardware cpu-cycles")

	cfg.EnableHWCPUCycles = true
	require.NoError(t, confmap.Validate(cfg))
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

func TestValidateTargetCPUIDs(t *testing.T) {
	for _, tt := range []struct {
		name         string
		targetCPUIDs string
		wantPinned   []int
		wantErr      bool
	}{
		{
			name:         "empty leaves PinnedCPUIDs unset",
			targetCPUIDs: "",
			wantPinned:   nil,
		},
		{
			name:         "range and single values are parsed into PinnedCPUIDs",
			targetCPUIDs: "0-2,6",
			wantPinned:   []int{0, 1, 2, 6},
		},
		{
			name:         "invalid range is rejected",
			targetCPUIDs: "not-a-range",
			wantErr:      true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.TargetCPUIDs = tt.targetCPUIDs
			err := confmap.Validate(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantPinned, cfg.PinnedCPUIDs)
		})
	}
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
			err := confmap.Validate(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.ErrorMode)
		})
	}
}

func TestValidateFilterMinProcessAge(t *testing.T) {
	cfg := validConfig()
	cfg.FilterMinProcessAge = -1 * time.Second

	err := confmap.Validate(cfg)
	require.Error(t, err)
}
