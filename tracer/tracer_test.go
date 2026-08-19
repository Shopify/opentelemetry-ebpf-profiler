// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"errors"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/elastic/go-perf"
	"github.com/stretchr/testify/require"
)

// Make accessible for testing
func (t *Tracer) GetEbpfMaps() map[string]*cebpf.Map {
	return t.ebpfMaps
}

func TestValidatePerSampleCountersConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "software clock trigger",
			cfg: Config{
				EnableSWCPUClock:        true,
				EnablePerSampleCounters: true,
			},
		},
		{
			name: "requires a software clock trigger",
			cfg: Config{
				EnablePerSampleCounters: true,
			},
			wantErr: "per-sample counters require software cpu-clock sampling (--enable-sw-cpu-clock)",
		},
		{
			name: "requires software clock",
			cfg: Config{
				EnableHWCPUCycles:       true,
				EnablePerSampleCounters: true,
			},
			wantErr: "per-sample counters require software cpu-clock sampling (--enable-sw-cpu-clock)",
		},
		{
			name: "excludes cycles trigger",
			cfg: Config{
				EnableSWCPUClock:        true,
				EnableHWCPUCycles:       true,
				EnablePerSampleCounters: true,
			},
			wantErr: "per-sample counters cannot be combined with --enable-hw-cpu-cycles or --enable-hw-instructions",
		},
		{
			name: "excludes instructions trigger",
			cfg: Config{
				EnableSWCPUClock:        true,
				EnableHWInstructions:    true,
				EnablePerSampleCounters: true,
			},
			wantErr: "per-sample counters cannot be combined with --enable-hw-cpu-cycles or --enable-hw-instructions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestPerSampleCounterOpenFailureDegradesGracefully(t *testing.T) {
	openCalls := 0
	var openedAttr perf.Attr
	var openedPID, openedCPU int
	tr := &Tracer{
		ebpfMaps: map[string]*cebpf.Map{
			perSampleCyclesMapName:       nil,
			perSampleInstructionsMapName: nil,
		},
		openPerfEvent: func(attr *perf.Attr, pid, cpu int, _ *perf.Event) (*perf.Event, error) {
			openCalls++
			openedAttr = *attr
			openedPID = pid
			openedCPU = cpu
			return nil, errors.New("PMU unavailable")
		},
	}

	softwareClockEvent := new(perf.Event)
	events := []*perf.Event{softwareClockEvent}
	tr.attachPerSampleCounters(&events, []int{0, 1})

	require.Equal(t, 1, openCalls, "the first PMU failure should abort one aggregated attempt")
	require.Equal(t, perf.HardwareEvent, openedAttr.Type)
	require.Equal(t, uint64(perf.CPUCycles), openedAttr.Config)
	require.Zero(t, openedAttr.Sample, "readable counters must not generate samples")
	require.True(t, openedAttr.Options.Disabled)
	require.True(t, openedAttr.CountFormat.Enabled)
	require.True(t, openedAttr.CountFormat.Running)
	require.Equal(t, perf.AllThreads, openedPID)
	require.Zero(t, openedCPU)
	require.Equal(t, []*perf.Event{softwareClockEvent}, events,
		"the already-attached software-clock event must remain available")
}
