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
			name: "branch misses extra",
			cfg: Config{
				EnableSWCPUClock:            true,
				EnablePerSampleCounters:     true,
				EnablePerSampleBranchMisses: true,
			},
		},
		{
			name: "topdown extra",
			cfg: Config{
				EnableSWCPUClock:        true,
				EnablePerSampleCounters: true,
				EnablePerSampleTopdown:  true,
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
		{
			name: "branch misses require per-sample counters",
			cfg: Config{
				EnableSWCPUClock:            true,
				EnablePerSampleBranchMisses: true,
			},
			wantErr: "per-sample branch misses require per-sample counters",
		},
		{
			name: "topdown requires per-sample counters",
			cfg: Config{
				EnableSWCPUClock:       true,
				EnablePerSampleTopdown: true,
			},
			wantErr: "per-sample topdown counters require per-sample counters",
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

func TestPerSampleCounterOpenFailuresDegradeIndependently(t *testing.T) {
	var openedAttrs []perf.Attr
	var openedPIDs, openedCPUs []int
	tr := &Tracer{
		ebpfMaps: map[string]*cebpf.Map{
			perSampleCyclesMapName:         nil,
			perSampleInstructionsMapName:   nil,
			perSampleBranchMissesMapName:   nil,
			perSampleCounterEnabledMapName: nil,
		},
		enablePerSampleBranchMisses: true,
		openPerfEvent: func(attr *perf.Attr, pid, cpu int, _ *perf.Event) (*perf.Event, error) {
			openedAttrs = append(openedAttrs, *attr)
			openedPIDs = append(openedPIDs, pid)
			openedCPUs = append(openedCPUs, cpu)
			return nil, errors.New("PMU unavailable")
		},
	}

	softwareClockEvent := new(perf.Event)
	events := []*perf.Event{softwareClockEvent}
	tr.attachPerSampleCounters(&events, []int{0, 1})

	require.Len(t, openedAttrs, 2, "base and opt-in counter sets should fail independently")
	require.Equal(t, uint64(perf.CPUCycles), openedAttrs[0].Config)
	require.Equal(t, uint64(perf.BranchMisses), openedAttrs[1].Config)
	for _, attr := range openedAttrs {
		require.Equal(t, perf.HardwareEvent, attr.Type)
		require.Zero(t, attr.Sample, "readable counters must not generate samples")
		require.True(t, attr.Options.Disabled)
		require.True(t, attr.CountFormat.Enabled)
		require.True(t, attr.CountFormat.Running)
	}
	require.Equal(t, []int{perf.AllThreads, perf.AllThreads}, openedPIDs)
	require.Equal(t, []int{0, 0}, openedCPUs)
	require.Equal(t, []*perf.Event{softwareClockEvent}, events,
		"the already-attached software-clock event must remain available")
}

func TestPerSampleBranchMissesMissingMapPreservesExistingEvents(t *testing.T) {
	tr := &Tracer{ebpfMaps: map[string]*cebpf.Map{}}
	existing := new(perf.Event)
	events := []*perf.Event{existing}

	err := tr.openPerSampleBranchMisses(&events, []int{0})
	require.EqualError(t, err, `eBPF map "per_sample_branch_misses" is not available`)
	require.Equal(t, []*perf.Event{existing}, events)
}

func TestPerSampleTopdownDiscoveryFailurePreservesExistingEvents(t *testing.T) {
	maps := map[string]*cebpf.Map{perSampleCounterEnabledMapName: nil}
	for _, counter := range perSampleTopdownCounterMaps {
		maps[counter.mapName] = nil
	}
	tr := &Tracer{ebpfMaps: maps, perfEventSysfsRoot: t.TempDir()}
	existing := new(perf.Event)
	events := []*perf.Event{existing}

	err := tr.openPerSampleTopdown(&events, []int{0})
	require.ErrorContains(t, err, "read PMU type")
	require.Equal(t, []*perf.Event{existing}, events)
}
