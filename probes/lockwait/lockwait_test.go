// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package lockwait

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/probes/usertarget"
)

func validDefinition() Definition {
	return Definition{
		Target: usertarget.Target{
			Name:             "generic-spin-wait",
			Process:          usertarget.ProcessSelector{ExecutableName: "server"},
			Object:           usertarget.ObjectSelector{Basename: "server"},
			SymbolCandidates: []string{"_Z8SlowLockv"},
		},
		Labels: Labels{
			Kind:      "spinlock",
			Mode:      "exclusive",
			Operation: "lock",
		},
	}
}

func TestNewDefaults(t *testing.T) {
	created, err := New(validDefinition(), nil)
	require.NoError(t, err)

	probe := created.(*lockWaitProbe)
	require.Equal(t, defaultSampleType, probe.definition.SampleType)
	require.Zero(t, probe.minDuration)
	require.Equal(t, uint32(math.MaxUint32), probe.sampleThreshold)
	require.Equal(t, defaultMaxEntries, probe.maxEntries)
	require.Equal(t, usertarget.DefaultMaxLinks, probe.definition.Target.MaxLinks)
	require.Equal(t, uint32(1), probe.definition.Target.MaxResolvedPoints)

	metadata := probe.ReportMetadata()
	require.Equal(t, defaultSampleType, metadata.SampleType)
	require.Equal(t, "nanoseconds", metadata.SampleUnit)
	require.True(t, metadata.ReportValues)
	require.Equal(t, "spinlock", metadata.StaticLabels[libpf.Intern("lock.kind")].String())
	require.Equal(t, "exclusive", metadata.StaticLabels[libpf.Intern("lock.mode")].String())
	require.Equal(t, "lock", metadata.StaticLabels[libpf.Intern("lock.operation")].String())
}

func TestNewConfigured(t *testing.T) {
	definition := validDefinition()
	definition.SampleType = "database_lock_wait"
	definition.ABI.ReturnValueMode = ReturnValueSigned32
	definition.ABI.SuccessfulReturnValues = []int64{0, 130}
	created, err := New(definition, map[string]any{
		"min_duration": "250us",
		"sample_rate":  0.5,
		"max_entries":  4096,
	})
	require.NoError(t, err)

	probe := created.(*lockWaitProbe)
	require.Equal(t, "database_lock_wait", probe.definition.SampleType)
	require.Equal(t, ReturnValueSigned32, probe.definition.ABI.ReturnValueMode)
	require.Equal(t, []int64{0, 130}, probe.definition.ABI.SuccessfulReturnValues)
	require.Equal(t, 250*time.Microsecond, probe.minDuration)
	require.Equal(t, uint32(math.MaxUint32/2), probe.sampleThreshold)
	require.Equal(t, uint32(4096), probe.maxEntries)

	definition.ABI.SuccessfulReturnValues[0] = 99
	require.Equal(t, int64(0), probe.definition.ABI.SuccessfulReturnValues[0])
}

func TestNewRejectsInvalidDescriptor(t *testing.T) {
	tests := map[string]struct {
		mutate    func(*Definition)
		config    any
		errorText string
	}{
		"invalid target": {
			mutate:    func(definition *Definition) { definition.Target.Name = "" },
			errorText: "userspace target name is empty",
		},
		"insufficient target links": {
			mutate: func(definition *Definition) {
				definition.Target.MaxLinks = minimumTargetLinks - 1
			},
			errorText: "max_links must be at least 2",
		},
		"long sample type": {
			mutate: func(definition *Definition) {
				definition.SampleType = strings.Repeat("s", maxSampleTypeBytes+1)
			},
			errorText: "sample type exceeds",
		},
		"empty kind": {
			mutate:    func(definition *Definition) { definition.Labels.Kind = "" },
			errorText: "lock kind is empty",
		},
		"invalid UTF-8 kind": {
			mutate: func(definition *Definition) {
				definition.Labels.Kind = "\xff"
			},
			errorText: "lock kind is not valid UTF-8",
		},
		"long mode": {
			mutate: func(definition *Definition) {
				definition.Labels.Mode = strings.Repeat("m", maxLabelValueBytes+1)
			},
			errorText: "lock mode exceeds",
		},
		"NUL operation": {
			mutate: func(definition *Definition) {
				definition.Labels.Operation = "lock\x00raw"
			},
			errorText: "lock operation contains a NUL byte",
		},
		"unsupported return mode": {
			mutate: func(definition *Definition) {
				definition.ABI.ReturnValueMode = ReturnValueMode(3)
			},
			errorText: "unsupported return value mode 3",
		},
		"signed return out of range": {
			mutate: func(definition *Definition) {
				definition.ABI.ReturnValueMode = ReturnValueSigned32
				definition.ABI.SuccessfulReturnValues = []int64{1 << 31}
			},
			errorText: "does not fit signed 32-bit",
		},
		"unsigned return out of range": {
			mutate: func(definition *Definition) {
				definition.ABI.ReturnValueMode = ReturnValueUnsigned32
				definition.ABI.SuccessfulReturnValues = []int64{-1}
			},
			errorText: "does not fit unsigned 32-bit",
		},
		"duplicate return": {
			mutate: func(definition *Definition) {
				definition.ABI.SuccessfulReturnValues = []int64{0, 0}
			},
			errorText: "duplicate successful return value 0",
		},
		"too many returns": {
			mutate: func(definition *Definition) {
				definition.ABI.SuccessfulReturnValues = []int64{0, 1, 2, 3, 4}
			},
			errorText: "at most 4 successful return values",
		},
		"unknown config": {
			config:    map[string]any{"unknown": true},
			errorText: "unknown lock wait configuration field",
		},
		"bad sample rate": {
			config:    map[string]any{"sample_rate": 0},
			errorText: "sample_rate must be in the range",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			definition := validDefinition()
			if test.mutate != nil {
				test.mutate(&definition)
			}
			_, err := New(definition, test.config)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}
