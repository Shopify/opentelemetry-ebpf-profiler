// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usertarget

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func validTarget() Target {
	return Target{
		Name:    "test",
		Process: ProcessSelector{ExecutableName: "server"},
		Object:  ObjectSelector{Basename: "server"},
		SymbolCandidates: []string{
			"server_lock",
		},
	}
}

func TestNormalizeBuildID(t *testing.T) {
	tests := map[string]string{
		"":         "",
		" 0xAABB ": "aabb",
		"0XAABB":   "aabb",
	}
	for input, expected := range tests {
		actual, err := normalizeBuildID(input)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
	for _, input := range []string{"abc", "zz", strings.Repeat("ab", 65)} {
		_, err := normalizeBuildID(input)
		require.Error(t, err)
	}
}

func TestTargetValidationDefaultsAndNormalizes(t *testing.T) {
	target := validTarget()
	target.Object.BuildID = "0xAABB"
	target.Offsets = []BuildIDOffset{{FileOffset: 0x1234}}

	validated, err := target.validated()
	require.NoError(t, err)
	require.Equal(t, "aabb", validated.Object.BuildID)
	require.Equal(t, "aabb", validated.Offsets[0].BuildID)
	require.Equal(t, DefaultMaxLinks, validated.MaxLinks)
}

func TestTargetValidationRejectsUnsafeDescriptors(t *testing.T) {
	tests := map[string]struct {
		mutate    func(*Target)
		errorText string
	}{
		"missing name": {
			mutate:    func(target *Target) { target.Name = "" },
			errorText: "name is empty",
		},
		"missing process selector": {
			mutate:    func(target *Target) { target.Process = ProcessSelector{} },
			errorText: "process selector",
		},
		"missing object selector": {
			mutate:    func(target *Target) { target.Object = ObjectSelector{} },
			errorText: "object selector",
		},
		"missing points": {
			mutate:    func(target *Target) { target.SymbolCandidates = nil },
			errorText: "symbols or offsets",
		},
		"duplicate symbol": {
			mutate: func(target *Target) {
				target.SymbolCandidates = []string{"server_lock", "server_lock"}
			},
			errorText: "duplicate symbol",
		},
		"zero offset": {
			mutate: func(target *Target) {
				target.Offsets = []BuildIDOffset{{BuildID: "aabb"}}
			},
			errorText: "file_offset must be non-zero",
		},
		"unscoped offset": {
			mutate: func(target *Target) {
				target.SymbolCandidates = nil
				target.Offsets = []BuildIDOffset{{FileOffset: 1}}
			},
			errorText: "not scoped to a build_id",
		},
		"invalid build id": {
			mutate:    func(target *Target) { target.Object.BuildID = "xyz" },
			errorText: "invalid object build_id",
		},
		"duplicate offset": {
			mutate: func(target *Target) {
				target.Offsets = []BuildIDOffset{
					{BuildID: "aabb", FileOffset: 1},
					{BuildID: "AABB", FileOffset: 1},
				}
			},
			errorText: "duplicates a previous",
		},
		"mismatched offset build id": {
			mutate: func(target *Target) {
				target.Object.BuildID = "aabb"
				target.Offsets = []BuildIDOffset{{BuildID: "ccdd", FileOffset: 1}}
			},
			errorText: "does not match object build_id",
		},
		"unbounded links": {
			mutate:    func(target *Target) { target.MaxLinks = MaximumMaxLinks + 1 },
			errorText: "max_links must be in the range",
		},
		"unbounded resolved points": {
			mutate:    func(target *Target) { target.MaxResolvedPoints = maxSymbolPoints + 1 },
			errorText: "max_resolved_points must be in the range",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			target := validTarget()
			test.mutate(&target)
			_, err := target.validated()
			require.ErrorContains(t, err, test.errorText)
		})
	}
}
