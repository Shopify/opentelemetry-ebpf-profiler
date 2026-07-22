// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usertarget

import (
	"debug/elf"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func resolverFixture(t *testing.T) (string, string) {
	t.Helper()
	switch pfelf.CurrentMachine {
	case elf.EM_X86_64:
		return filepath.Join("..", "..", "rust-crates", "symblib", "testdata", "go-1.24.0"),
			"main.main"
	case elf.EM_AARCH64:
		return filepath.Join("..", "..", "rust-crates", "symblib", "testdata", "inline"),
			"main"
	default:
		t.Skipf("unsupported test machine %s", pfelf.CurrentMachine)
		return "", ""
	}
}

func TestResolvePointsDeduplicatesSymbolAndVerifiedOffset(t *testing.T) {
	fixture, symbolName := resolverFixture(t)
	file, err := pfelf.Open(fixture)
	require.NoError(t, err)
	defer file.Close()

	symbols, err := findSymbols(file, []string{symbolName})
	require.NoError(t, err)
	symbol, ok := symbols[symbolName]
	require.True(t, ok)
	fileOffset, ok := executableFileOffset(file, uint64(symbol.Address))
	require.True(t, ok)
	buildID, err := file.GetBuildID()
	require.NoError(t, err)

	target := validTarget()
	target.SymbolCandidates = []string{symbolName}
	target.Offsets = []BuildIDOffset{{BuildID: buildID, FileOffset: fileOffset}}
	target.MaxResolvedPoints = 1
	target, err = target.validated()
	require.NoError(t, err)

	points, gotBuildID, err := resolvePoints(file, target)
	require.NoError(t, err)
	require.Equal(t, target.Offsets[0].BuildID, gotBuildID)
	require.Equal(t, []resolvedPoint{{fileOffset: fileOffset, source: symbolName}}, points)
}

func TestResolvePointsEnforcesMaximumDistinctPoints(t *testing.T) {
	fixture, symbolName := resolverFixture(t)
	file, err := pfelf.Open(fixture)
	require.NoError(t, err)
	defer file.Close()

	symbols, err := findSymbols(file, []string{symbolName})
	require.NoError(t, err)
	symbol, found := symbols[symbolName]
	require.True(t, found)
	fileOffset, ok := executableFileOffset(file, uint64(symbol.Address))
	require.True(t, ok)
	require.True(t, executableOffset(file, fileOffset+1))
	buildID, err := file.GetBuildID()
	require.NoError(t, err)

	target := validTarget()
	target.SymbolCandidates = nil
	target.Offsets = []BuildIDOffset{
		{BuildID: buildID, FileOffset: fileOffset},
		{BuildID: buildID, FileOffset: fileOffset + 1},
	}
	target.MaxResolvedPoints = 1
	target, err = target.Validate()
	require.NoError(t, err)
	_, _, err = resolvePoints(file, target)
	require.ErrorContains(t, err, "resolved 2 points, exceeding configured maximum 1")
}

func TestResolvePointsRejectsCrossArchitecture(t *testing.T) {
	var fixture string
	switch pfelf.CurrentMachine {
	case elf.EM_X86_64:
		fixture = filepath.Join("..", "..", "rust-crates", "symblib", "testdata", "inline")
	case elf.EM_AARCH64:
		fixture = filepath.Join("..", "..", "rust-crates", "symblib", "testdata", "go-1.24.0")
	default:
		t.Skipf("unsupported test machine %s", pfelf.CurrentMachine)
	}
	file, err := pfelf.Open(fixture)
	require.NoError(t, err)
	defer file.Close()

	target, err := validTarget().validated()
	require.NoError(t, err)
	_, _, err = resolvePoints(file, target)
	require.ErrorContains(t, err, "does not match profiler machine")
}

func TestResolvePointsRejectsMissingSymbols(t *testing.T) {
	fixture, _ := resolverFixture(t)
	file, err := pfelf.Open(fixture)
	require.NoError(t, err)
	defer file.Close()

	target := validTarget()
	target.SymbolCandidates = []string{"symbol_that_does_not_exist"}
	target, err = target.validated()
	require.NoError(t, err)
	_, _, err = resolvePoints(file, target)
	require.ErrorContains(t, err, "no configured symbol or offset resolved")
}

func TestResolvePointsRejectsBuildIDMismatch(t *testing.T) {
	fixture, symbolName := resolverFixture(t)
	file, err := pfelf.Open(fixture)
	require.NoError(t, err)
	defer file.Close()

	target := validTarget()
	target.Object.BuildID = "aabb"
	target.SymbolCandidates = []string{symbolName}
	target, err = target.validated()
	require.NoError(t, err)

	_, _, err = resolvePoints(file, target)
	require.ErrorIs(t, err, errObjectMismatch)
}
