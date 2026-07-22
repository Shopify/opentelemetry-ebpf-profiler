// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package usertarget resolves and maintains PID-scoped uprobes from runtime
// process, mapped-object, symbol, and build-ID descriptors.
package usertarget // import "go.opentelemetry.io/ebpf-profiler/probes/usertarget"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// DefaultMaxLinks bounds the number of live kernel links owned by one target.
	DefaultMaxLinks = uint32(1024)
	// MaximumMaxLinks is the hard configuration ceiling for one target.
	MaximumMaxLinks     = uint32(64 * 1024)
	maxSymbolPoints     = 32
	maxBuildIDHexLength = 128
)

// ProcessSelector matches exact /proc process metadata. At least one field is
// required; multiple fields are ANDed.
type ProcessSelector struct {
	ExecutableName string `mapstructure:"executable_name" yaml:"executable_name"`
	ExecutablePath string `mapstructure:"executable_path" yaml:"executable_path"`
}

// ObjectSelector matches exact executable file mappings. At least one field is
// required; multiple fields are ANDed. BuildID is lowercase hexadecimal, with
// an optional 0x prefix accepted on input.
type ObjectSelector struct {
	Basename string `mapstructure:"basename" yaml:"basename"`
	Path     string `mapstructure:"path" yaml:"path"`
	BuildID  string `mapstructure:"build_id" yaml:"build_id"`
}

// BuildIDOffset identifies a verified executable file offset for one exact
// ELF build. BuildID is mandatory unless Object.BuildID supplies it.
type BuildIDOffset struct {
	BuildID    string `mapstructure:"build_id" yaml:"build_id"`
	FileOffset uint64 `mapstructure:"file_offset" yaml:"file_offset"`
}

// Target is a symbol-agnostic runtime attachment descriptor. Symbol aliases
// and build-ID-scoped offsets may be supplied together; resolved duplicate
// file offsets are attached only once.
type Target struct {
	Name             string          `mapstructure:"name" yaml:"name"`
	Process          ProcessSelector `mapstructure:"process" yaml:"process"`
	Object           ObjectSelector  `mapstructure:"object" yaml:"object"`
	SymbolCandidates []string        `mapstructure:"symbol_candidates" yaml:"symbol_candidates"`
	Offsets          []BuildIDOffset `mapstructure:"offsets" yaml:"offsets"`
	MaxLinks         uint32          `mapstructure:"max_links" yaml:"max_links"`
	// MaxResolvedPoints rejects a mapped object when its descriptor resolves
	// to more distinct executable offsets. Zero permits every configured point.
	MaxResolvedPoints uint32 `mapstructure:"max_resolved_points" yaml:"max_resolved_points"`
}

func normalizeBuildID(value string) (string, error) {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if value == "" {
		return "", nil
	}
	if len(value) > maxBuildIDHexLength {
		return "", fmt.Errorf("must not exceed %d hexadecimal characters", maxBuildIDHexLength)
	}
	if len(value)%2 != 0 {
		return "", errors.New("must contain an even number of hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("must be hexadecimal")
	}
	return value, nil
}

// Validate normalizes and validates a runtime target descriptor.
func (target Target) Validate() (Target, error) {
	if target.Name == "" {
		return Target{}, errors.New("userspace target name is empty")
	}
	if len(target.Name) > 128 {
		return Target{}, errors.New("userspace target name exceeds 128 bytes")
	}
	if target.Process.ExecutableName == "" && target.Process.ExecutablePath == "" {
		return Target{}, errors.New("userspace target requires a process selector")
	}
	if target.Object.Basename == "" && target.Object.Path == "" && target.Object.BuildID == "" {
		return Target{}, errors.New("userspace target requires an object selector")
	}
	if len(target.SymbolCandidates) == 0 && len(target.Offsets) == 0 {
		return Target{}, errors.New("userspace target requires symbols or offsets")
	}
	if len(target.SymbolCandidates)+len(target.Offsets) > maxSymbolPoints {
		return Target{}, fmt.Errorf("userspace target has more than %d symbol points", maxSymbolPoints)
	}

	seenSymbols := make(map[string]struct{}, len(target.SymbolCandidates))
	for _, symbol := range target.SymbolCandidates {
		if symbol == "" {
			return Target{}, errors.New("userspace target contains an empty symbol")
		}
		if len(symbol) > 512 {
			return Target{}, errors.New("userspace target symbol exceeds 512 bytes")
		}
		if _, exists := seenSymbols[symbol]; exists {
			return Target{}, fmt.Errorf("userspace target contains duplicate symbol %q", symbol)
		}
		seenSymbols[symbol] = struct{}{}
	}

	var err error
	target.Object.BuildID, err = normalizeBuildID(target.Object.BuildID)
	if err != nil {
		return Target{}, fmt.Errorf("invalid object build_id: %w", err)
	}
	seenOffsets := make(map[BuildIDOffset]struct{}, len(target.Offsets))
	for index := range target.Offsets {
		offset := &target.Offsets[index]
		// cilium/ebpf uses Address == 0 to request symbol lookup, so a raw
		// offset of zero cannot be represented by the attachment API.
		if offset.FileOffset == 0 {
			return Target{}, fmt.Errorf("offset %d file_offset must be non-zero", index)
		}
		offset.BuildID, err = normalizeBuildID(offset.BuildID)
		if err != nil {
			return Target{}, fmt.Errorf("invalid offset %d build_id: %w", index, err)
		}
		if offset.BuildID == "" {
			offset.BuildID = target.Object.BuildID
		}
		if offset.BuildID == "" {
			return Target{}, fmt.Errorf("offset %d is not scoped to a build_id", index)
		}
		if target.Object.BuildID != "" && offset.BuildID != target.Object.BuildID {
			return Target{}, fmt.Errorf("offset %d build_id does not match object build_id", index)
		}
		if _, exists := seenOffsets[*offset]; exists {
			return Target{}, fmt.Errorf("offset %d duplicates a previous build_id/file_offset", index)
		}
		seenOffsets[*offset] = struct{}{}
	}

	if target.MaxLinks == 0 {
		target.MaxLinks = DefaultMaxLinks
	}
	if target.MaxLinks > MaximumMaxLinks {
		return Target{}, fmt.Errorf("max_links must be in the range [1, %d]", MaximumMaxLinks)
	}
	if target.MaxResolvedPoints > maxSymbolPoints {
		return Target{}, fmt.Errorf("max_resolved_points must be in the range [0, %d]", maxSymbolPoints)
	}
	return target, nil
}

func (target Target) validated() (Target, error) {
	return target.Validate()
}
