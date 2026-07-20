// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package probeconfig aggregates typed custom-probe configuration, mirroring
// interpreter/interpreterconfig. Each probe owns its event semantics and
// attachment-specific settings.
package probeconfig // import "go.opentelemetry.io/ebpf-profiler/probes/probeconfig"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/probes/memory"
)

// Config holds configuration for custom profiling probes. Probe zero values
// are disabled so adding a new probe cannot increase baseline overhead.
type Config struct {
	Memory memory.Config `mapstructure:"memory" json:"memory,omitempty"`
}

// DefaultConfig returns the default-off custom-probe configuration.
func DefaultConfig() Config {
	return Config{Memory: memory.DefaultConfig()}
}

// ApplyDefaults fills defaults owned by each typed probe.
func (cfg *Config) ApplyDefaults() {
	cfg.Memory.ApplyDefaults()
}

// Validate validates all typed custom probes.
func (cfg Config) Validate() error {
	if err := cfg.Memory.Validate(); err != nil {
		return fmt.Errorf("memory: %w", err)
	}
	return nil
}

// IsMapEnabled reports whether a map needed only by a custom probe should be
// loaded. Unknown maps are left enabled for backward compatibility.
func (cfg Config) IsMapEnabled(mapName string) bool {
	return cfg.Memory.IsMapEnabled(mapName)
}
