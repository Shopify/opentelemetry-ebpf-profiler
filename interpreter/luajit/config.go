// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

// BPFMapName is the name of the eBPF map holding per-process LuaJIT state.
const BPFMapName = "luajit_procs"

// Config holds LuaJIT-specific configuration.
type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}

// GetLoader returns the LuaJIT interpreter loader for the given config.
func GetLoader(_ Config) interpreter.Loader {
	return Loader
}
