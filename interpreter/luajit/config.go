// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

// BPFMapName is the name of the eBPF map holding per-process LuaJIT state.
const BPFMapName = "luajit_procs"

// Config holds LuaJIT-specific configuration.
type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`

	// Executables lists additional executable base names that statically link
	// the LuaJIT runtime and should be probed for the interpreter, in addition
	// to the built-in set (the libluajit-5.1.so shared library and the
	// well-known hosts nginx/openresty). This lets binaries that embed LuaJIT
	// (e.g. "tarantool") opt in via configuration, without changing the code.
	Executables []string `mapstructure:"executables" json:"executables,omitempty"`
}

var _ interpreter.Config = Config{}

// GetLoader returns the LuaJIT interpreter loader for the given config. The
// loader probes the built-in LuaJIT executables plus any additional
// statically-linked hosts configured via Config.Executables.
func GetLoader(cfg Config) interpreter.Loader {
	extraExecutables := cfg.Executables
	return func(ebpf interpreter.EbpfHandler,
		info *interpreter.LoaderInfo) (interpreter.Data, error) {
		return loadLuaJIT(ebpf, info, extraExecutables)
	}
}
