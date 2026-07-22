// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby

import "testing"

func TestRubyVMExecCoreSymbolMatches(t *testing.T) {
	cases := map[string]bool{
		"vm_exec_core":                 true, // non-LTO / plain symbol
		"vm_exec_core.lto_priv.0":      true, // LTO-privatized hot loop
		"vm_exec_core.lto_priv.1":      true,
		"vm_exec_core.constprop.0":     true,
		"vm_exec_core.lto_priv.0.cold": false, // hot/cold split: cold partition
		"vm_exec_core.cold":            false,
		"vm_exec_loop":                 false, // wrapper, not the dispatch loop
		"rb_vm_exec":                   false, // entry stub (already slot 1)
		"vm_exec_core_helper":          false, // different symbol (no dot boundary)
		"":                             false,
	}
	for name, want := range cases {
		if got := rubyVMExecCoreSymbolMatches(name); got != want {
			t.Errorf("rubyVMExecCoreSymbolMatches(%q) = %v, want %v", name, got, want)
		}
	}
}
