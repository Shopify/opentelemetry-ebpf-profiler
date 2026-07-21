// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package memory // import "go.opentelemetry.io/ebpf-profiler/probes/memory"

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// allocatorInjector performs explicitly enabled, destructive process mutation.
// Implementations must never be constructed for InjectionDisabled.
type allocatorInjector interface {
	Inject(pid libpf.PID, expectedExecutable libpf.String) (InjectionResult, error)
}

// errUnsafeTraceeTerminated marks the exceptional fail-closed path where the
// injector sent SIGKILL because it could not safely restore remote-call state.
var errUnsafeTraceeTerminated = errors.New("injector terminated unsafe tracee")

// InjectionResult describes which interposition mechanism an injected shim
// reported. It is intentionally diagnostic only: hook discovery remains the
// source of truth for whether the profiler can attach.
type InjectionResult struct {
	AlreadyPresent      bool
	GOTMallocPatched    bool
	GOTFreePatched      bool
	InlineMallocPatched bool
	InlineFreePatched   bool
	PatchedSlots        uint32
}

func (r InjectionResult) String() string {
	return fmt.Sprintf(
		"already_present=%t got_malloc=%t got_free=%t inline_malloc=%t inline_free=%t slots=%d",
		r.AlreadyPresent, r.GOTMallocPatched, r.GOTFreePatched,
		r.InlineMallocPatched, r.InlineFreePatched, r.PatchedSlots)
}
