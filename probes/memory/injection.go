// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package memory // import "go.opentelemetry.io/ebpf-profiler/probes/memory"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// allocatorInjector performs explicitly enabled, destructive process mutation.
// Implementations must never be constructed for InjectionDisabled.
type allocatorInjector interface {
	Inject(pid libpf.PID) (InjectionResult, error)
}

// InjectionResult describes which interposition mechanism an injected shim
// reported. It is intentionally diagnostic only: hook discovery remains the
// source of truth for whether the profiler can attach.
type InjectionResult struct {
	AlreadyPresent bool
	GOTPatched     bool
	InlinePatched  bool
	PatchedSlots   uint32
}

func (r InjectionResult) String() string {
	return fmt.Sprintf("already_present=%t got=%t inline=%t slots=%d",
		r.AlreadyPresent, r.GOTPatched, r.InlinePatched, r.PatchedSlots)
}
