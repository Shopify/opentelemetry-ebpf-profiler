// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
)

// attachToTracepoint attaches an eBPF program of type tracepoint to a tracepoint in the kernel
// defined by group and name.
// Otherwise it returns an error.
func (t *Tracer) attachToTracepoint(group, name string, prog *ebpf.Program) error {
	hp := hookPoint{
		group: group,
		name:  name,
	}
	hook, err := link.Tracepoint(hp.group, hp.name, prog, nil)
	if err != nil {
		return fmt.Errorf("failed to configure tracepoint on %#v: %v", hp, err)
	}
	t.hooks[hp] = hook
	return nil
}

// AttachSchedMonitor attaches tracepoints for process exec and exit. Exec
// invalidates stale per-PID metadata before surviving uprobes can emit for the
// replacement image; exit enables cleanup of process-scoped state.
func (t *Tracer) AttachSchedMonitor() error {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("failed to adjust rlimit: %v", err)
	}

	defer restoreRlimit()

	execHookPoint := hookPoint{group: "sched", name: "sched_process_exec"}
	if err := t.attachToTracepoint(execHookPoint.group, execHookPoint.name,
		t.ebpfProgs[schedProcessExec]); err != nil {
		return err
	}

	name := schedProcessFreeHookName(libpf.MapKeysToSet(t.ebpfProgs))
	if err := t.attachToTracepoint("sched", "sched_process_free", t.ebpfProgs[name]); err != nil {
		// Keep the pair transactional when startup fails.
		_ = t.hooks[execHookPoint].Close()
		delete(t.hooks, execHookPoint)
		return err
	}
	return nil
}
