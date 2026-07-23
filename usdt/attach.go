// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// errProgramNotLoaded is returned by attach when no BPF program has been
// registered for the parsed probe's Kind. Reconcile treats this as a soft
// per-probe failure and continues with the rest.
var errProgramNotLoaded = errors.New("usdt: no BPF program registered for probe kind")

// attach creates one PID-scoped uprobe link for a single parsed probe.
//
// Prefer /proc/<pid>/root/<mapping path>. The perf uprobe PMU resolves the
// pathname supplied to perf_event_open; on some kernels a map_files symlink is
// accepted but the resulting event never fires. The root path both enters the
// target mount namespace and resolves to the executable itself. map_files is
// retained as a fallback for deleted/replaced mappings where it is the only
// remaining reference to the mapped inode.
func (m *Manager) attach(
	pid libpf.PID,
	mapping *process.RawMapping,
	p parsedProbe,
) (link.Link, error) {
	prog, ok := m.progs[p.Kind]
	if !ok {
		return nil, errProgramNotLoaded
	}

	paths := make([]string, 0, 2)
	if strings.HasPrefix(mapping.Path, "/") && !strings.HasSuffix(mapping.Path, " (deleted)") {
		paths = append(paths, fmt.Sprintf("/proc/%d/root%s", pid, mapping.Path))
	}
	paths = append(paths, fmt.Sprintf("/proc/%d/map_files/%x-%x",
		pid, mapping.Vaddr, mapping.Vaddr+mapping.Length))

	var attachErrs []error
	for _, path := range paths {
		ex, err := link.OpenExecutable(path)
		if err != nil {
			attachErrs = append(attachErrs, fmt.Errorf("open executable %s: %w", path, err))
			continue
		}

		// Empty symbol: attach by absolute file offset (UprobeOptions.Address),
		// not by symbol lookup. Cookie carries the ProbeKind so the BPF side can
		// dispatch via bpf_get_attach_cookie() if it ever needs to.
		lnk, err := ex.Uprobe("", prog, &link.UprobeOptions{
			PID:          int(pid),
			Address:      p.Location,
			RefCtrOffset: p.SemaphoreOffset,
			Cookie:       uint64(p.Kind),
		})
		if err == nil {
			return lnk, nil
		}
		attachErrs = append(attachErrs,
			fmt.Errorf("attach uprobe at %s+%#x: %w", path, p.Location, err))
	}

	return nil, errors.Join(attachErrs...)
}
