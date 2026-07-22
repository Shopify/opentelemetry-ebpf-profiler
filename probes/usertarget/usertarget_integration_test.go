//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usertarget

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

func TestPIDScopedUserspaceTargetAttachment(t *testing.T) {
	restore, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restore()

	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "usertarget_noop",
		Type:    ebpf.Kprobe,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	require.NoError(t, err)
	defer program.Close()

	child := exec.Command("sleep", "30")
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	pid := libpf.PID(child.Process.Pid)
	proc := process.New(pid, pid)
	defer proc.Close()
	var meta process.ProcessMeta
	var mappings []process.RawMapping
	manager, err := New(Target{
		Name:             "integration",
		Process:          ProcessSelector{ExecutableName: "sleep"},
		Object:           ObjectSelector{Basename: "libc.so.6"},
		SymbolCandidates: []string{"nanosleep"},
		MaxLinks:         2,
	}, Programs{Entry: program, Return: program}, Options{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		meta = proc.GetProcessMeta(process.MetaConfig{})
		mappings = mappings[:0]
		hasLibc := false
		_, iterateErr := proc.IterateMappings(func(mapping process.RawMapping) bool {
			if mapping.IsExecutable() && mapping.IsFileBacked() {
				mapping.Path = strings.Clone(mapping.Path)
				mappings = append(mappings, mapping)
				hasLibc = hasLibc || filepath.Base(mapping.Path) == "libc.so.6"
			}
			return true
		})
		identity, identityErr := tracer.ReadProcessIdentity(pid)
		if iterateErr != nil || identityErr != nil || !hasLibc ||
			strings.TrimSpace(meta.Name.String()) != "sleep" {
			return false
		}
		manager.ProcessSynchronized(tracer.ProcessEvent{
			PID: pid, TID: pid, Identity: identity, Meta: meta, Mappings: mappings,
		})
		return manager.Snapshot().ActiveLinks == 2
	}, 2*time.Second, 10*time.Millisecond)
	stats := manager.Snapshot()
	if stats.ActiveLinks != 2 {
		paths := make([]string, 0, len(mappings))
		for _, mapping := range mappings {
			paths = append(paths, mapping.Path)
		}
		t.Logf("stats=%+v process=%q mappings=%v", stats, meta.Name.String(), paths)
	}
	require.Equal(t, uint64(2), stats.ActiveLinks)
	require.NoError(t, manager.Close())
	require.Zero(t, manager.Snapshot().ActiveLinks)
}
