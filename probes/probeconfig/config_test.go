// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package probeconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/probes/memory"
)

func TestDefaultConfigIsDisabledAndComplete(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.Memory.Enabled)
	assert.NotEmpty(t, cfg.Memory.AllocationHooks)
	assert.NotEmpty(t, cfg.Memory.DeallocationHooks)
	require.NoError(t, cfg.Validate())
}

func TestIsMapEnabled(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.IsMapEnabled("heap_alloc_live"))
	assert.True(t, cfg.IsMapEnabled("pid_page_to_mapping_info"))

	cfg.Memory.Enabled = true
	assert.True(t, cfg.IsMapEnabled("heap_alloc_live"))
	assert.False(t, cfg.IsMapEnabled("heap_pending_allocs"),
		"the default weighted USDT producer does not need allocator entry/return state")

	cfg.Memory.AllocationHooks = []memory.Hook{memory.UprobeHook("libc.so.6", "malloc")}
	assert.True(t, cfg.IsMapEnabled("heap_pending_allocs"))
}
