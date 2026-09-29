// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/ebpf-profiler/process"
)

func TestFindJITRegionExcludesVsyscall(t *testing.T) {
	vsyscall := process.RawMapping{Vaddr: 0xffffffffff600000, Length: 4096, Flags: elf.PF_X}
	mappings := []process.RawMapping{
		{Vaddr: 0x1000, Length: 0x2000, Flags: elf.PF_R | elf.PF_X},
		vsyscall,
	}
	start, end, found := findJITRegion(mappings)
	assert.True(t, found)
	assert.Equal(t, uint64(0x1000), start)
	assert.Equal(t, uint64(0x3000), end)
	_, _, found = findJITRegion([]process.RawMapping{vsyscall})
	assert.False(t, found)
}
