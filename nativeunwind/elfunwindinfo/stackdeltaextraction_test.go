// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestARM64PLTDeltas(t *testing.T) {
	// plt-arm64.so is built from plt.c, see testdata/Makefile. Its linker emitted no
	// CFI for .plt, so without synthesized deltas a sample inside a PLT stub
	// cannot be unwound.
	const elfFile = "testdata/plt-arm64.so"
	ef, err := pfelf.Open(elfFile)
	require.NoError(t, err)
	defer ef.Close()
	plt := ef.Section(".plt")
	require.NotNil(t, plt)
	require.Greater(t, plt.Size, uint64(arm64PLT0Size))

	intervals, err := Extract(elfFile)
	require.NoError(t, err)

	// PLT0 pushes x16 and x30, so it keeps no deltas.
	assert.Nil(t, intervals.Find(plt.Addr))
	for addr := plt.Addr + arm64PLT0Size; addr < plt.Addr+plt.Size; addr += 4 {
		bb := intervals.Find(addr)
		require.NotNil(t, bb, "no stack delta for PLT address %#x", addr)
		require.Len(t, bb.Deltas, 1)
		assert.Equal(t, sdtypes.UnwindInfoLR, bb.Deltas[0].Info)
	}
	// The .eh_frame deltas of the code calling through the PLT are kept.
	assert.Greater(t, len(intervals.Blocks), 1)
}
