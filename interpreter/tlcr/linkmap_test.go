// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tlcr // import "go.opentelemetry.io/ebpf-profiler/interpreter/tlcr"

import (
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func TestIsValidStaticTLSOffset(t *testing.T) {
	tests := map[string]struct {
		offset int64
		valid  bool
	}{
		"zero":              {offset: 0, valid: false},
		"minus one":         {offset: -1, valid: false},
		"minus two":         {offset: -2, valid: false},
		"positive normal":   {offset: 0x488, valid: true},
		"negative normal":   {offset: -0x100, valid: true},
		"large positive":    {offset: 1 << 31, valid: false},
		"large negative":    {offset: -(1 << 31), valid: false},
		"small positive":    {offset: 16, valid: true},
		"boundary positive": {offset: 1 << 30, valid: true},
		"over boundary":     {offset: (1 << 30) + 1, valid: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.valid, isValidStaticTLSOffset(tc.offset))
		})
	}
}

func TestGetDTVParams(t *testing.T) {
	tests := []struct {
		name     string
		libc     libcType
		arch     elf.Machine
		expected dtvParams
		ok       bool
	}{
		{
			name:     "glibc x86_64",
			libc:     libcGlibc,
			arch:     elf.EM_X86_64,
			expected: dtvParams{offset: 8, step: 16, indirect: 0},
			ok:       true,
		},
		{
			name:     "glibc aarch64",
			libc:     libcGlibc,
			arch:     elf.EM_AARCH64,
			expected: dtvParams{offset: 0, step: 16, indirect: 1},
			ok:       true,
		},
		{
			name:     "musl x86_64",
			libc:     libcMusl,
			arch:     elf.EM_X86_64,
			expected: dtvParams{offset: 8, step: 8, indirect: 1},
			ok:       true,
		},
		{
			name:     "musl aarch64",
			libc:     libcMusl,
			arch:     elf.EM_AARCH64,
			expected: dtvParams{offset: -8, step: 8, indirect: 1},
			ok:       true,
		},
		{
			name: "unsupported arch",
			libc: libcGlibc,
			arch: elf.EM_MIPS,
			ok:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params, ok := getDTVParams(tc.libc, tc.arch)
			assert.Equal(t, tc.ok, ok)
			if ok {
				assert.Equal(t, tc.expected, params)
			}
		})
	}
}

func TestMatchesByBasename(t *testing.T) {
	tests := map[string]struct {
		fullPath       string
		targetBasename string
		expected       bool
	}{
		"exact match":        {"/usr/lib/libfoo.so", "libfoo.so", true},
		"different dir":      {"/app/lib/libfoo.so", "libfoo.so", true},
		"no match":           {"/usr/lib/libbar.so", "libfoo.so", false},
		"empty path":         {"", "libfoo.so", false},
		"empty target":       {"/usr/lib/libfoo.so", "", false},
		"basename only":      {"libfoo.so", "libfoo.so", true},
		"versioned so match": {"/usr/lib/libfoo.so.1.2.3", "libfoo.so.1.2.3", true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expected, matchesByBasename(tc.fullPath, tc.targetBasename))
		})
	}
}

// mockRemoteMemory creates a RemoteMemory backed by a flat byte slice.
type mockReaderAt struct {
	data []byte
}

func (m *mockReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || int(off) >= len(m.data) {
		return 0, nil
	}
	n := copy(p, m.data[off:])
	return n, nil
}

func newMockRemoteMemory(size int) (remotememory.RemoteMemory, *mockReaderAt) {
	mock := &mockReaderAt{data: make([]byte, size)}
	return remotememory.RemoteMemory{ReaderAt: mock}, mock
}

func writeUint64(mock *mockReaderAt, offset int, val uint64) {
	binary.LittleEndian.PutUint64(mock.data[offset:], val)
}

func writeString(mock *mockReaderAt, offset int, s string) {
	copy(mock.data[offset:], s)
	mock.data[offset+len(s)] = 0 // null terminator
}

func TestWalkGlibcLinkMap(t *testing.T) {
	// Build a mock memory layout with r_debug and 3 link_map entries.
	//
	// Layout:
	//   0x1000: r_debug { r_version=1, r_map=0x2000 }
	//   0x2000: link_map entry 1 { l_name -> "ld-linux.so", l_next -> 0x3000, ... }
	//   0x3000: link_map entry 2 { l_name -> "/usr/lib/libfoo.so", l_next -> 0x4000, ... }
	//   0x4000: link_map entry 3 { l_name -> "/app/lib/libtarget.so", l_next -> 0 }
	//
	// link_map public layout:
	//   offset 0:  l_addr
	//   offset 8:  l_name (char *)
	//   offset 16: l_ld
	//   offset 24: l_next
	//   offset 32: l_prev

	rm, mock := newMockRemoteMemory(0x8000)

	// r_debug at 0x1000
	writeUint64(mock, 0x1000+0, 1)      // r_version
	writeUint64(mock, 0x1000+8, 0x2000)  // r_map -> first link_map

	// Entry 1: ld-linux
	writeUint64(mock, 0x2000+0, 0)        // l_addr
	writeUint64(mock, 0x2000+8, 0x5000)   // l_name -> string at 0x5000
	writeUint64(mock, 0x2000+16, 0)       // l_ld
	writeUint64(mock, 0x2000+24, 0x3000)  // l_next -> entry 2
	writeString(mock, 0x5000, "/lib/ld-linux-x86-64.so.2")

	// Entry 2: libfoo.so
	writeUint64(mock, 0x3000+0, 0)        // l_addr
	writeUint64(mock, 0x3000+8, 0x5100)   // l_name -> string at 0x5100
	writeUint64(mock, 0x3000+16, 0)       // l_ld
	writeUint64(mock, 0x3000+24, 0x4000)  // l_next -> entry 3
	writeString(mock, 0x5100, "/usr/lib/libfoo.so")

	// Entry 3: libtarget.so (our target)
	writeUint64(mock, 0x4000+0, 0)        // l_addr
	writeUint64(mock, 0x4000+8, 0x5200)   // l_name -> string at 0x5200
	writeUint64(mock, 0x4000+16, 0)       // l_ld
	writeUint64(mock, 0x4000+24, 0)       // l_next -> NULL (end of chain)
	writeString(mock, 0x5200, "/app/lib/libtarget.so")

	// Write TLS fields for entry 3 at hardcoded glibc x86_64 offsets
	offsets := tlsFieldOffsets{modidOffset: 0x490, tlsOffOffset: 0x488}
	writeUint64(mock, 0x4000+int(offsets.tlsOffOffset), uint64(0x280)) // l_tls_offset
	writeUint64(mock, 0x4000+int(offsets.modidOffset), 5)              // l_tls_modid

	modID, tlsOff, err := walkGlibcLinkMap(rm, 0x1000, offsets, "/app/lib/libtarget.so")
	require.NoError(t, err)
	assert.Equal(t, uint64(5), modID)
	assert.Equal(t, int64(0x280), tlsOff)
}

func TestWalkGlibcLinkMap_NotFound(t *testing.T) {
	rm, mock := newMockRemoteMemory(0x4000)

	// r_debug with a single entry that doesn't match
	writeUint64(mock, 0x1000+8, 0x2000)  // r_map
	writeUint64(mock, 0x2000+8, 0x3000)  // l_name ptr
	writeUint64(mock, 0x2000+24, 0)      // l_next = NULL
	writeString(mock, 0x3000, "/usr/lib/libother.so")

	offsets := tlsFieldOffsets{modidOffset: 0x490, tlsOffOffset: 0x488}
	_, _, err := walkGlibcLinkMap(rm, 0x1000, offsets, "/app/lib/libtarget.so")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in link_map chain")
}

func TestWalkMuslDSOChain(t *testing.T) {
	rm, mock := newMockRemoteMemory(0x8000)

	// _dl_debug_addr at 0x1000 points to first DSO at 0x2000
	writeUint64(mock, 0x1000, 0x2000)

	// DSO entry 1: not our target
	writeUint64(mock, 0x2000+8, 0x5000)   // name ptr
	writeUint64(mock, 0x2000+24, 0x3000)  // next
	writeString(mock, 0x5000, "/lib/libc.so")

	// DSO entry 2: our target
	writeUint64(mock, 0x3000+8, 0x5100)                    // name ptr
	writeUint64(mock, 0x3000+24, 0)                         // next = NULL
	writeUint64(mock, 0x3000+muslDSOTlsIDOffset, 3)        // tls_id = 3
	writeString(mock, 0x5100, "/app/lib/libtarget.so")

	modID, tlsOff, err := walkMuslDSOChain(rm, 0x1000, "/app/lib/libtarget.so")
	require.NoError(t, err)
	assert.Equal(t, uint64(3), modID)
	assert.Equal(t, int64(-1), tlsOff) // musl always returns -1 for tls_offset
}

func TestComputeStaticTPOffset(t *testing.T) {
	tests := map[string]struct {
		ltlsOffset   int64
		symbolOffset uint64
		arch         elf.Machine
		expected     int64
	}{
		"x86_64 typical": {
			ltlsOffset:   0x280,
			symbolOffset: 0x18,
			arch:         elf.EM_X86_64,
			// TP - 0x280 + 0x18 = -(0x280) + 0x18
			expected: -0x280 + 0x18,
		},
		"aarch64 typical": {
			ltlsOffset:   0x200,
			symbolOffset: 0x10,
			arch:         elf.EM_AARCH64,
			// TP + 0x200 + 0x10
			expected: 0x200 + 0x10,
		},
		"x86_64 zero symbol offset": {
			ltlsOffset:   0x100,
			symbolOffset: 0,
			arch:         elf.EM_X86_64,
			expected:     -0x100,
		},
		"unsupported arch": {
			ltlsOffset:   0x100,
			symbolOffset: 0x10,
			arch:         elf.EM_MIPS,
			expected:     0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := computeStaticTPOffset(tc.ltlsOffset, tc.symbolOffset, tc.arch)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestComputeStaticTPOffset_LinkMapX86(t *testing.T) {
	// Simulates a shared library loaded with static TLS on x86_64.
	// l_tls_offset = 0x480, symbol st_value = 0x20
	// Expected: TP - 0x480 + 0x20 = -0x460
	result := computeStaticTPOffset(0x480, 0x20, elf.EM_X86_64)
	assert.Equal(t, int64(-0x460), result)
}

func TestComputeStaticTPOffset_LinkMapAarch64(t *testing.T) {
	// Simulates a shared library loaded with static TLS on aarch64.
	// l_tls_offset = 0x300, symbol st_value = 0x18
	// Expected: TP + 0x300 + 0x18 = 0x318
	result := computeStaticTPOffset(0x300, 0x18, elf.EM_AARCH64)
	assert.Equal(t, int64(0x318), result)
}

func TestWalkGlibcLinkMap_NullRMap(t *testing.T) {
	rm, mock := newMockRemoteMemory(0x2000)
	// r_debug with r_map = NULL
	writeUint64(mock, 0x1000+8, 0) // r_map = NULL

	offsets := tlsFieldOffsets{modidOffset: 0x490, tlsOffOffset: 0x488}
	_, _, err := walkGlibcLinkMap(rm, 0x1000, offsets, "libtarget.so")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "r_debug.r_map is NULL")
}

func TestWalkGlibcLinkMap_MatchByBasename(t *testing.T) {
	rm, mock := newMockRemoteMemory(0x8000)

	// r_debug at 0x1000
	writeUint64(mock, 0x1000+8, 0x2000) // r_map

	// Single entry with a different directory but same basename
	writeUint64(mock, 0x2000+8, 0x5000) // l_name ptr
	writeUint64(mock, 0x2000+24, 0)     // l_next = NULL
	writeString(mock, 0x5000, "/different/path/libtarget.so")

	offsets := tlsFieldOffsets{modidOffset: 0x490, tlsOffOffset: 0x488}
	writeUint64(mock, 0x2000+int(offsets.modidOffset), 7)
	writeUint64(mock, 0x2000+int(offsets.tlsOffOffset), 0x100)

	// Search using a different directory but same basename
	modID, _, err := walkGlibcLinkMap(rm, 0x1000, offsets, "/app/lib/libtarget.so")
	require.NoError(t, err)
	assert.Equal(t, uint64(7), modID)
}

// TestDefaultGlibcOffsetsExist verifies that default offsets exist for supported architectures.
func TestDefaultGlibcOffsetsExist(t *testing.T) {
	for _, arch := range []elf.Machine{elf.EM_X86_64, elf.EM_AARCH64} {
		offsets, ok := defaultGlibcOffsets[arch]
		assert.True(t, ok, "default glibc offsets missing for %s", arch)
		assert.NotZero(t, offsets.modidOffset)
		assert.NotZero(t, offsets.tlsOffOffset)
		// l_tls_offset should come before l_tls_modid in the struct
		assert.Less(t, offsets.tlsOffOffset, offsets.modidOffset,
			"l_tls_offset should be at a lower offset than l_tls_modid")
	}
}

// TestLibcTypeString is a basic sanity check that libcType constants are distinct.
func TestLibcTypeConstants(t *testing.T) {
	assert.NotEqual(t, libcGlibc, libcMusl)
}

// TestWalkMuslDSOChain_NullDebugAddr verifies error when _dl_debug_addr is NULL.
func TestWalkMuslDSOChain_NullDebugAddr(t *testing.T) {
	rm, mock := newMockRemoteMemory(0x2000)
	writeUint64(mock, 0x1000, 0) // _dl_debug_addr = NULL

	_, _, err := walkMuslDSOChain(rm, 0x1000, "libtarget.so")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "_dl_debug_addr is NULL")
}

func TestResolveTLSViaLinkMap_IntegrationPath(t *testing.T) {
	// This test verifies that resolveTLSViaLinkMap returns an error when
	// we can't access /proc/<pid>/maps for a non-existent PID.
	_, err := resolveTLSViaLinkMap(libpf.PID(999999999),
		remotememory.RemoteMemory{}, "libtarget.so", elf.EM_X86_64)
	assert.Error(t, err)
}
