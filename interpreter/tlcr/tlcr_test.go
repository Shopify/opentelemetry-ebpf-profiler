// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tlcr // import "go.opentelemetry.io/ebpf-profiler/interpreter/tlcr"

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestComputeLocalExecTPOffset(t *testing.T) {
	tests := map[string]struct {
		machine  elf.Machine
		stValue  uint64
		tlsAlign uint64
		tlsMemsz uint64
		expected int64
	}{
		"arm64 basic": {
			machine:  elf.EM_AARCH64,
			stValue:  0x18,
			tlsAlign: 8,
			tlsMemsz: 0x60,
			// round_up(16, 8) + 0x18 = 16 + 24 = 40 = 0x28
			expected: 0x28,
		},
		"arm64 large alignment": {
			machine:  elf.EM_AARCH64,
			stValue:  0x10,
			tlsAlign: 64,
			tlsMemsz: 0x100,
			// round_up(16, 64) + 0x10 = 64 + 16 = 80
			expected: 80,
		},
		"arm64 zero offset": {
			machine:  elf.EM_AARCH64,
			stValue:  0,
			tlsAlign: 8,
			tlsMemsz: 0x08,
			// round_up(16, 8) + 0 = 16
			expected: 16,
		},
		"x86_64 basic": {
			machine:  elf.EM_X86_64,
			stValue:  0x18,
			tlsAlign: 8,
			tlsMemsz: 0x60,
			// -(round_up(0x60, 8) - 0x18) = -(96 - 24) = -72
			expected: -72,
		},
		"x86_64 single variable": {
			machine:  elf.EM_X86_64,
			stValue:  0,
			tlsAlign: 8,
			tlsMemsz: 8,
			// -(round_up(8, 8) - 0) = -8
			expected: -8,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ef := &pfelf.File{
				Machine: tc.machine,
				Progs: []pfelf.Prog{
					{
						ProgHeader: elf.ProgHeader{
							Type:  elf.PT_TLS,
							Memsz: tc.tlsMemsz,
							Align: tc.tlsAlign,
						},
					},
				},
			}

			offset, err := computeLocalExecTPOffset(ef, tc.stValue)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, offset, "TP offset mismatch")
		})
	}
}

func TestComputeLocalExecTPOffset_NoTLS(t *testing.T) {
	ef := &pfelf.File{
		Machine: elf.EM_AARCH64,
		Progs: []pfelf.Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD}},
		},
	}
	_, err := computeLocalExecTPOffset(ef, 0x18)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no PT_TLS segment")
}

func TestComputeLocalExecTPOffset_UnsupportedArch(t *testing.T) {
	ef := &pfelf.File{
		Machine: elf.EM_MIPS,
		Progs: []pfelf.Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_TLS, Memsz: 64, Align: 8}},
		},
	}
	_, err := computeLocalExecTPOffset(ef, 0x18)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported architecture")
}

func TestRoundUp(t *testing.T) {
	assert.Equal(t, uint64(16), roundUp(16, 8))
	assert.Equal(t, uint64(64), roundUp(16, 64))
	assert.Equal(t, uint64(8), roundUp(1, 8))
	assert.Equal(t, uint64(16), roundUp(16, 16))
	assert.Equal(t, uint64(0), roundUp(0, 8))
}
