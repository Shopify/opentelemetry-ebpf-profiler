package ruby

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractEcOffset(t *testing.T) {
	testCases := map[string]struct {
		machine elf.Machine
		code    []byte
		offset  int64
	}{
		"ruby 3.4.7 static / x86_64": {
			//machine: elf.EM_AARCH64,
			machine: elf.EM_X86_64,
			code: []byte{
				// mov    %fs:0xfffffffffffffff8,%rax
				// ret
				0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff,
				0xc3,
			},
			offset: -8,
		},
		"ruby 3.4.7 static / aarch64": {
			machine: elf.EM_AARCH64,
			code: []byte{
				0x40, 0xd0, 0x3b, 0xd5, // mrs     x0, tpidr_el0
				0x00, 0x00, 0x40, 0x91, // add     x0, x0, #0x0, lsl #12
				0x00, 0xe0, 0x00, 0x91, // add     x0, x0, #0x38
				0x00, 0x00, 0x40, 0xf9, // ldr     x0, [x0]
				0xc0, 0x03, 0x5f, 0xd6, // ret
			},
			offset: 56,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			var offset int64
			var err error
			switch test.machine {
			case elf.EM_X86_64:
				offset, err = extractRubyECOffsetX86(test.code)
			case elf.EM_AARCH64:
				offset, err = extractRubyECOffsetARM(test.code)
			}
			if assert.NoError(t, err) {
				assert.Equal(t, test.offset, offset, "Wrong ruby EC offset extraction")
			}
		})
	}
}
