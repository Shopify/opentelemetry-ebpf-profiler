// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tpbase // import "go.opentelemetry.io/ebpf-profiler/tpbase"
import (
	"errors"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"golang.org/x/arch/x86/x86asm"
)

// analyzeDTVOffsetX86 analyzes __tls_get_addr to find the DTV offset from FS base
func analyzeDTVOffsetX86(code []byte) (uint32, error) {
	// We're looking for: mov %fs:offset,%reg
	// This loads the DTV pointer from thread-local storage

	offset := 0
	for offset < len(code) {
		inst, err := x86asm.Decode(code[offset:], 64)
		if err != nil {
			// Try next byte in case of misalignment
			offset++
			continue
		}

		// Check if this is a MOV instruction
		if inst.Op == x86asm.MOV {
			// Check if source operand is a memory reference with FS segment
			if mem, ok := inst.Args[1].(x86asm.Mem); ok {
				if mem.Segment == x86asm.FS {
					// Found it! Extract the displacement (offset)
					return uint32(mem.Disp), nil
				}
			}
		}

		offset += inst.Len

		if inst.Op == x86asm.CMP {
			// Typically this instruction should be near the beginning
			// If we've gone too far, something's wrong
			break
		}
	}

	return 0, errors.New("DTV offset not found: no mov from FS segment found")
}

func extractTSDInfoX86(code []byte) (TSDInfo, error) {
	it := amd.NewInterpreterWithCode(code)
	key := it.Regs.Get(amd.RDI)
	_, err := it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.RET
	})
	if err != nil {
		return TSDInfo{}, err
	}
	res := it.Regs.Get(amd.RAX)
	var (
		multiplier  = e.NewImmediateCapture("multiplier")
		multiplier2 = e.NewImmediateCapture("multiplier2")
		offset      = e.NewImmediateCapture("offset")
	)

	expected := e.Mem8(
		e.Add(
			e.Mem8(
				e.Add(
					e.MemWithSegment8(x86asm.FS, e.Imm(0)),
					offset,
				),
			),
			e.Multiply(
				e.ZeroExtend32(key),
				multiplier),
		),
	)
	if res.Match(expected) {
		return TSDInfo{
			Offset:     int16(offset.CapturedValue()),
			Multiplier: uint8(multiplier.CapturedValue()),
			Indirect:   1,
		}, nil
	}
	expected = e.Mem8(
		e.Add(
			e.MemWithSegment8(x86asm.FS, e.Imm(0x10)),
			e.Multiply(e.ZeroExtend32(key), multiplier),
			offset,
		),
	)
	if res.Match(expected) {
		return TSDInfo{
			Offset:     int16(offset.CapturedValue()),
			Multiplier: uint8(multiplier.CapturedValue()),
			Indirect:   0,
		}, nil
	}
	expected = e.Mem8(
		e.Add(
			e.MemWithSegment8(x86asm.FS, e.Imm(0x10)),
			e.Multiply(
				e.ZeroExtend32(e.Add(key, multiplier2)),
				multiplier,
			),
			offset,
		),
	)
	if res.Match(expected) {
		return TSDInfo{
			Offset: int16(multiplier.CapturedValue()*multiplier2.CapturedValue() +
				offset.CapturedValue()),
			Multiplier: uint8(multiplier.CapturedValue()),
			Indirect:   0,
		}, nil
	}
	return TSDInfo{}, errors.New("could not extract tsdInfo amd")
}
