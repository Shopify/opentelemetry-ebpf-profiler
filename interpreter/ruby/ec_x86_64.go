package ruby

import (
	"errors"
	//"fmt"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"golang.org/x/arch/x86/x86asm"
)

// extractRubyECOffsetX86 extracts the Ruby EC (execution context) offset from x86_64 assembly
func extractRubyECOffsetX86(code []byte) (int64, error) {
	it := amd.NewInterpreterWithCode(code)
	_, err := it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.RET
	})
	if err != nil {
		return 0, err
	}
	res := it.Regs.Get(amd.RAX)

	offset := e.NewImmediateCapture("offset")

	// Match: mov %fs:offset,%rax
	// The result should be a memory read from FS segment
	expected := e.Mem8(
		e.Add(
			e.MemWithSegment8(x86asm.FS, e.Imm(0)),
			offset,
		),
	)

	if res.Match(expected) {
		return int64(int32(offset.CapturedValue())), nil
	}

	// Try direct segment access pattern
	expected = e.MemWithSegment8(x86asm.FS, offset)
	if res.Match(expected) {
		return int64(int32(offset.CapturedValue())), nil
	}

	return 0, errors.New("could not extract Ruby EC offset from x86_64 code")
}
