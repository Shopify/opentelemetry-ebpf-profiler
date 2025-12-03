package ruby

import (
	"errors"

	ah "go.opentelemetry.io/ebpf-profiler/armhelpers"
	aa "golang.org/x/arch/arm64/arm64asm"
)

// extractRubyECOffsetARM extracts the Ruby EC offset from aarch64 assembly
func extractRubyECOffsetARM(code []byte) (int64, error) {
	const (
		Unspec int = iota
		ECBase
	)

	type regState struct {
		status int
		offset int64
	}

	// Track all registers
	var regs [32]regState

	for offs := 0; offs < len(code); offs += 4 {
		inst, err := aa.Decode(code[offs:])
		if err != nil {
			continue
		}
		if inst.Op == aa.RET {
			break
		}

		destReg, ok := ah.Xreg2num(inst.Args[0])
		if !ok {
			continue
		}

		switch inst.Op {
		case aa.MRS:
			// MRS X0, tpidr_el0 (S3_3_C13_C0_2)
			if inst.Args[1].String() == "S3_3_C13_C0_2" {
				regs[destReg] = regState{
					status: ECBase,
					offset: 0,
				}
			}
		case aa.ADD:
			srcReg, ok := ah.Xreg2num(inst.Args[1])
			if !ok {
				continue
			}
			if regs[srcReg].status == ECBase {
				i, ok := ah.DecodeImmediate(inst.Args[2])
				if !ok {
					continue
				}
				regs[destReg] = regState{
					status: ECBase,
					offset: regs[srcReg].offset + i,
				}
			}
		case aa.LDR:
			// LDR doesn't change the offset we're calculating
			continue
		}
	}

	// The offset should be in X0 (return register)
	if regs[0].status != ECBase {
		return 0, errors.New("could not extract Ruby EC offset from ARM code")
	}

	return regs[0].offset, nil
}
