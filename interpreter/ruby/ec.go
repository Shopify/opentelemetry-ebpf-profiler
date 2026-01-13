package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"debug/elf"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// extractEcOffset extracts the ec offset from disassembly
func extractEcOffset(ef *pfelf.File) (int64, error) {
	symbolName := libpf.SymbolName("rb_current_ec_noinline")
	_, code, err := ef.SymbolData(symbolName, 2048)
	if err != nil {
		found := false
		if err = ef.VisitSymbols(func(s libpf.Symbol) bool {
			if s.Name == symbolName {
				data, err := ef.VirtualMemory(int64(s.Address), int(s.Size), 2048)
				if err != nil {
					log.Errorf("Failed to read memory for %s, %v", symbolName, err)
				} else {
					code = data
					found = true
				}
				return false
			}
			return true
		}); err != nil {
			log.Warnf("failed to visit symbols: %v", err)
		}

		if !found {
			return 0, fmt.Errorf("unable to read 'rb_current_ec_noinline': %s", err)
		}
	}
	if len(code) < 8 {
		return 0, fmt.Errorf("rb_current_ec_noinline function size is %d", len(code))
	}
	var offset int64
	switch ef.Machine {
	case elf.EM_X86_64:
		offset, err = extractRubyECOffsetX86(code)
	case elf.EM_AARCH64:
		offset, err = extractRubyECOffsetARM(code)
	default:
		return 0, fmt.Errorf("unsupported arch %s", ef.Machine.String())
	}
	return offset, nil
}
