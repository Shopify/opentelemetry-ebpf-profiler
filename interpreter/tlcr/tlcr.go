// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package tlcr implements a pseudo-interpreter handler that detects shared libraries
// or executables exporting the Thread-Local Context Record (TLCR) TLS variable and
// configures the eBPF profiler to read trace context (trace_id, span_id) from it
// during CPU sampling.
package tlcr // import "go.opentelemetry.io/ebpf-profiler/interpreter/tlcr"

import (
	"debug/elf"
	"fmt"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const tlsSymbolName = "custom_labels_current_set_v2"

// ARM64 glibc tcbhead_t is 16 bytes (DTV pointer + private pointer).
const arm64TCBSize = 16

// Loader implements interpreter.Loader for TLCR-enabled libraries and executables.
//
// It scans every loaded ELF file for the TLCR TLS variable symbol
// (custom_labels_current_set_v2) using a 4-strategy fallback that covers
// most ELF TLS access models:
//
//	Strategy 1 — Named TLSDESC: The linker emitted a TLSDESC relocation with the
//	symbol name. This is the common case for shared libraries that reference a TLS
//	variable defined in another .so. At runtime the TLSDESC GOT entry contains the
//	resolved TP offset in its second slot.
//	(context-reader equivalent: TlsLocation::SharedLibrary with tlsdesc)
//
//	Strategy 2 — TLSDESC by addend: The TLS variable is defined in the same .so
//	that uses it, so the linker emits an anonymous TLSDESC relocation with the
//	symbol's st_value as the addend. We find the symbol in .symtab first, then
//	match it against TLSDESC relocations by addend.
//	(context-reader equivalent: same SharedLibrary path, matched by offset)
//
//	Strategy 3 — DTPMOD/DTPOFF: For dlopen'd libraries that lack TLSDESC support,
//	the linker emits DTPMOD64 + DTPOFF64 relocation pairs. At runtime we read the
//	module ID from the GOT entry and walk the Dynamic Thread Vector (DTV) in BPF.
//	(context-reader equivalent: DTV lookup with module_id)
//
//	Strategy 4 — Local Exec TLS: For statically linked binaries or main executables
//	where the linker resolved the TP offset at link time. No TLS relocations exist;
//	we compute the offset from the PT_TLS segment and st_value using the ELF TLS ABI:
//	  ARM64 (variant 1): TP + round_up(tcb_size, p_align) + st_value
//	  x86_64 (variant 2): TP - round_up(p_memsz, p_align) + st_value
//	(context-reader equivalent: TlsLocation::MainExecutable)
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Strategy 1: TLSDESC with symbol name (external TLS references)
	var tlsDescElfAddr libpf.Address
	if err = ef.VisitTLSRelocations(func(r pfelf.ElfReloc, symName string) bool {
		if symName == tlsSymbolName {
			tlsDescElfAddr = libpf.Address(r.Off)
			return false
		}
		return true
	}); err != nil {
		log.Debugf("TLCR: failed to visit TLS relocations for %s: %v", info.FileName(), err)
	}

	if tlsDescElfAddr != 0 {
		log.Debugf("TLCR: found named TLSDESC for %s at 0x%08X in %s",
			tlsSymbolName, tlsDescElfAddr, info.FileName())
		return &data{
			tlsDescElfAddr: tlsDescElfAddr,
		}, nil
	}

	// Strategy 2: Find symbol in .symtab, then match against anonymous TLSDESC by addend.
	// This handles the case where the TLS variable is defined in the same .so
	// and the linker emits TLSDESC with addend (no symbol name).
	var tlsSymbolOffset libpf.SymbolValue
	found := false
	if err = ef.VisitSymbols(func(s libpf.Symbol) bool {
		if s.Name == tlsSymbolName {
			tlsSymbolOffset = s.Address
			found = true
			return false
		}
		return true
	}); err != nil {
		// .symtab missing is normal for stripped system libraries
	}

	if !found {
		return nil, nil
	}

	// Found the TLS symbol. Now find the TLSDESC relocation whose addend matches.
	if err = ef.VisitTLSRelocations(func(r pfelf.ElfReloc, _ string) bool {
		if libpf.SymbolValue(r.Addend) == tlsSymbolOffset {
			tlsDescElfAddr = libpf.Address(r.Off)
			return false
		}
		return true
	}); err != nil {
		log.Debugf("TLCR: failed to visit TLS relocations for addend match in %s: %v",
			info.FileName(), err)
	}

	if tlsDescElfAddr != 0 {
		log.Debugf("TLCR: found TLSDESC by addend 0x%X at 0x%08X in %s",
			tlsSymbolOffset, tlsDescElfAddr, info.FileName())
		return &data{
			tlsDescElfAddr: tlsDescElfAddr,
		}, nil
	}

	// Strategy 3: DTPMOD (for dlopen'd libraries without TLSDESC)
	var moduleIdOffset libpf.Address
	var symbolOffset uint64
	foundDTPMOD := false

	if err = ef.VisitRelocations(func(r pfelf.ElfReloc, symName string) bool {
		if symName == tlsSymbolName {
			moduleIdOffset = libpf.Address(r.Off)
			foundDTPMOD = true
			return false
		}
		return true
	}, func(rela pfelf.ElfReloc) bool {
		ty := rela.Info & 0xffff
		return (ef.Machine == elf.EM_AARCH64 && elf.R_AARCH64(ty) == elf.R_AARCH64_TLS_DTPMOD64) ||
			(ef.Machine == elf.EM_X86_64 && elf.R_X86_64(ty) == elf.R_X86_64_DTPMOD64)
	}); err != nil {
		log.Debugf("TLCR: failed to visit DTPMOD relocations for %s: %v", info.FileName(), err)
	}

	if foundDTPMOD {
		if err = ef.VisitRelocations(func(r pfelf.ElfReloc, symName string) bool {
			if symName == tlsSymbolName {
				symbolOffset = uint64(r.Addend)
				return false
			}
			return true
		}, func(rela pfelf.ElfReloc) bool {
			ty := rela.Info & 0xffff
			return (ef.Machine == elf.EM_AARCH64 && elf.R_AARCH64(ty) == elf.R_AARCH64_TLS_DTPREL64) ||
				(ef.Machine == elf.EM_X86_64 && elf.R_X86_64(ty) == elf.R_X86_64_DTPOFF64)
		}); err != nil {
			log.Debugf("TLCR: failed to visit DTPOFF relocations for %s: %v", info.FileName(), err)
		}

		log.Debugf("TLCR: found DTPMOD for %s at 0x%08X, symbol offset %d in %s",
			tlsSymbolName, moduleIdOffset, symbolOffset, info.FileName())

		return &data{
			moduleIdOffset: moduleIdOffset,
			symbolOffset:   symbolOffset,
			useDTV:         true,
		}, nil
	}

	// Strategy 4: Local Exec TLS (static binaries / main executables).
	// No TLS relocations exist because the linker resolved the TP offset at link time.
	// Compute the offset from the thread pointer using the PT_TLS segment and the
	// ELF TLS ABI for the target architecture.
	tpOffset, err := computeLocalExecTPOffset(ef, uint64(tlsSymbolOffset))
	if err != nil {
		log.Debugf("TLCR: symbol %s found in .symtab of %s but cannot compute TP offset: %v",
			tlsSymbolName, info.FileName(), err)
		return nil, nil
	}

	log.Debugf("TLCR: found Local Exec TLS for %s in %s, TP offset %d (0x%X)",
		tlsSymbolName, info.FileName(), tpOffset, tpOffset)

	return &data{
		staticTPOffset: tpOffset,
		useStaticTLS:   true,
	}, nil
}

// computeLocalExecTPOffset computes the thread-pointer-relative offset for a TLS
// variable in the main executable's initial TLS block, using the ELF TLS ABI.
//
// This is Strategy 4 in the Loader and corresponds to TlsLocation::MainExecutable
// in the reference context-reader (research/ctx-sharing-demo/context-reader/).
// The reference implementation additionally supports reading l_tls_offset from
// glibc's link_map for shared library static TLS; we don't need that because
// Strategies 1-3 cover shared libraries via relocations.
//
// Architecture formulas (from the ELF TLS specification):
//   - ARM64 (variant 1): TP + round_up(tcb_size, p_align) + st_value
//     TP (TPIDR_EL0) points to the TCB; TLS block grows upward after it.
//     glibc tcbhead_t is 16 bytes (dtv pointer + private pointer).
//   - x86_64 (variant 2): TP - round_up(p_memsz, p_align) + st_value
//     TP (FS_BASE) points to the TCB; TLS block grows downward before it.
func computeLocalExecTPOffset(ef *pfelf.File, stValue uint64) (int64, error) {
	var tlsMemsz, tlsAlign uint64
	foundTLS := false
	for i := range ef.Progs {
		if ef.Progs[i].Type == elf.PT_TLS {
			tlsMemsz = ef.Progs[i].Memsz
			tlsAlign = ef.Progs[i].Align
			if tlsAlign == 0 {
				tlsAlign = 1
			}
			foundTLS = true
			break
		}
	}
	if !foundTLS {
		return 0, fmt.Errorf("no PT_TLS segment")
	}

	switch ef.Machine {
	case elf.EM_AARCH64:
		// TLS variant 1: TLS block is above TP, after the TCB header.
		tcbAligned := roundUp(arm64TCBSize, tlsAlign)
		return int64(tcbAligned + stValue), nil
	case elf.EM_X86_64:
		// TLS variant 2: TLS block is below TP.
		tlsBlockSize := roundUp(tlsMemsz, tlsAlign)
		return -int64(tlsBlockSize) + int64(stValue), nil
	default:
		return 0, fmt.Errorf("unsupported architecture %s for Local Exec TLS", ef.Machine)
	}
}

func roundUp(val, align uint64) uint64 {
	return (val + align - 1) &^ (align - 1)
}

// data holds the TLS resolution result from Loader, used at Attach time to
// populate TlcrProcInfo for the BPF map. Exactly one of the three access modes
// is active depending on which Loader strategy succeeded:
//
//   - TLSDESC (default):   tlsDescElfAddr is set. At Attach, we read the resolved
//     TP offset from the TLSDESC GOT entry (second slot).
//   - DTV (useDTV=true):   moduleIdOffset and symbolOffset are set. At Attach, we
//     read the runtime module ID from the GOT and pass it to
//     BPF for DTV array indexing.
//   - Static (useStaticTLS=true): staticTPOffset is pre-computed by the Loader via
//     computeLocalExecTPOffset. No runtime reads needed.
type data struct {
	tlsDescElfAddr libpf.Address // ELF address of TLSDESC GOT entry (Strategies 1 & 2)
	moduleIdOffset libpf.Address // ELF address of DTPMOD GOT entry (Strategy 3)
	symbolOffset   uint64        // Symbol offset within TLS block (Strategy 3)
	staticTPOffset int64         // Pre-computed TP offset (Strategy 4)
	useDTV         bool          // Use DTV-based TLS access
	useStaticTLS   bool          // Use pre-computed static TP offset
}

var _ interpreter.Data = &data{}

func (d *data) String() string {
	return "TLCR"
}

// Attach resolves runtime TLS parameters for a specific process and writes
// TlcrProcInfo into the BPF map so maybe_add_tlcr_info() can read the TLCR
// variable during sampling.
func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	var procInfo support.TlcrProcInfo

	if d.useDTV {
		modId := rm.Uint64(bias + d.moduleIdOffset)
		log.Debugf("TLCR: PID %d DTV module ID %d, symbol offset %d",
			pid, modId, d.symbolOffset)
		procInfo = support.TlcrProcInfo{
			Tls_symbol_offset: d.symbolOffset,
			Tls_module_id:     modId,
			Dtv_step:          16,
			Use_dtv:           1,
		}
	} else if d.useStaticTLS {
		log.Debugf("TLCR: PID %d Local Exec TLS, TP offset %d", pid, d.staticTPOffset)
		procInfo = support.TlcrProcInfo{
			Tls_tpbase_offset: d.staticTPOffset,
		}
	} else {
		tlsOffset := int64(rm.Uint64(bias + d.tlsDescElfAddr + 8))
		log.Debugf("TLCR: PID %d TLSDESC tpbase offset %d", pid, tlsOffset)
		procInfo = support.TlcrProcInfo{
			Tls_tpbase_offset: tlsOffset,
		}
	}

	if err := ebpf.UpdateProcData(libpf.TLCR, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	return &instance{}, nil
}

func (d *data) Unload(_ interpreter.EbpfHandler) {}

type instance struct {
	interpreter.InstanceStubs
}

var _ interpreter.Instance = &instance{}

func (i *instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.TLCR, pid)
}
