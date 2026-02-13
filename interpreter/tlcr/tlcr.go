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
// (custom_labels_current_set_v2) using a 3-path architecture:
//
//	Path 1 — TLSDESC: The linker emitted a TLSDESC relocation (named or by addend).
//	At runtime the TLSDESC GOT entry contains the resolved TP offset in its second
//	slot. This is the fastest path and the common case for shared libraries.
//
//	Path 2 — link_map: The symbol is found in .symtab but no TLSDESC relocation
//	exists. At Attach time, we walk the dynamic linker's link_map chain to get the
//	authoritative module ID (l_tls_modid) and static TLS offset (l_tls_offset).
//	If l_tls_offset is valid, we use it as a direct TP offset (fast path).
//	Otherwise, we fall back to DTV with the authoritative module ID.
//	This replaces the old DTPMOD-based strategies.
//
//	Path 3 — Local Exec TLS: For statically linked binaries (no PT_INTERP / no
//	.dynamic section) where the linker resolved the TP offset at link time.
//	We compute the offset from the PT_TLS segment and st_value using the ELF TLS ABI.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Path 1a: TLSDESC with symbol name (external TLS references)
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

	// Look up symbol in .symtab — needed for all remaining paths.
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

	// Path 1b: TLSDESC by addend (TLS variable defined in the same .so)
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

	// Path 2 vs Path 3: check if binary has a dynamic linker
	if hasDynamicLinker(ef) {
		// Path 2: Dynamic binary — resolve via link_map at Attach time
		log.Debugf("TLCR: found %s in .symtab of %s (st_value=0x%X), will use link_map",
			tlsSymbolName, info.FileName(), tlsSymbolOffset)
		return &data{
			fileName:     info.FileName(),
			symbolOffset: uint64(tlsSymbolOffset),
			arch:         ef.Machine,
			needsLinkMap: true,
		}, nil
	}

	// Path 3: Static binary — compute Local Exec TP offset
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

// hasDynamicLinker returns true if the ELF has a PT_INTERP or .dynamic section,
// indicating it's a dynamically linked binary/shared library.
func hasDynamicLinker(ef *pfelf.File) bool {
	for i := range ef.Progs {
		if ef.Progs[i].Type == elf.PT_INTERP || ef.Progs[i].Type == elf.PT_DYNAMIC {
			return true
		}
	}
	return false
}

// computeLocalExecTPOffset computes the thread-pointer-relative offset for a TLS
// variable in the main executable's initial TLS block, using the ELF TLS ABI.
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
// populate TlcrProcInfo for the BPF map. Exactly one of three access paths
// is active depending on which Loader path succeeded:
//
//   - TLSDESC (default):          tlsDescElfAddr is set. At Attach, we read the
//     resolved TP offset from the TLSDESC GOT entry (second slot).
//   - link_map (needsLinkMap):    fileName and symbolOffset are set. At Attach, we
//     walk the link_map chain to get module ID and l_tls_offset.
//   - Static (useStaticTLS):      staticTPOffset is pre-computed by the Loader.
type data struct {
	tlsDescElfAddr libpf.Address // ELF address of TLSDESC GOT entry (Path 1)
	fileName       string        // .so path for link_map matching (Path 2)
	symbolOffset   uint64        // st_value for link_map path (Path 2)
	arch           elf.Machine   // Target architecture (Path 2)
	staticTPOffset int64         // Pre-computed TP offset (Path 3)
	needsLinkMap   bool          // Resolve via link_map at Attach time
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

	switch {
	case d.needsLinkMap:
		res, err := resolveTLSViaLinkMap(pid, rm, d.fileName, d.arch)
		if err != nil {
			return nil, fmt.Errorf("TLCR: link_map resolution failed for PID %d: %w", pid, err)
		}

		if isValidStaticTLSOffset(res.tlsOffset) {
			// Fast path: static TLS from link_map (no DTV needed at runtime)
			tpOff := computeStaticTPOffset(res.tlsOffset, d.symbolOffset, d.arch)
			log.Debugf("TLCR: PID %d link_map static TLS, l_tls_offset=0x%X, TP offset=%d",
				pid, res.tlsOffset, tpOff)
			procInfo = support.TlcrProcInfo{
				Tls_tpbase_offset: tpOff,
			}
		} else {
			// DTV path with authoritative module ID from link_map
			log.Debugf("TLCR: PID %d link_map DTV, module_id=%d, symbol_offset=%d",
				pid, res.modID, d.symbolOffset)
			procInfo = support.TlcrProcInfo{
				Tls_symbol_offset: d.symbolOffset,
				Tls_module_id:     res.modID,
				Dtv_offset:        res.dtv.offset,
				Dtv_step:          res.dtv.step,
				Dtv_indirect:      res.dtv.indirect,
				Use_dtv:           1,
			}
		}

	case d.useStaticTLS:
		log.Debugf("TLCR: PID %d Local Exec TLS, TP offset %d", pid, d.staticTPOffset)
		procInfo = support.TlcrProcInfo{
			Tls_tpbase_offset: d.staticTPOffset,
		}

	default: // TLSDESC
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
