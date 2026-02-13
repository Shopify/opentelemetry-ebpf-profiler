// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tlcr // import "go.opentelemetry.io/ebpf-profiler/interpreter/tlcr"

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

type libcType int

const (
	libcGlibc libcType = iota
	libcMusl
)

type tlsFieldOffsets struct {
	modidOffset  uint32 // byte offset of l_tls_modid within link_map
	tlsOffOffset uint32 // byte offset of l_tls_offset within link_map
}

type dtvParams struct {
	offset   int16 // DTV pointer offset from TP (or from indirect base)
	step     uint8 // DTV entry stride (16 glibc, 8 musl)
	indirect uint8 // 1 = read TP:0 first, then add offset
}

type tlsResolution struct {
	modID     uint64
	tlsOffset int64 // l_tls_offset (0 or -1 = invalid, use DTV)
	dtv       dtvParams
}

// glibc link_map field offsets (stable across glibc 2.17–2.40).
// Used as fallback when _thread_db symbol discovery fails.
var defaultGlibcOffsets = map[elf.Machine]tlsFieldOffsets{
	elf.EM_X86_64:  {modidOffset: 0x490, tlsOffOffset: 0x488},
	elf.EM_AARCH64: {modidOffset: 0x498, tlsOffOffset: 0x490},
}

// dtvParamsTable maps (libc, arch) to DTV access parameters.
//
//	glibc x86_64:  DTV = *(TP + 8)          → offset=+8, step=16, indirect=0
//	glibc aarch64: DTV = *(*(TP) + 0)       → offset=0,  step=16, indirect=1
//	musl  x86_64:  DTV = *(*(TP) + 8)       → offset=+8, step=8,  indirect=1
//	musl  aarch64: DTV = *(*(TP) + (-8))    → offset=-8, step=8,  indirect=1
var dtvParamsTable = map[libcType]map[elf.Machine]dtvParams{
	libcGlibc: {
		elf.EM_X86_64:  {offset: 8, step: 16, indirect: 0},
		elf.EM_AARCH64: {offset: 0, step: 16, indirect: 1},
	},
	libcMusl: {
		elf.EM_X86_64:  {offset: 8, step: 8, indirect: 1},
		elf.EM_AARCH64: {offset: -8, step: 8, indirect: 1},
	},
}

// resolveTLSViaLinkMap walks the dynamic linker's link_map chain to find the TLS
// module ID and static TLS offset for the given target file. This replaces the old
// DTPMOD-based strategies (3 and 4) with an authoritative source of module IDs.
func resolveTLSViaLinkMap(pid libpf.PID, rm remotememory.RemoteMemory,
	targetFileName string, arch elf.Machine) (tlsResolution, error) {
	libc, err := detectLibc(pid)
	if err != nil {
		return tlsResolution{}, fmt.Errorf("detect libc: %w", err)
	}

	dtv, ok := getDTVParams(libc, arch)
	if !ok {
		return tlsResolution{}, fmt.Errorf("no DTV params for libc=%d arch=%s", libc, arch)
	}

	var modID uint64
	var tlsOff int64

	switch libc {
	case libcGlibc:
		offsets, err := discoverGlibcFieldOffsets(pid, arch)
		if err != nil {
			log.Debugf("TLCR: field offset discovery failed, using defaults: %v", err)
			var ok bool
			offsets, ok = defaultGlibcOffsets[arch]
			if !ok {
				return tlsResolution{}, fmt.Errorf("no default offsets for arch %s", arch)
			}
		}

		rDebugAddr, err := findRDebugAddr(pid)
		if err != nil {
			return tlsResolution{}, fmt.Errorf("find _r_debug: %w", err)
		}

		modID, tlsOff, err = walkGlibcLinkMap(rm, rDebugAddr, offsets, targetFileName)
		if err != nil {
			return tlsResolution{}, fmt.Errorf("walk link_map: %w", err)
		}
	case libcMusl:
		debugAddr, err := findMuslDebugAddr(pid)
		if err != nil {
			return tlsResolution{}, fmt.Errorf("find musl debug addr: %w", err)
		}

		modID, tlsOff, err = walkMuslDSOChain(rm, debugAddr, targetFileName)
		if err != nil {
			return tlsResolution{}, fmt.Errorf("walk musl DSO chain: %w", err)
		}
	}

	return tlsResolution{
		modID:     modID,
		tlsOffset: tlsOff,
		dtv:       dtv,
	}, nil
}

// detectLibc determines whether the target process uses glibc or musl by scanning
// /proc/<pid>/maps for the dynamic linker name.
func detectLibc(pid libpf.PID) (libcType, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Maps lines end with the pathname, e.g.:
		// 7f...  r-xp ... /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
		// 7f...  r-xp ... /lib/ld-musl-aarch64.so.1
		if idx := strings.LastIndex(line, "/"); idx >= 0 {
			basename := line[idx+1:]
			if strings.HasPrefix(basename, "ld-musl") {
				return libcMusl, nil
			}
			if strings.HasPrefix(basename, "ld-linux") || strings.HasPrefix(basename, "ld-") {
				return libcGlibc, nil
			}
		}
	}
	return 0, fmt.Errorf("could not detect libc for PID %d", pid)
}

// findRDebugAddr locates the _r_debug symbol in the dynamic linker (ld-linux-*.so)
// and returns its absolute address in the target process.
func findRDebugAddr(pid libpf.PID) (uint64, error) {
	ldPath, ldBase, err := findMappingByPrefix(pid, "ld-linux")
	if err != nil {
		return 0, err
	}

	procRoot := fmt.Sprintf("/proc/%d/root", pid)
	ef, err := pfelf.Open(path.Join(procRoot, ldPath))
	if err != nil {
		return 0, fmt.Errorf("open ld.so ELF %s: %w", ldPath, err)
	}
	defer ef.Close()

	sym, err := ef.LookupSymbol("_r_debug")
	if err != nil {
		return 0, fmt.Errorf("_r_debug symbol not found in %s: %w", ldPath, err)
	}

	return ldBase + uint64(sym.Address), nil
}

// findMuslDebugAddr locates the _dl_debug_addr symbol in ld-musl-*.so and returns
// its absolute address in the target process.
func findMuslDebugAddr(pid libpf.PID) (uint64, error) {
	ldPath, ldBase, err := findMappingByPrefix(pid, "ld-musl")
	if err != nil {
		return 0, err
	}

	procRoot := fmt.Sprintf("/proc/%d/root", pid)
	ef, err := pfelf.Open(path.Join(procRoot, ldPath))
	if err != nil {
		return 0, fmt.Errorf("open ld-musl ELF %s: %w", ldPath, err)
	}
	defer ef.Close()

	sym, err := ef.LookupSymbol("_dl_debug_addr")
	if err != nil {
		return 0, fmt.Errorf("_dl_debug_addr not found in %s: %w", ldPath, err)
	}

	return ldBase + uint64(sym.Address), nil
}

// findMappingByPrefix finds the first executable mapping in /proc/<pid>/maps whose
// basename starts with the given prefix. Returns the full path and base address.
func findMappingByPrefix(pid libpf.PID, prefix string) (string, uint64, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Only look at executable mappings
		if !strings.Contains(line, "r-xp") && !strings.Contains(line, "r--p") {
			continue
		}

		pathIdx := strings.LastIndex(line, "/")
		if pathIdx < 0 {
			continue
		}
		fullPath := line[strings.Index(line, "/"):]
		basename := line[pathIdx+1:]

		if strings.HasPrefix(basename, prefix) {
			// Parse the base address from the first field
			addrEnd := strings.Index(line, "-")
			if addrEnd < 0 {
				continue
			}
			base, err := strconv.ParseUint(line[:addrEnd], 16, 64)
			if err != nil {
				continue
			}
			return fullPath, base, nil
		}
	}
	return "", 0, fmt.Errorf("no mapping with prefix %q in PID %d", prefix, pid)
}

// discoverGlibcFieldOffsets reads _thread_db_link_map_l_tls_modid and
// _thread_db_link_map_l_tls_offset symbols from libc.so to discover the byte
// offsets of TLS fields within the link_map struct at runtime.
//
// Each symbol points to a 12-byte descriptor: {uint32 indx, uint32 num, uint32 offset}.
// The offset field (bytes 8-11) gives the byte offset within struct link_map.
func discoverGlibcFieldOffsets(pid libpf.PID, arch elf.Machine) (tlsFieldOffsets, error) {
	libcPath, err := findLibcPath(pid)
	if err != nil {
		return tlsFieldOffsets{}, err
	}

	procRoot := fmt.Sprintf("/proc/%d/root", pid)
	ef, err := pfelf.Open(path.Join(procRoot, libcPath))
	if err != nil {
		return tlsFieldOffsets{}, fmt.Errorf("open libc ELF %s: %w", libcPath, err)
	}
	defer ef.Close()

	modidOff, err := readThreadDBDescriptor(ef, "_thread_db_link_map_l_tls_modid")
	if err != nil {
		return tlsFieldOffsets{}, fmt.Errorf("l_tls_modid: %w", err)
	}

	tlsOffOff, err := readThreadDBDescriptor(ef, "_thread_db_link_map_l_tls_offset")
	if err != nil {
		return tlsFieldOffsets{}, fmt.Errorf("l_tls_offset: %w", err)
	}

	log.Debugf("TLCR: discovered link_map field offsets for %s: "+
		"l_tls_modid=0x%X, l_tls_offset=0x%X", arch, modidOff, tlsOffOff)

	return tlsFieldOffsets{
		modidOffset:  modidOff,
		tlsOffOffset: tlsOffOff,
	}, nil
}

// readThreadDBDescriptor looks up a _thread_db_* symbol in the ELF's symbol
// tables and reads the 12-byte descriptor to extract the offset field.
func readThreadDBDescriptor(ef *pfelf.File, symbolName string) (uint32, error) {
	sym, err := ef.LookupSymbol(libpf.SymbolName(symbolName))
	if err != nil {
		return 0, fmt.Errorf("symbol %s not found: %w", symbolName, err)
	}

	// The symbol points to a 12-byte descriptor in .rodata:
	// struct { uint32_t indx; uint32_t num; uint32_t offset; }
	addr := uint64(sym.Address)

	var desc [12]byte
	if _, err := ef.ReadVirtualMemory(desc[:], int64(addr)); err != nil {
		return 0, fmt.Errorf("read descriptor for %s at 0x%X: %w", symbolName, addr, err)
	}

	offset := binary.LittleEndian.Uint32(desc[8:12])
	return offset, nil
}

// findLibcPath finds the path to libc.so in /proc/<pid>/maps.
// On glibc >= 2.34, _thread_db symbols are in libc.so.6.
// On older glibc, they may be in libpthread.so.
func findLibcPath(pid libpf.PID) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	var libcPath string
	var libpthreadPath string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		pathIdx := strings.LastIndex(line, "/")
		if pathIdx < 0 {
			continue
		}
		fullPath := line[strings.Index(line, "/"):]
		basename := line[pathIdx+1:]

		if strings.HasPrefix(basename, "libc.so") || strings.HasPrefix(basename, "libc-") {
			if libcPath == "" {
				libcPath = fullPath
			}
		}
		if strings.HasPrefix(basename, "libpthread.so") || strings.HasPrefix(basename, "libpthread-") {
			if libpthreadPath == "" {
				libpthreadPath = fullPath
			}
		}
	}

	if libcPath != "" {
		return libcPath, nil
	}
	if libpthreadPath != "" {
		return libpthreadPath, nil
	}
	return "", fmt.Errorf("libc.so not found in PID %d maps", pid)
}

// walkGlibcLinkMap walks the glibc link_map chain starting from _r_debug.r_map
// and returns the l_tls_modid and l_tls_offset for the entry whose l_name matches
// the target path.
//
// glibc link_map layout (public fields at fixed offsets):
//
//	offset 0:  l_addr  (Elf64_Addr)
//	offset 8:  l_name  (char *)
//	offset 16: l_ld    (Elf64_Dyn *)
//	offset 24: l_next  (struct link_map *)
//	offset 32: l_prev  (struct link_map *)
//
// r_debug layout:
//
//	offset 0:  r_version (int)
//	offset 8:  r_map     (struct link_map *)
func walkGlibcLinkMap(rm remotememory.RemoteMemory, rDebugAddr uint64,
	offsets tlsFieldOffsets, targetPath string) (uint64, int64, error) {
	// Read r_map from r_debug (offset 8)
	linkMapAddr := rm.Uint64(libpf.Address(rDebugAddr + 8))
	if linkMapAddr == 0 {
		return 0, 0, fmt.Errorf("r_debug.r_map is NULL")
	}

	targetBasename := path.Base(targetPath)

	for i := 0; i < 512 && linkMapAddr != 0; i++ {
		// Read l_name pointer (offset 8)
		namePtr := rm.Uint64(libpf.Address(linkMapAddr + 8))
		if namePtr != 0 {
			name := rm.String(libpf.Address(namePtr))
			if matchesByBasename(name, targetBasename) {
				modID := rm.Uint64(libpf.Address(linkMapAddr + uint64(offsets.modidOffset)))
				tlsOff := int64(rm.Uint64(libpf.Address(linkMapAddr + uint64(offsets.tlsOffOffset))))

				log.Debugf("TLCR: link_map match %q: module_id=%d, l_tls_offset=0x%X",
					name, modID, tlsOff)
				return modID, tlsOff, nil
			}
		}

		// Read l_next (offset 24)
		linkMapAddr = rm.Uint64(libpf.Address(linkMapAddr + 24))
	}

	return 0, 0, fmt.Errorf("target %q not found in link_map chain", targetPath)
}

// walkMuslDSOChain walks musl's DSO chain to find the target library's TLS info.
//
// musl's _dl_debug_addr is a pointer to struct debug, which contains:
//
//	offset 0:  base (void *)
//	offset 8:  name (char *)
//	...
//	offset 24: next (struct dso *)
//
// The tls_id field is at a hardcoded offset within struct dso.
// musl 1.2.x: tls_id at offset 0xc0 on both x86_64 and aarch64.
const muslDSOTlsIDOffset = 0xc0

func walkMuslDSOChain(rm remotememory.RemoteMemory, debugAddr uint64,
	targetPath string) (uint64, int64, error) {
	// _dl_debug_addr points to the head DSO
	dsoAddr := rm.Uint64(libpf.Address(debugAddr))
	if dsoAddr == 0 {
		return 0, 0, fmt.Errorf("_dl_debug_addr is NULL")
	}

	targetBasename := path.Base(targetPath)

	for i := 0; i < 512 && dsoAddr != 0; i++ {
		// Read name pointer (offset 8 in struct dso)
		namePtr := rm.Uint64(libpf.Address(dsoAddr + 8))
		if namePtr != 0 {
			name := rm.String(libpf.Address(namePtr))
			if matchesByBasename(name, targetBasename) {
				// musl: tls_id is the module ID (similar to glibc's l_tls_modid)
				tlsID := rm.Uint64(libpf.Address(dsoAddr + muslDSOTlsIDOffset))
				// musl does not provide l_tls_offset equivalent;
				// dlopen'd libs always use DTV
				log.Debugf("TLCR: musl DSO match %q: tls_id=%d", name, tlsID)
				return tlsID, -1, nil
			}
		}

		// Read next pointer (offset 24 in struct dso)
		dsoAddr = rm.Uint64(libpf.Address(dsoAddr + 24))
	}

	return 0, 0, fmt.Errorf("target %q not found in musl DSO chain", targetPath)
}

// matchesByBasename checks if a library path matches the target by comparing
// basenames. This handles cases like /usr/lib/x86_64-linux-gnu/libfoo.so matching
// /app/lib/libfoo.so.
func matchesByBasename(fullPath, targetBasename string) bool {
	if fullPath == "" {
		return false
	}
	return path.Base(fullPath) == targetBasename
}

// getDTVParams returns the DTV access parameters for a given libc and architecture.
func getDTVParams(libc libcType, arch elf.Machine) (dtvParams, bool) {
	archMap, ok := dtvParamsTable[libc]
	if !ok {
		return dtvParams{}, false
	}
	params, ok := archMap[arch]
	return params, ok
}

// isValidStaticTLSOffset returns true if the l_tls_offset from link_map is a
// valid static TLS offset (not a sentinel value).
//
// Sentinel values in glibc:
//
//	0  = NO_TLS_OFFSET (undetermined)
//	-1 = FORCED_DYNAMIC_TLS_OFFSET (committed to DTV)
//	-2 = used by some glibc internals
//
// We also reject absurdly large values (> 1GB) as likely corruption.
func isValidStaticTLSOffset(offset int64) bool {
	if offset == 0 || offset == -1 || offset == -2 {
		return false
	}
	const maxReasonableOffset = 1 << 30 // 1GB
	if offset > maxReasonableOffset || offset < -maxReasonableOffset {
		return false
	}
	return true
}

// computeStaticTPOffset computes the final TP-relative offset for a TLS variable
// when the library has a static TLS slot (l_tls_offset is valid).
//
// For x86_64 (variant 2): TP - l_tls_offset + symbol_offset
// For aarch64 (variant 1): TP + l_tls_offset + symbol_offset
func computeStaticTPOffset(ltlsOffset int64, symbolOffset uint64, arch elf.Machine) int64 {
	switch arch {
	case elf.EM_X86_64:
		// Variant 2: TLS block is at negative offset from TP
		return -ltlsOffset + int64(symbolOffset)
	case elf.EM_AARCH64:
		// Variant 1: TLS block is at positive offset from TP
		return ltlsOffset + int64(symbolOffset)
	default:
		return 0
	}
}
