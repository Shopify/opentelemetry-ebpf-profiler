// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/*
Ruby stores its current, running execution context in thread local storage (TLS)
In order to reliably access this, we need:

- The $fs_base location, where TLS variables are stored
  - We can get this from ptrace in userspace, or the kernel task struct in BPF
- The index within the DTV, which is dependant on the *load* order of the library
  - The code here provides this, basically by acting like 'ldd'
- The width of the DTV entries (eg, 2 byte with glibc, 1 byte with musl)
  - The code here provides this by checking the library list and pattern matching
- The TLS symbol index within the module-indexed DTV
  - This is easy, it is in the ELF symbol table

In memory:
--$fs_base--
DTV layout is the same across architectures:
DTV[0] = generation counter
DTV[1] = module 1's TLS block
DTV[2] = module 2's TLS block
etc.

DTV layout is like:
DTV[1]: map[usize]usize

Where lookup would be like:
tls_var_value = DTV[MODULE_INDEX][ELF_TLS_SYMBOL]

Very importantly, the module index is determined by the order that it is
**loaded into memory**, not its **position in the memory map**.

So this tool aims to mimic what ldd does, determining all of the linked libraries.
We cannot just use the ELF file for this, we need to look at a running process.
Factors like LD_LIBRARY_PATH and LD_PRELOAD make this difficult to compute, so
the most reliable way to get this load order is from the running process itself,
as the linker has already computed all of this, and written this information to
is to parse /proc/PID/auxv, and locate the link map and parse this out of memory.

Once we have the link map, we check the ELF files for TLS sections, and assign
them a module ID based on the order we found them in.

Since this also gives us a list of all linked libraries, we can use this to
pretty reliably determine which libc was being used. We need this to know the
width of DTV entries when reading them.

Ruby frequently has libruby.so at module index 1, but it also frequently uses
LD_PRELOAD in particular for loading jemalloc. It may also LD_PRELOAD other
libraries, so we can't just rely on convention - the safest thing to do is to
look it up to ensure the profiler will get a valid TLS.
*/

package ruby

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/spf13/afero"
)

var fs = afero.NewOsFs()

// Runtime linker structures not available in standard packages
type rDebug struct {
	Version  int32
	_        int32  // padding
	LinkMap  uint64 // struct link_map *
	LdBrk    uint64
	State    int32
	_        int32 // padding
	LdBase   uint64
	Loader   uint64
	LdLoaded int32
	_        int32 // padding
}

type linkMap struct {
	LAddr uint64 // Base address shared object is loaded at
	LName uint64 // Absolute pathname where object was found (char*)
	LLd   uint64 // Dynamic section of the shared object (Elf64_Dyn*)
	LNext uint64 // Chain of loaded objects (struct link_map*)
	LPrev uint64 // Previous in chain
}

type libraryInfo struct {
	name        string
	path        string
	baseAddress uint64
	isVirtual   bool
	loadOrder   int
	hasTLS      bool
}

type linkmapInspector struct {
	pid       int
	rm        io.ReaderAt
	libraries *[]libraryInfo
}

func newLinkmapInspector(pid int, rm io.ReaderAt) (*linkmapInspector, error) {
	return &linkmapInspector{
		pid: pid,
		rm:  rm,
	}, nil
}

func (pi *linkmapInspector) close() error {
	return nil
}

func (pi *linkmapInspector) readMemory(addr uint64, size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := pi.rm.ReadAt(buf, int64(addr))
	if err != nil {
		return buf, err
	}
	return buf, nil
}

func (pi *linkmapInspector) readString(addr uint64) (string, error) {
	var result []byte
	offset := uint64(0)

	for {
		buf, err := pi.readMemory(addr+offset, 256)
		if err != nil {
			if len(result) > 0 {
				return string(result), nil
			}
			return "", err
		}

		idx := bytes.IndexByte(buf, 0)
		if idx >= 0 {
			result = append(result, buf[:idx]...)
			break
		}

		result = append(result, buf...)
		offset += uint64(len(buf))

		if len(result) > 4096 {
			break
		}
	}

	return string(result), nil
}

func (pi *linkmapInspector) getAuxVector() (map[uint64]uint64, error) {
	auxvPath := fmt.Sprintf("/proc/%d/auxv", pi.pid)
	data, err := afero.ReadFile(fs, auxvPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read auxv: %v", err)
	}

	auxv := make(map[uint64]uint64)
	reader := bytes.NewReader(data)

	for {
		var typ, val uint64
		if err := binary.Read(reader, binary.LittleEndian, &typ); err != nil {
			break
		}
		if err := binary.Read(reader, binary.LittleEndian, &val); err != nil {
			break
		}
		if typ == 0 {
			break
		}
		auxv[typ] = val
	}

	return auxv, nil
}

// Check if a library has a TLS section by reading its ELF header and program headers
func (pi *linkmapInspector) hasTLSSection(baseAddr uint64) bool {
	// Read ELF header
	ehdrBuf, err := pi.readMemory(baseAddr, int(unsafe.Sizeof(elf.Header64{})))
	if err != nil {
		return false
	}

	var ehdr elf.Header64
	reader := bytes.NewReader(ehdrBuf)
	if err := binary.Read(reader, binary.LittleEndian, &ehdr); err != nil {
		return false
	}

	// Verify ELF magic
	if ehdr.Ident[0] != '\x7f' || ehdr.Ident[1] != 'E' ||
		ehdr.Ident[2] != 'L' || ehdr.Ident[3] != 'F' {
		return false
	}

	// Read program headers
	phOffset := baseAddr + ehdr.Phoff
	for i := uint16(0); i < ehdr.Phnum; i++ {
		phAddr := phOffset + uint64(i)*uint64(ehdr.Phentsize)

		phBuf, err := pi.readMemory(phAddr, int(unsafe.Sizeof(elf.Prog64{})))
		if err != nil {
			continue
		}

		var phdr elf.Prog64
		reader := bytes.NewReader(phBuf)
		if err := binary.Read(reader, binary.LittleEndian, &phdr); err != nil {
			continue
		}

		if elf.ProgType(phdr.Type) == elf.PT_TLS {
			return true
		}
	}

	return false
}

// Get the base address of the main executable (for PIE binaries)
func (pi *linkmapInspector) getMainExecutableBase(auxv map[uint64]uint64) (uint64, error) {
	// AT_PHDR from auxv
	const AT_PHDR = 3
	const AT_PHENT = 4
	const AT_PHNUM = 5

	phdr := auxv[AT_PHDR]
	if phdr == 0 {
		return 0, fmt.Errorf("AT_PHDR not found")
	}

	phent := auxv[AT_PHENT]
	phnum := auxv[AT_PHNUM]

	for i := uint64(0); i < phnum; i++ {
		phdrAddr := phdr + i*phent

		buf, err := pi.readMemory(phdrAddr, int(unsafe.Sizeof(elf.Prog64{})))
		if err != nil {
			continue
		}

		var ph elf.Prog64
		reader := bytes.NewReader(buf)
		if err := binary.Read(reader, binary.LittleEndian, &ph); err != nil {
			continue
		}

		if elf.ProgType(ph.Type) == elf.PT_PHDR {
			base := phdr - ph.Vaddr
			return base, nil
		}
	}
	return 0, fmt.Errorf("could not determine main executable base address")
}

func (pi *linkmapInspector) findDynamicSection(phdr uint64, phent uint64, phnum uint64, baseAddr uint64) (uint64, error) {
	for i := uint64(0); i < phnum; i++ {
		phdrAddr := phdr + i*phent

		buf, err := pi.readMemory(phdrAddr, int(unsafe.Sizeof(elf.Prog64{})))
		if err != nil {
			return 0, fmt.Errorf("failed to read program header %d: %v", i, err)
		}

		var ph elf.Prog64
		reader := bytes.NewReader(buf)
		if err := binary.Read(reader, binary.LittleEndian, &ph); err != nil {
			continue
		}

		if elf.ProgType(ph.Type) == elf.PT_DYNAMIC {
			dynAddr := ph.Vaddr
			if dynAddr < 0x400000 {
				dynAddr += baseAddr
			}
			return dynAddr, nil
		}
	}

	return 0, fmt.Errorf("PT_DYNAMIC segment not found")
}

func (pi *linkmapInspector) findDebugPtr(dynAddr uint64) (uint64, error) {
	maxEntries := 1000

	for i := 0; i < maxEntries; i++ {
		addr := dynAddr + uint64(i*16)

		buf, err := pi.readMemory(addr, 16)
		if err != nil {
			return 0, fmt.Errorf("failed to read dynamic entry at 0x%x: %v", addr, err)
		}

		var dyn elf.Dyn64
		reader := bytes.NewReader(buf)
		if err := binary.Read(reader, binary.LittleEndian, &dyn); err != nil {
			return 0, fmt.Errorf("failed to parse dynamic entry: %v", err)
		}

		if elf.DynTag(dyn.Tag) == elf.DT_NULL {
			break
		}

		// DT_DEBUG is not defined in the elf package
		const DT_DEBUG = 21
		if dyn.Tag == DT_DEBUG {
			if dyn.Val == 0 {
				return 0, fmt.Errorf("DT_DEBUG found but value is NULL")
			}
			return dyn.Val, nil
		}
	}

	return 0, fmt.Errorf("DT_DEBUG not found")
}

// Get the link map starting point from r_debug
func (pi *linkmapInspector) getLinkMapStart() (uint64, error) {
	// Constants for auxiliary vector
	const (
		AT_PHDR  = 3
		AT_PHENT = 4
		AT_PHNUM = 5
	)

	// Get auxiliary vector
	auxv, err := pi.getAuxVector()
	if err != nil {
		return 0, fmt.Errorf("failed to get auxiliary vector: %v", err)
	}

	phdr := auxv[AT_PHDR]
	phent := auxv[AT_PHENT]
	phnum := auxv[AT_PHNUM]

	// Get base address for PIE binaries
	baseAddr, _ := pi.getMainExecutableBase(auxv)

	// Find dynamic section
	dynAddr, err := pi.findDynamicSection(phdr, phent, phnum, baseAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to find dynamic section: %v", err)
	}

	// Find debug pointer
	debugPtr, err := pi.findDebugPtr(dynAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to find debug pointer: %v", err)
	}

	// Read r_debug structure
	buf, err := pi.readMemory(debugPtr, int(unsafe.Sizeof(rDebug{})))
	if err != nil {
		return 0, fmt.Errorf("failed to read r_debug structure: %v", err)
	}

	var rd rDebug
	reader := bytes.NewReader(buf)
	if err := binary.Read(reader, binary.LittleEndian, &rd); err != nil {
		return 0, fmt.Errorf("failed to parse r_debug: %v", err)
	}

	if rd.Version != 1 {
		return 0, fmt.Errorf("unexpected r_debug version: %d", rd.Version)
	}

	if rd.LinkMap == 0 {
		return 0, fmt.Errorf("link map pointer is NULL")
	}

	return rd.LinkMap, nil
}

// getLoadedLibraries returns all loaded libraries in their load order
func (pi *linkmapInspector) getLoadedLibraries() ([]libraryInfo, error) {
	if pi.libraries != nil {
		return *pi.libraries, nil
	}
	linkMapStart, err := pi.getLinkMapStart()
	if err != nil {
		return nil, err
	}

	var libraries []libraryInfo
	current := linkMapStart
	loadOrder := 0
	maxLibraries := 1000

	for current != 0 && loadOrder < maxLibraries {
		buf, err := pi.readMemory(current, int(unsafe.Sizeof(linkMap{})))
		if err != nil {
			return nil, fmt.Errorf("failed to read link map entry at 0x%x: %v", current, err)
		}

		var lm linkMap
		reader := bytes.NewReader(buf)
		if err := binary.Read(reader, binary.LittleEndian, &lm); err != nil {
			return nil, fmt.Errorf("failed to parse link map entry: %v", err)
		}

		info := libraryInfo{
			baseAddress: lm.LAddr,
			loadOrder:   loadOrder,
		}

		// Read library name if available
		if lm.LName != 0 {
			name, err := pi.readString(lm.LName)
			if err == nil && name != "" {
				info.path = name
				info.name = filepath.Base(name)

				// Check if it's a virtual DSO
				if strings.Contains(name, "linux-vdso") ||
					strings.Contains(name, "linux-gate") ||
					strings.HasPrefix(name, "[") {
					info.isVirtual = true
				}
			}
		} else if loadOrder == 0 {
			// Main executable usually has empty name
			info.name = "[main]"
			info.path = ""
		}

		// Check for TLS section if base address is valid
		if lm.LAddr != 0 {
			info.hasTLS = pi.hasTLSSection(lm.LAddr)
		}

		libraries = append(libraries, info)
		current = lm.LNext
		loadOrder++
	}

	if loadOrder == maxLibraries {
		return nil, fmt.Errorf("too many libraries (limit: %d)", maxLibraries)
	}

	pi.libraries = &libraries

	return libraries, nil
}

// findTLSModuleID finds the TLS module ID for a specific library
func (pi *linkmapInspector) findTLSModuleID(targetLibrary string) (int, error) {
	libraries, err := pi.getLoadedLibraries()
	if err != nil {
		return 0, err
	}

	tlsModuleID := 0

	for _, lib := range libraries {
		// If it has TLS, increment the module ID
		if lib.hasTLS {
			tlsModuleID++
		}

		// Check if this is the target library
		if lib.path != "" && strings.Contains(lib.path, targetLibrary) {
			if lib.hasTLS {
				return tlsModuleID, nil
			} else {
				return 0, fmt.Errorf("%s does not have a TLS section", targetLibrary)
			}
		}
	}

	return 0, fmt.Errorf("%s not found in loaded libraries", targetLibrary)
}

// libcType represents the C library implementation
type libcType int

const (
	libcUnknown libcType = iota
	libcGlibc
	libcMusl
)

func (lt libcType) String() string {
	switch lt {
	case libcGlibc:
		return "glibc"
	case libcMusl:
		return "musl"
	default:
		return "unknown"
	}
}

func detectLibc(libs []libraryInfo) libcType {
	for _, lib := range libs {
		// musl detection - the loader/libc is typically named ld-musl-*.so.1
		// Examples:
		// - /lib/ld-musl-x86_64.so.1
		// - /lib/ld-musl-aarch64.so.1
		// - /lib/libc.musl-x86_64.so.1 (Alpine Linux)
		if strings.Contains(lib.path, "ld-musl") || strings.Contains(lib.path, "libc.musl") {
			return libcMusl
		}

		// glibc detection - look for the characteristic libc.so.6
		// Examples:
		// - /lib/x86_64-linux-gnu/libc.so.6
		// - /lib64/libc.so.6
		// - /usr/lib/libc.so.6
		if strings.Contains(lib.name, "libc.so.6") || strings.Contains(lib.path, "libc.so.6") {
			return libcGlibc
		}

		// Alternative glibc detection - look for the loader
		// - /lib64/ld-linux-x86-64.so.2
		// - /lib/ld-linux.so.2
		if strings.Contains(lib.path, "ld-linux") && strings.Contains(lib.path, ".so.2") {
			return libcGlibc
		}
	}
	return libcUnknown
}
