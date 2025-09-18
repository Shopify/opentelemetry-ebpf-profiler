// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MemoryRegion represents a memory mapping from /proc/PID/maps
type MemoryRegion struct {
	Start       uint64
	End         uint64
	Permissions string
	Offset      uint64
	Device      string
	Inode       uint64
	Pathname    string
}

// ProcessMemoryInfo holds information about process memory layout
type ProcessMemoryInfo struct {
	PID         int
	TextSection *MemoryRegion  // Main executable text section
	BaseAddress uint64         // Base load address of the executable
	YJITRegions []MemoryRegion // YJIT memory regions
	AllRegions  []MemoryRegion // All memory regions
}

// ParseProcessMemory parses /proc/PID/maps and extracts memory layout info
func ParseProcessMemory(pid int) (*ProcessMemoryInfo, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open maps file: %w", err)
	}
	defer file.Close()

	info := &ProcessMemoryInfo{
		PID:         pid,
		YJITRegions: make([]MemoryRegion, 0),
		AllRegions:  make([]MemoryRegion, 0),
	}

	scanner := bufio.NewScanner(file)
	rubyBinaryPath := ""
	
	for scanner.Scan() {
		line := scanner.Text()
		region, err := parseMapsLine(line)
		if err != nil {
			continue
		}

		info.AllRegions = append(info.AllRegions, region)

		// Check if this is a YJIT region
		if strings.Contains(region.Pathname, "rb_yjit_reserve_addr_space") {
			info.YJITRegions = append(info.YJITRegions, region)
		}

		// Find the Ruby binary and its text section
		if strings.HasSuffix(region.Pathname, "/ruby") || 
		   strings.Contains(region.Pathname, "/ruby-") {
			if info.TextSection == nil && strings.Contains(region.Permissions, "x") {
				info.TextSection = &region
				info.BaseAddress = region.Start - region.Offset
				rubyBinaryPath = region.Pathname
			} else if region.Pathname == rubyBinaryPath && info.BaseAddress == 0 {
				info.BaseAddress = region.Start - region.Offset
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading maps file: %w", err)
	}

	// If we didn't find a text section, try to find any executable section
	if info.TextSection == nil {
		for _, region := range info.AllRegions {
			if strings.Contains(region.Permissions, "x") && 
			   (strings.Contains(region.Pathname, "ruby") || region.Pathname == "") {
				info.TextSection = &region
				if region.Pathname != "" {
					info.BaseAddress = region.Start - region.Offset
				}
				break
			}
		}
	}

	return info, nil
}

// parseMapsLine parses a single line from /proc/PID/maps
func parseMapsLine(line string) (MemoryRegion, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return MemoryRegion{}, fmt.Errorf("invalid maps line: %s", line)
	}

	addresses := strings.Split(fields[0], "-")
	if len(addresses) != 2 {
		return MemoryRegion{}, fmt.Errorf("invalid address range: %s", fields[0])
	}

	start, err := strconv.ParseUint(addresses[0], 16, 64)
	if err != nil {
		return MemoryRegion{}, fmt.Errorf("invalid start address: %s", addresses[0])
	}

	end, err := strconv.ParseUint(addresses[1], 16, 64)
	if err != nil {
		return MemoryRegion{}, fmt.Errorf("invalid end address: %s", addresses[1])
	}

	offset, err := strconv.ParseUint(fields[2], 16, 64)
	if err != nil {
		return MemoryRegion{}, fmt.Errorf("invalid offset: %s", fields[2])
	}

	inode, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return MemoryRegion{}, fmt.Errorf("invalid inode: %s", fields[4])
	}

	pathname := ""
	if len(fields) > 5 {
		pathname = strings.Join(fields[5:], " ")
	}

	return MemoryRegion{
		Start:       start,
		End:         end,
		Permissions: fields[1],
		Offset:      offset,
		Device:      fields[3],
		Inode:       inode,
		Pathname:    pathname,
	}, nil
}

// GetYJITRange returns the complete YJIT address range (from first to last region)
func (p *ProcessMemoryInfo) GetYJITRange() (start, end uint64, found bool) {
	if len(p.YJITRegions) == 0 {
		return 0, 0, false
	}

	// Get the start of the first YJIT region
	start = p.YJITRegions[0].Start
	
	// Get the end of the last YJIT region
	end = p.YJITRegions[len(p.YJITRegions)-1].End
	
	return start, end, true
}

// GetYJITRangeRelative returns the YJIT range relative to text section
func (p *ProcessMemoryInfo) GetYJITRangeRelative() (startOffset, endOffset int64, found bool) {
	start, end, found := p.GetYJITRange()
	if !found || p.TextSection == nil {
		return 0, 0, false
	}

	startOffset = int64(start) - int64(p.TextSection.Start)
	endOffset = int64(end) - int64(p.TextSection.Start)
	
	return startOffset, endOffset, true
}

// IsInYJITRange checks if an address falls within the complete YJIT range
func (p *ProcessMemoryInfo) IsInYJITRange(addr uint64) bool {
	start, end, found := p.GetYJITRange()
	if !found {
		return false
	}
	return addr >= start && addr < end
}

// PrintYJITRange outputs the YJIT range in a simple format
func (p *ProcessMemoryInfo) PrintYJITRange() {
	start, end, found := p.GetYJITRange()
	if !found {
		fmt.Printf("No YJIT regions found\n")
		return
	}

	fmt.Printf("YJIT Range (absolute):\n")
	fmt.Printf("  Start: 0x%016x\n", start)
	fmt.Printf("  End:   0x%016x\n", end)
	fmt.Printf("  Size:  %d MB\n", (end-start)/(1024*1024))

	if p.TextSection != nil {
		startOffset, endOffset, _ := p.GetYJITRangeRelative()
		fmt.Printf("\nYJIT Range (relative to text at 0x%x):\n", p.TextSection.Start)
		fmt.Printf("  Start: text + 0x%x\n", startOffset)
		fmt.Printf("  End:   text + 0x%x\n", endOffset)
	}
}
