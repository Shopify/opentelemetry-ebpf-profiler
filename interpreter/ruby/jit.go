package ruby

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Parses
// https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/jit-interface.txt

// Symbol represents a JIT symbol mapping
type Symbol struct {
	Start uint64
	End   uint64
	Name  string
}

// PerfMap holds the parsed JIT perf map data
type PerfMap struct {
	mu           sync.RWMutex
	symbols      []Symbol
	filename     string
	lastModTime  time.Time
	lastLoadTime time.Time
}

// NewPerfMap creates a new PerfMap instance
func NewPerfMap() *PerfMap {
	return &PerfMap{
		symbols: make([]Symbol, 0),
	}
}

// ParseFile parses a JIT perf map file
// Format: START SIZE name
// Example: 7f2b12345678 1a0 java.lang.String.hashCode()
func (pm *PerfMap) ParseFile(filename string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Get file info for modification time tracking
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Parse the file
	newSymbols := make([]Symbol, 0)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse the line: START SIZE name
		parts := strings.Fields(line)
		if len(parts) < 3 {
			// Some lines might have malformed data, skip them
			continue
		}

		// Parse start address (hex)
		start, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			// Log or handle parse error if needed
			fmt.Fprintf(os.Stderr, "Warning: line %d: failed to parse start address: %v\n", lineNum, err)
			continue
		}

		// Parse size (hex)
		size, err := strconv.ParseUint(parts[1], 16, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: line %d: failed to parse size: %v\n", lineNum, err)
			continue
		}

		// The rest is the symbol name (may contain spaces)
		name := strings.Join(parts[2:], " ")

		newSymbols = append(newSymbols, Symbol{
			Start: start,
			End:   start + size,
			Name:  name,
		})
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Sort symbols by start address for binary search
	sort.Slice(newSymbols, func(i, j int) bool {
		return newSymbols[i].Start < newSymbols[j].Start
	})

	// Replace old symbols with new ones
	pm.symbols = newSymbols
	pm.filename = filename
	pm.lastModTime = fileInfo.ModTime()
	pm.lastLoadTime = time.Now()

	return nil
}

// Reload reloads the symbols from the backing file
func (pm *PerfMap) Reload() error {
	if pm.filename == "" {
		return fmt.Errorf("no backing file to reload from")
	}

	return pm.ParseFile(pm.filename)
}

// isFileModified checks if the backing file has been modified since last load
func (pm *PerfMap) isFileModified() bool {
	if pm.filename == "" {
		return false
	}

	fileInfo, err := os.Stat(pm.filename)
	if err != nil {
		// File might have been deleted or become inaccessible
		return false
	}

	return fileInfo.ModTime().After(pm.lastModTime)
}

// sortSymbols sorts the symbols by start address
func (pm *PerfMap) sortSymbols() {
	sort.Slice(pm.symbols, func(i, j int) bool {
		return pm.symbols[i].Start < pm.symbols[j].Start
	})
}

// Lookup finds the symbol containing the given PC address
func (pm *PerfMap) Lookup(pc uint64) (Symbol, bool) {
	// Binary search for the symbol containing this PC
	idx := sort.Search(len(pm.symbols), func(i int) bool {
		return pm.symbols[i].End > pc
	})

	// Check if we found a valid symbol and the PC is within its range
	if idx < len(pm.symbols) && pm.symbols[idx].Start <= pc && pc < pm.symbols[idx].End {
		return pm.symbols[idx], true
	}

	return Symbol{}, false
}

// LookupWithReload performs a lookup with automatic reload if the file has changed
// If the initial lookup fails and the file has been modified, it reloads and retries
func (pm *PerfMap) LookupWithReload(pc uint64) (Symbol, bool, error) {
	// First attempt lookup
	sym, found := pm.Lookup(pc)
	if found {
		// Found on first try, check if file needs reload for future lookups
		if pm.isFileModified() {
			// Reload in background for future lookups, but return current result
			go func() {
				_ = pm.Reload()
			}()
		}
		return sym, true, nil
	}

	// Not found, check if file has been modified
	if !pm.isFileModified() {
		// File hasn't changed, symbol genuinely doesn't exist
		return Symbol{}, false, nil
	}

	// File has been modified, reload and retry
	if err := pm.Reload(); err != nil {
		return Symbol{}, false, fmt.Errorf("failed to reload perf map: %w", err)
	}

	// Retry lookup after reload
	sym, found = pm.Lookup(pc)
	return sym, found, nil
}

// LookupName returns just the symbol name for a given PC
func (pm *PerfMap) LookupName(pc uint64) string {
	if sym, found := pm.Lookup(pc); found {
		return sym.Name
	}
	return ""
}

// Stats returns statistics about the perf map
func (pm *PerfMap) Stats() string {
	if len(pm.symbols) == 0 {
		return "No symbols loaded"
	}

	minAddr := pm.symbols[0].Start
	maxAddr := uint64(0)
	totalSize := uint64(0)

	for _, sym := range pm.symbols {
		if sym.End > maxAddr {
			maxAddr = sym.End
		}
		totalSize += (sym.End - sym.Start)
	}

	return fmt.Sprintf("Symbols: %d, Address range: 0x%x-0x%x, Total size: %d bytes",
		len(pm.symbols), minAddr, maxAddr, totalSize)
}
