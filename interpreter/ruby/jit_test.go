package ruby

//// Example usage
//func main() {
//	// Example 1: Parse from file
//	pm := NewPerfMap()
//
//	// Create a sample perf map file for testing
//	sampleData := `7f2b12345000 200 java.lang.String.hashCode()
//7f2b12345200 150 java.util.HashMap.get()
//7f2b12345350 300 com.example.MyClass.doWork()
//7f2b12345650 100 [stub] Runtime stub
//`
//
//	// Parse the sample data
//	if err := pm.ParseString(sampleData); err != nil {
//		fmt.Printf("Error parsing perf map: %v\n", err)
//		return
//	}
//
//	// Test lookups
//	testAddresses := []uint64{
//		0x7f2b12345100, // Should be in hashCode()
//		0x7f2b12345250, // Should be in HashMap.get()
//		0x7f2b12345400, // Should be in MyClass.doWork()
//		0x7f2b12345700, // Should be in Runtime stub
//		0x7f2b12340000, // Should not be found
//	}
//
//	fmt.Println("Testing PC lookups:")
//	fmt.Println("-------------------")
//	for _, pc := range testAddresses {
//		if sym, found := pm.Lookup(pc); found {
//			fmt.Printf("PC 0x%x -> %s (range: 0x%x-0x%x)\n",
//				pc, sym.Name, sym.Start, sym.End)
//		} else {
//			fmt.Printf("PC 0x%x -> NOT FOUND\n", pc)
//		}
//	}
//
//	fmt.Println("\n" + pm.Stats())
//
//	// Example 2: Parse from actual file
//	// Uncomment to use with a real file
//	/*
//	pm2 := NewPerfMap()
//	if err := pm2.ParseFile("/tmp/perf-12345.map"); err != nil {
//		fmt.Printf("Error loading perf map file: %v\n", err)
//	} else {
//		// Lookup a specific address
//		pc := uint64(0x7f2b12345100)
//		if name := pm2.LookupName(pc); name != "" {
//			fmt.Printf("Symbol at 0x%x: %s\n", pc, name)
//		}
//	}
//	*/
//}

//// ParseString parses JIT perf map data from a string
//func (pm *PerfMap) parseString(data string) error {
//	lines := strings.Split(data, "\n")
//
//	for i, line := range lines {
//		line = strings.TrimSpace(line)
//
//		if line == "" || strings.HasPrefix(line, "#") {
//			continue
//		}
//
//		parts := strings.Fields(line)
//		if len(parts) < 3 {
//			continue
//		}
//
//		start, err := strconv.ParseUint(parts[0], 16, 64)
//		if err != nil {
//			fmt.Fprintf(os.Stderr, "Warning: line %d: failed to parse start address: %v\n", i+1, err)
//			continue
//		}
//
//		size, err := strconv.ParseUint(parts[1], 16, 64)
//		if err != nil {
//			fmt.Fprintf(os.Stderr, "Warning: line %d: failed to parse size: %v\n", i+1, err)
//			continue
//		}
//
//		name := strings.Join(parts[2:], " ")
//
//		pm.symbols = append(pm.symbols, Symbol{
//			Start: start,
//			End:   start + size,
//			Name:  name,
//		})
//	}
//
//	pm.sortSymbols()
//	return nil
//}
//
