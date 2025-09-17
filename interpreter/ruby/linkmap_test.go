// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/*
This test suite provides fixture-based tests which can be run with the
environment variable RECORD_PID=$(pidof ruby). In which case, no assertions
are run and a new test fixture is generated.

It will record all of the memory accessed as well as the contents of auxv,
and store it in a JSON file. When the tests are run, the memory reads are
provided back these same values for the queried memory addresses.

It is conceptually similar to a coredump test, but only the memory that is
actually accessed is saved and provided back in the test stub.

If the memory access pattern or schema of the recording changes, the fixtures
are likely all invalidated and must be re-recorded.

However, if the code changes, the fixtures should ensure that it continues to
work in cases it previously worked in, and provides a spec for what IS supported
and verified against at least.

To record fixtures:

RECORD_PID=$(pidof ruby) go test -race -count=1 -v ./interpreter/ruby
*/

package ruby

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const FIXTURE_FILE_FORMAT_STRING = "testdata/memory_recording_%d.json.gz"

// MemoryRecorder wraps a RemoteMemory and records all reads
type MemoryRecorder struct {
	rm         io.ReaderAt
	pid        int
	auxv       []byte
	recordings map[uint64][]byte
	logReads   bool
}

type RecordedRead struct {
	Address uint64 `json:"addr"`
	Data    []byte `json:"data"`
	Size    int    `json:"size"`
}

type RecordingData struct {
	Reads []RecordedRead `json:"reads"`
	// Metadata about the process
	PID  int    `json:"pid"`
	Auxv []byte `json:"auxv"`
}

func NewMemoryRecorder(rm io.ReaderAt, pid int, logReads bool) (*MemoryRecorder, error) {
	auxv, err := os.ReadFile(fmt.Sprintf("/proc/%d/auxv", pid))
	if err != nil {
		return nil, err
	}
	return &MemoryRecorder{
		rm:         rm,
		pid:        pid,
		auxv:       auxv,
		recordings: make(map[uint64][]byte),
		logReads:   logReads,
	}, nil
}

func (mr *MemoryRecorder) ReadAt(p []byte, off int64) (n int, err error) {
	addr := uint64(off)

	if mr.logReads {
		fmt.Printf("Reading at %X (size: %d)\n", addr, len(p))
	}

	// Perform the actual read
	n, err = mr.rm.ReadAt(p, off)

	// Record successful reads
	if err == nil && n > 0 {
		// Store a copy of the data
		data := make([]byte, n)
		copy(data, p[:n])
		mr.recordings[addr] = data
	}

	return n, err
}

func (mr *MemoryRecorder) GetRecording() RecordingData {
	rd := RecordingData{
		Reads: make([]RecordedRead, 0, len(mr.recordings)),
		PID:   mr.pid,
		Auxv:  mr.auxv,
	}

	for addr, data := range mr.recordings {
		rd.Reads = append(rd.Reads, RecordedRead{
			Address: addr,
			Data:    data,
			Size:    len(data),
		})
	}

	return rd
}

func (mr *MemoryRecorder) SaveToFile() error {
	data := mr.GetRecording()

	file, err := os.Create(fmt.Sprintf(FIXTURE_FILE_FORMAT_STRING, mr.pid))
	if err != nil {
		return err
	}
	defer file.Close()

	gz, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer gz.Close()

	encoder := json.NewEncoder(gz)
	return encoder.Encode(data)
}

// ReplayMemory implements RemoteMemory using recorded data
type ReplayMemory struct {
	reads  map[uint64][]byte
	ranges []memRange // Sorted list of address ranges for efficient lookup
	auxv   []byte
	pid    int
	debug  bool
}

type memRange struct {
	start uint64
	end   uint64
	data  []byte
}

func NewReplayMemory(recordings RecordingData) *ReplayMemory {
	rm := &ReplayMemory{
		reads:  make(map[uint64][]byte),
		ranges: make([]memRange, 0),
		auxv:   recordings.Auxv,
		pid:    recordings.PID,
	}

	// Build the memory map
	for _, read := range recordings.Reads {
		rm.reads[read.Address] = read.Data

		// Create a range for efficient lookup
		rm.ranges = append(rm.ranges, memRange{
			start: read.Address,
			end:   read.Address + uint64(len(read.Data)),
			data:  read.Data,
		})
	}

	// Sort ranges for binary search
	sort.Slice(rm.ranges, func(i, j int) bool {
		return rm.ranges[i].start < rm.ranges[j].start
	})

	// Merge overlapping ranges for efficiency
	rm.mergeRanges()

	return rm
}

func (rm *ReplayMemory) mergeRanges() {
	if len(rm.ranges) <= 1 {
		return
	}

	merged := []memRange{rm.ranges[0]}

	for i := 1; i < len(rm.ranges); i++ {
		last := &merged[len(merged)-1]
		curr := rm.ranges[i]

		// If current range overlaps or is adjacent to last
		if curr.start <= last.end {
			// Extend the last range
			if curr.end > last.end {
				// Combine the data
				newData := make([]byte, curr.end-last.start)
				copy(newData, last.data)
				copy(newData[curr.start-last.start:], curr.data)
				last.data = newData
				last.end = curr.end
			}
		} else {
			merged = append(merged, curr)
		}
	}

	rm.ranges = merged
}

func (rm *ReplayMemory) ReadAt(p []byte, off int64) (n int, err error) {
	addr := uint64(off)

	if rm.debug {
		fmt.Printf("ReplayMemory: Reading at %X (size: %d)\n", addr, len(p))
	}

	// First check exact address match
	if data, ok := rm.reads[addr]; ok {
		copy(p, data)
		return len(data), nil
	}

	// Binary search for range containing this address
	idx := sort.Search(len(rm.ranges), func(i int) bool {
		return rm.ranges[i].end > addr
	})

	if idx < len(rm.ranges) && rm.ranges[idx].start <= addr {
		r := rm.ranges[idx]
		offset := addr - r.start
		available := uint64(len(r.data)) - offset
		toRead := uint64(len(p))
		if toRead > available {
			toRead = available
		}

		copy(p, r.data[offset:offset+toRead])
		return int(toRead), nil
	}

	if rm.debug {
		fmt.Printf("ReplayMemory: No data for address %X\n", addr)
	}
	return 0, io.EOF
}

func LoadReplayMemory(filename string) (*ReplayMemory, error) {
	compressed, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		return nil, err
	}

	// Try to decode as JSON first
	var recording RecordingData
	if err := json.Unmarshal(decompressed, &recording); err != nil {
		return nil, err
	}

	return NewReplayMemory(recording), nil
}

func ProcessInspectorTest(t *testing.T) {
	tests := []struct {
		desc           string
		file           string
		expectedModule int
		expectedLibs   []libraryInfo
		expectedLibc   libcType
	}{
		{
			desc:           "it works with a plain ruby invocation",
			file:           "testdata/memory_recording_1835475.json.gz",
			expectedModule: 1,
			expectedLibs:   []libraryInfo{libraryInfo{name: "", path: "", baseAddress: 0xb127b97a0000, isVirtual: false, loadOrder: 0, hasTLS: false}, libraryInfo{name: "linux-vdso.so.1", path: "linux-vdso.so.1", baseAddress: 0xf76fcece2000, isVirtual: true, loadOrder: 1, hasTLS: false}, libraryInfo{name: "libruby.so.3.4", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/libruby.so.3.4", baseAddress: 0xf76fce600000, isVirtual: false, loadOrder: 2, hasTLS: true}, libraryInfo{name: "libz.so.1", path: "/lib/aarch64-linux-gnu/libz.so.1", baseAddress: 0xf76fce5c0000, isVirtual: false, loadOrder: 3, hasTLS: false}, libraryInfo{name: "libcrypt.so.1", path: "/lib/aarch64-linux-gnu/libcrypt.so.1", baseAddress: 0xf76fce570000, isVirtual: false, loadOrder: 4, hasTLS: false}, libraryInfo{name: "libm.so.6", path: "/lib/aarch64-linux-gnu/libm.so.6", baseAddress: 0xf76fce4c0000, isVirtual: false, loadOrder: 5, hasTLS: false}, libraryInfo{name: "libc.so.6", path: "/lib/aarch64-linux-gnu/libc.so.6", baseAddress: 0xf76fce300000, isVirtual: false, loadOrder: 6, hasTLS: true}, libraryInfo{name: "ld-linux-aarch64.so.1", path: "/lib/ld-linux-aarch64.so.1", baseAddress: 0xf76fceca5000, isVirtual: false, loadOrder: 7, hasTLS: false}, libraryInfo{name: "libgcc_s.so.1", path: "/lib/aarch64-linux-gnu/libgcc_s.so.1", baseAddress: 0xf76fce2c0000, isVirtual: false, loadOrder: 8, hasTLS: true}, libraryInfo{name: "encdb.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/enc/encdb.so", baseAddress: 0xf76fce060000, isVirtual: false, loadOrder: 9, hasTLS: false}, libraryInfo{name: "transdb.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/enc/trans/transdb.so", baseAddress: 0xf76fce020000, isVirtual: false, loadOrder: 10, hasTLS: false}, libraryInfo{name: "monitor.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/monitor.so", baseAddress: 0xf76fb4a80000, isVirtual: false, loadOrder: 11, hasTLS: false}},
			expectedLibc:   libcGlibc,
		},
		{
			desc:           "it works with jemalloc",
			file:           "testdata/memory_recording_1735824.json.gz",
			expectedModule: 2,
			expectedLibs:   []libraryInfo{libraryInfo{name: "", path: "", baseAddress: 0xae58dab90000, isVirtual: false, loadOrder: 0, hasTLS: false}, libraryInfo{name: "linux-vdso.so.1", path: "linux-vdso.so.1", baseAddress: 0xe3f7d62cb000, isVirtual: true, loadOrder: 1, hasTLS: false}, libraryInfo{name: "libjemalloc.so", path: "/usr/lib/aarch64-linux-gnu/libjemalloc.so", baseAddress: 0xe3f7d6170000, isVirtual: false, loadOrder: 2, hasTLS: true}, libraryInfo{name: "libruby.so.3.4", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/libruby.so.3.4", baseAddress: 0xe3f7d5a00000, isVirtual: false, loadOrder: 3, hasTLS: true}, libraryInfo{name: "libz.so.1", path: "/lib/aarch64-linux-gnu/libz.so.1", baseAddress: 0xe3f7d6130000, isVirtual: false, loadOrder: 4, hasTLS: false}, libraryInfo{name: "libcrypt.so.1", path: "/lib/aarch64-linux-gnu/libcrypt.so.1", baseAddress: 0xe3f7d60e0000, isVirtual: false, loadOrder: 5, hasTLS: false}, libraryInfo{name: "libm.so.6", path: "/lib/aarch64-linux-gnu/libm.so.6", baseAddress: 0xe3f7d5950000, isVirtual: false, loadOrder: 6, hasTLS: false}, libraryInfo{name: "libc.so.6", path: "/lib/aarch64-linux-gnu/libc.so.6", baseAddress: 0xe3f7d5790000, isVirtual: false, loadOrder: 7, hasTLS: true}, libraryInfo{name: "ld-linux-aarch64.so.1", path: "/lib/ld-linux-aarch64.so.1", baseAddress: 0xe3f7d628e000, isVirtual: false, loadOrder: 8, hasTLS: false}, libraryInfo{name: "libstdc++.so.6", path: "/lib/aarch64-linux-gnu/libstdc++.so.6", baseAddress: 0xe3f7d5400000, isVirtual: false, loadOrder: 9, hasTLS: true}, libraryInfo{name: "libgcc_s.so.1", path: "/lib/aarch64-linux-gnu/libgcc_s.so.1", baseAddress: 0xe3f7d60a0000, isVirtual: false, loadOrder: 10, hasTLS: true}, libraryInfo{name: "encdb.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/enc/encdb.so", baseAddress: 0xe3f7d56a0000, isVirtual: false, loadOrder: 11, hasTLS: false}, libraryInfo{name: "transdb.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/enc/trans/transdb.so", baseAddress: 0xe3f7d4fc0000, isVirtual: false, loadOrder: 12, hasTLS: false}, libraryInfo{name: "monitor.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/monitor.so", baseAddress: 0xe3f7d4ba0000, isVirtual: false, loadOrder: 13, hasTLS: false}},
			expectedLibc:   libcGlibc,
		},
		{
			desc:           "it works with multiple libraries with a TLS section preloaded",
			file:           "testdata/memory_recording_2003555.json.gz",
			expectedModule: 4,
			expectedLibs:   []libraryInfo{libraryInfo{name: "", path: "", baseAddress: 0xb33889da0000, isVirtual: false, loadOrder: 0, hasTLS: false}, libraryInfo{name: "linux-vdso.so.1", path: "linux-vdso.so.1", baseAddress: 0xe2bce4d39000, isVirtual: true, loadOrder: 1, hasTLS: false}, libraryInfo{name: "libmemusage.so", path: "/usr/lib/aarch64-linux-gnu/libmemusage.so", baseAddress: 0xe2bce4b50000, isVirtual: false, loadOrder: 2, hasTLS: true}, libraryInfo{name: "libelf.so", path: "/usr/lib/aarch64-linux-gnu/libelf.so", baseAddress: 0xe2bce4b10000, isVirtual: false, loadOrder: 3, hasTLS: true}, libraryInfo{name: "libjemalloc.so", path: "/usr/lib/aarch64-linux-gnu/libjemalloc.so", baseAddress: 0xe2bce49f0000, isVirtual: false, loadOrder: 4, hasTLS: true}, libraryInfo{name: "libruby.so.3.4", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/libruby.so.3.4", baseAddress: 0xe2bce4200000, isVirtual: false, loadOrder: 5, hasTLS: true}, libraryInfo{name: "libz.so.1", path: "/lib/aarch64-linux-gnu/libz.so.1", baseAddress: 0xe2bce49b0000, isVirtual: false, loadOrder: 6, hasTLS: false}, libraryInfo{name: "libcrypt.so.1", path: "/lib/aarch64-linux-gnu/libcrypt.so.1", baseAddress: 0xe2bce4960000, isVirtual: false, loadOrder: 7, hasTLS: false}, libraryInfo{name: "libm.so.6", path: "/lib/aarch64-linux-gnu/libm.so.6", baseAddress: 0xe2bce48b0000, isVirtual: false, loadOrder: 8, hasTLS: false}, libraryInfo{name: "libc.so.6", path: "/lib/aarch64-linux-gnu/libc.so.6", baseAddress: 0xe2bce4040000, isVirtual: false, loadOrder: 9, hasTLS: true}, libraryInfo{name: "ld-linux-aarch64.so.1", path: "/lib/ld-linux-aarch64.so.1", baseAddress: 0xe2bce4cfc000, isVirtual: false, loadOrder: 10, hasTLS: false}, libraryInfo{name: "libzstd.so.1", path: "/lib/aarch64-linux-gnu/libzstd.so.1", baseAddress: 0xe2bce3f80000, isVirtual: false, loadOrder: 11, hasTLS: false}, libraryInfo{name: "libstdc++.so.6", path: "/lib/aarch64-linux-gnu/libstdc++.so.6", baseAddress: 0xe2bce3c00000, isVirtual: false, loadOrder: 12, hasTLS: true}, libraryInfo{name: "libgcc_s.so.1", path: "/lib/aarch64-linux-gnu/libgcc_s.so.1", baseAddress: 0xe2bce3f40000, isVirtual: false, loadOrder: 13, hasTLS: true}, libraryInfo{name: "encdb.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/enc/encdb.so", baseAddress: 0xe2bce37c0000, isVirtual: false, loadOrder: 14, hasTLS: false}, libraryInfo{name: "transdb.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/enc/trans/transdb.so", baseAddress: 0xe2bce3780000, isVirtual: false, loadOrder: 15, hasTLS: false}, libraryInfo{name: "monitor.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/monitor.so", baseAddress: 0xe2bce3360000, isVirtual: false, loadOrder: 16, hasTLS: false}},
			expectedLibc:   libcGlibc,
		},
		{
			desc:           "it detects musl",
			file:           "testdata/memory_recording_15.json.gz",
			expectedModule: 1,
			expectedLibs:   []libraryInfo{libraryInfo{name: "", path: "", baseAddress: 0xbd0aeeea0000, isVirtual: false, loadOrder: 0, hasTLS: false}, libraryInfo{name: "libruby.so.3.4", path: "/usr/lib/libruby.so.3.4", baseAddress: 0xf6632ad36000, isVirtual: false, loadOrder: 1, hasTLS: true}, libraryInfo{name: "libz.so.1", path: "/usr/lib/libz.so.1", baseAddress: 0xf6632ad05000, isVirtual: false, loadOrder: 2, hasTLS: false}, libraryInfo{name: "libgmp.so.10", path: "/usr/lib/libgmp.so.10", baseAddress: 0xf6632ac84000, isVirtual: false, loadOrder: 3, hasTLS: false}, libraryInfo{name: "libucontext.so.1", path: "/usr/lib/libucontext.so.1", baseAddress: 0xf6632ac63000, isVirtual: false, loadOrder: 4, hasTLS: false}, libraryInfo{name: "ld-musl-aarch64.so.1", path: "/lib/ld-musl-aarch64.so.1", baseAddress: 0xf6632b30b000, isVirtual: false, loadOrder: 5, hasTLS: false}, libraryInfo{name: "libgcc_s.so.1", path: "/usr/lib/libgcc_s.so.1", baseAddress: 0xf6632ac32000, isVirtual: false, loadOrder: 6, hasTLS: true}, libraryInfo{name: "", path: "", baseAddress: 0xf6632b3c9000, isVirtual: false, loadOrder: 7, hasTLS: false}, libraryInfo{name: "encdb.so", path: "/usr/lib/ruby/3.4.0/aarch64-linux-musl/enc/encdb.so", baseAddress: 0xf6631158e000, isVirtual: false, loadOrder: 8, hasTLS: false}, libraryInfo{name: "transdb.so", path: "/usr/lib/ruby/3.4.0/aarch64-linux-musl/enc/trans/transdb.so", baseAddress: 0xf6631154f000, isVirtual: false, loadOrder: 9, hasTLS: false}, libraryInfo{name: "monitor.so", path: "/usr/lib/ruby/3.4.0/aarch64-linux-musl/monitor.so", baseAddress: 0xf6630fd1f000, isVirtual: false, loadOrder: 10, hasTLS: false}},
			expectedLibc:   libcMusl,
		},
		{
			desc:           "it detects the correct module offset with jemalloc and musl",
			file:           "testdata/memory_recording_4335.json.gz",
			expectedModule: 2,
			expectedLibs:   []libraryInfo{libraryInfo{name: "", path: "", baseAddress: 0xc8c54c530000, isVirtual: false, loadOrder: 0, hasTLS: false}, libraryInfo{name: "libjemalloc.so.2", path: "/usr/lib/libjemalloc.so.2", baseAddress: 0xef98bdb81000, isVirtual: false, loadOrder: 1, hasTLS: true}, libraryInfo{name: "libruby.so.3.4", path: "/usr/lib/libruby.so.3.4", baseAddress: 0xef98bd5ac000, isVirtual: false, loadOrder: 2, hasTLS: true}, libraryInfo{name: "libz.so.1", path: "/usr/lib/libz.so.1", baseAddress: 0xef98bd57b000, isVirtual: false, loadOrder: 3, hasTLS: false}, libraryInfo{name: "libgmp.so.10", path: "/usr/lib/libgmp.so.10", baseAddress: 0xef98bd4fa000, isVirtual: false, loadOrder: 4, hasTLS: false}, libraryInfo{name: "libucontext.so.1", path: "/usr/lib/libucontext.so.1", baseAddress: 0xef98bd4d9000, isVirtual: false, loadOrder: 5, hasTLS: false}, libraryInfo{name: "ld-musl-aarch64.so.1", path: "/lib/ld-musl-aarch64.so.1", baseAddress: 0xef98bdc8d000, isVirtual: false, loadOrder: 6, hasTLS: false}, libraryInfo{name: "libstdc++.so.6", path: "/usr/lib/libstdc++.so.6", baseAddress: 0xef98bd234000, isVirtual: false, loadOrder: 7, hasTLS: true}, libraryInfo{name: "libgcc_s.so.1", path: "/usr/lib/libgcc_s.so.1", baseAddress: 0xef98bd203000, isVirtual: false, loadOrder: 8, hasTLS: true}, libraryInfo{name: "", path: "", baseAddress: 0xef98bdd4b000, isVirtual: false, loadOrder: 9, hasTLS: false}, libraryInfo{name: "encdb.so", path: "/usr/lib/ruby/3.4.0/aarch64-linux-musl/enc/encdb.so", baseAddress: 0xef98bcd5b000, isVirtual: false, loadOrder: 10, hasTLS: false}, libraryInfo{name: "transdb.so", path: "/usr/lib/ruby/3.4.0/aarch64-linux-musl/enc/trans/transdb.so", baseAddress: 0xef98bcd1f000, isVirtual: false, loadOrder: 11, hasTLS: false}, libraryInfo{name: "monitor.so", path: "/usr/lib/ruby/3.4.0/aarch64-linux-musl/monitor.so", baseAddress: 0xef98a31df000, isVirtual: false, loadOrder: 12, hasTLS: false}},
			expectedLibc:   libcMusl,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			replay, err := LoadReplayMemory(tt.file)
			require.NoError(t, err)
			oldFs := fs
			defer func() {
				fs = oldFs
			}()
			fs = afero.NewMemMapFs()
			afero.WriteFile(fs, fmt.Sprintf("/proc/%d/auxv", replay.pid), replay.auxv, 0644)

			inspector, err := newLinkmapInspector(replay.pid, replay)

			id, err := inspector.findTLSModuleID("libruby.so")
			require.NoError(t, err)
			assert.Equal(t, tt.expectedModule, id)

			libs, err := inspector.getLoadedLibraries()
			require.NoError(t, err)
			assert.Equal(t, tt.expectedLibs, libs)

			libc := detectLibc(libs)
			assert.Equal(t, tt.expectedLibc, libc)
		})
	}
}

func recordProcess(t *testing.T, pid int) {
	rm := remotememory.NewProcessVirtualMemory(libpf.PID(pid))
	recorder, err := NewMemoryRecorder(rm, pid, false)
	require.NoError(t, err)

	inspector, err := newLinkmapInspector(pid, recorder)
	require.NoError(t, err)

	id, err := inspector.findTLSModuleID("libruby.so")
	require.NoError(t, err)

	fmt.Printf("Recorded fixture for pid: %d\n", pid)
	fmt.Printf("Fixture file: %s\n", fmt.Sprintf(FIXTURE_FILE_FORMAT_STRING, pid))
	fmt.Printf("TLS module ID %d\n", id)
	libs, err := inspector.getLoadedLibraries()
	require.NoError(t, err)
	fmt.Printf("libraryInfo:\n%s\n", strings.ReplaceAll(fmt.Sprintf("%#v", libs), "ruby.libraryInfo", "libraryInfo"))
	libc := detectLibc(libs)
	fmt.Printf("libc: %+v\n", libc)

	require.NoError(t, recorder.SaveToFile())
}

func TestProcessVirtualMemory(t *testing.T) {
	// Note: Recording is platform dependant, but tests can be run anywhere
	// NOTE CAP_SYS_PTRACE is required to record
	if pidStr := os.Getenv("RECORD_PID"); pidStr != "" {
		if runtime.GOOS != "linux" {
			t.Skipf("unsupported os %s", runtime.GOOS)
		}
		pid, err := strconv.Atoi(pidStr)
		require.NoError(t, err)
		recordProcess(t, pid)
	} else {
		ProcessInspectorTest(t)
	}
}
