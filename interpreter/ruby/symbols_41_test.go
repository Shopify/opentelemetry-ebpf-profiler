// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func newRuby41MemoryTest(t *testing.T, memory []byte) *rubyInstance {
	t.Helper()
	r := &rubyData{version: rubyVersion(4, 1, 0), globalSymbolsAddr: 0x100}
	applyRuby41Layout(r, "amd64")
	r.vmStructs.rb_symbols_t.ids = 16
	r.vmStructs.size_of_value = 8
	inst, err := r.Attach(&rubyTestEbpfHandler{}, 1, 0,
		remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)})
	require.NoError(t, err)
	return inst.(*rubyInstance)
}

func TestRuby41SymbolDirectory(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		serial, capacity, size           uint64
		embedded, emptyBucket, wantError bool
	}{
		{"operator", 43, 2, 512, false, false, false},
		{"dynamic symbol", 519, 2, 512, false, false, false},
		{"last bucket element", 1023, 2, 512, false, false, false},
		{"embedded TypedData", 519, 2, 512, true, false, false},
		{"directory bound", 512, 1, 512, false, false, true},
		{"bucket bound", 519, 2, 7, false, false, true},
		{"empty bucket", 519, 2, 512, false, true, true},
		{"zero serial", 0, 2, 512, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memory := make([]byte, 0x6000)
			put := func(at, value uint64) { binary.LittleEndian.PutUint64(memory[at:], value) }
			put(0x100, 2048)  // ruby_global_symbols.next_id
			put(0x110, 0x200) // ruby_global_symbols.ids
			dir, bucket := uint64(0x300), uint64(0x800)
			put(0x200, 0x0c) // RUBY_T_DATA
			put(0x500, 0x0c)
			if tc.embedded {
				dir, bucket = 0x220, 0x520
				put(0x218, 1)
				put(0x518, 1)
			} else {
				put(0x220, dir)
				put(0x520, bucket)
			}
			put(dir, tc.capacity)
			put(dir+8, 0x400) // id_entry_dir.entries points to a separate array
			if !tc.emptyBucket {
				put(0x400+(tc.serial/512)*8, 0x500)
			}
			put(bucket, tc.size)
			put(bucket+8, 512)
			// sym_id_entry is {sym, str}, the reverse of the old RArray pair.
			put(bucket+16+(tc.serial%512)*16, 0xdead)
			put(bucket+16+(tc.serial%512)*16+8, 0x5000)
			r := newRuby41MemoryTest(t, memory)
			r.addrToString.Add(0x5000, libpf.Intern("sleep"))
			id := tc.serial
			if id > r.r.lastOpId {
				id <<= rubyIdScopeShift
			}
			got, err := r.id2str(id)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, libpf.Intern("sleep"), got)
		})
	}
}

func TestRuby41SingletonClassReadIncludesAttachedObject(t *testing.T) {
	memory := make([]byte, 0x6000)
	put := func(at, value uint64) { binary.LittleEndian.PutUint64(memory[at:], value) }
	r := newRuby41MemoryTest(t, memory)
	put(0x100, 2|uint64(r.r.rubyFlSingleton)) // singleton T_CLASS
	put(0x100+24+104, 0x300)                  // attached_object is AFTER classpath
	put(0x300+24+24, 0x5000)
	r.addrToString.Add(0x5000, libpf.Intern("Ruby41Fixture"))
	name, singleton, err := r.readClassName(0x100)
	require.NoError(t, err)
	assert.True(t, singleton)
	assert.Equal(t, libpf.Intern("Ruby41Fixture"), name)
}
