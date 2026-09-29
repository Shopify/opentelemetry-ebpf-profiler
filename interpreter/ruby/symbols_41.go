// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	npsr "go.opentelemetry.io/ebpf-profiler/nopanicslicereader"
)

// Ruby 4.1 replaced the two RArray levels in ruby_global_symbols.ids with
// TypedData objects containing an id_entry_dir and rb_darray(sym_id_entry).
// See symbol.c:get_id_serial_entry at ruby41Revision. The offsets below are
// identical on Linux amd64 and arm64; they are not the old RArray offsets.
const (
	ruby41TypedDataTypeOffset      = 24
	ruby41TypedDataDataOffset      = 32
	ruby41TypedDataSize            = 40
	ruby41TypedDataEmbedded        = 1
	ruby41IDDirectoryEntriesOffset = 8
	ruby41DarrayHeaderSize         = 16
	ruby41SymbolEntrySize          = 16
	ruby41SymbolEntryStringOffset  = 8
)

func (r *rubyInstance) readRuby41TypedData(object libpf.Address) (libpf.Address, error) {
	var data [ruby41TypedDataSize]byte
	if err := r.rm.Read(object, data[:]); err != nil {
		return 0, fmt.Errorf("failed to read symbol TypedData: %w", err)
	}
	// RUBY_T_DATA. Do not reinterpret an absent or stale object as a directory.
	if npsr.Uint64(data[:], 0)&rubyTMask != 0x0c {
		return 0, fmt.Errorf("invalid symbol TypedData at %#x", object)
	}
	if npsr.Uint64(data[:], ruby41TypedDataTypeOffset)&ruby41TypedDataEmbedded != 0 {
		return object + ruby41TypedDataDataOffset, nil
	}
	pointer := npsr.Ptr(data[:], ruby41TypedDataDataOffset)
	if pointer == 0 {
		return 0, fmt.Errorf("empty symbol TypedData at %#x", object)
	}
	return pointer, nil
}

func (r *rubyInstance) readRuby41IDString(serial uint64) (libpf.String, error) {
	if serial == 0 {
		return libpf.NullString, fmt.Errorf("invalid symbol serial 0")
	}
	ids := r.rm.Ptr(r.globalSymbolsAddr + libpf.Address(r.r.vmStructs.rb_symbols_t.ids))
	dir, err := r.readRuby41TypedData(ids)
	if err != nil {
		return libpf.NullString, err
	}
	idx := serial / idEntryUnit
	capacity := r.rm.Uint64(dir) // id_entry_dir.capa
	if idx >= capacity {
		return libpf.NullString, fmt.Errorf("invalid symbol directory index %d, capacity %d", idx, capacity)
	}
	entries := r.rm.Ptr(dir + ruby41IDDirectoryEntriesOffset)
	bucketObject := r.rm.Ptr(entries + libpf.Address(idx*8))
	bucket, err := r.readRuby41TypedData(bucketObject)
	if err != nil {
		return libpf.NullString, err
	}
	position := serial % idEntryUnit
	size := r.rm.Uint64(bucket) // rb_darray_meta.size
	if position >= size {
		return libpf.NullString, fmt.Errorf("invalid symbol bucket index %d, size %d", position, size)
	}
	stringPtr := r.rm.Ptr(bucket + ruby41DarrayHeaderSize +
		libpf.Address(position*ruby41SymbolEntrySize+ruby41SymbolEntryStringOffset))
	return r.getStringCached(stringPtr, r.readRubyString)
}
