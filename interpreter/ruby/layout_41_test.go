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

func TestRuby41RevisionGate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		version  uint32
		revision string
		want     bool
	}{
		{"audited", rubyVersion(4, 1, 0), ruby41Revision, true},
		{"missing revision", rubyVersion(4, 1, 0), "", false},
		{"abbreviated revision", rubyVersion(4, 1, 0), ruby41Revision[:10], false},
		{"other development ABI", rubyVersion(4, 1, 0), "8fdf4342", false},
		{"old version", rubyVersion(4, 0, 7), ruby41Revision, false},
		{"future patch", rubyVersion(4, 1, 1), ruby41Revision, false},
		{"future minor", rubyVersion(4, 2, 0), ruby41Revision, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, rubyUses41Layout(tc.version, tc.revision, ""))
		})
	}
}

func TestRuby41StrippedRevisionGate(t *testing.T) {
	const description = "ruby 4.1.0dev (2026-09-28T21:54:22Z shopify a68e42cfad) +ZJIT +PRISM [x86_64-linux]"
	assert.True(t, rubyUses41Layout(rubyVersion(4, 1, 0), "", description))
	assert.False(t, rubyUses41Layout(rubyVersion(4, 1, 0), "other", description))
	assert.False(t, rubyUses41Layout(rubyVersion(4, 1, 1), "", description))
	assert.False(t, rubyUses41Layout(rubyVersion(4, 1, 0), "", "ruby 4.1.0dev (date shopify a68e42cfa)"))
	assert.False(t, rubyUses41Layout(rubyVersion(4, 1, 0), "", "ruby 4.1.0 (date shopify a68e42cfad)"))
}

func TestRuby41Layout(t *testing.T) {
	// Values independently measured from private DWARF in miniruby, with
	// YJIT enabled, on each architecture at ruby41Revision.
	for _, tc := range []struct {
		arch                string
		runningEC, objspace uint16
	}{
		{"amd64", 416, 600},
		{"arm64", 432, 616},
	} {
		t.Run(tc.arch, func(t *testing.T) {
			r := &rubyData{version: rubyVersion(4, 1, 0)}
			applyRuby41Layout(r, tc.arch)
			vms := &r.vmStructs
			assert.True(t, r.hasClassPath)
			assert.True(t, r.hasObjspace)
			assert.Equal(t, uint64(174), r.lastOpId)
			assert.Equal(t, uint8(24), vms.rclass_and_rb_classext_t.classext)
			assert.Equal(t, uint8(24), vms.rb_classext_struct.classpath)
			assert.Equal(t, uint8(104), vms.rb_classext_struct.as_singleton_class_attached_object)
			assert.Equal(t, uint8(8), vms.iseq_struct.body)
			assert.Equal(t, uint8(104), vms.iseq_constant_body.insn_info_body)
			assert.Equal(t, uint8(120), vms.iseq_constant_body.insn_info_size)
			assert.Equal(t, uint8(112), vms.iseq_constant_body.succ_index_table)
			assert.Equal(t, uint16(160), vms.iseq_constant_body.local_iseq)
			assert.Equal(t, uint16(168), vms.iseq_constant_body.size_of_iseq_constant_body)
			assert.Equal(t, uint8(8), vms.iseq_location_struct.label)
			assert.Equal(t, uint8(16), vms.iseq_location_struct.size_of_iseq_location_struct)
			assert.Equal(t, uint8(24), vms.thread_struct.ractor)
			assert.Equal(t, uint16(0), vms.vm_struct.gc_objspace)
			assert.Equal(t, uint8(76), vms.objspace.flags)
			assert.Equal(t, tc.runningEC, vms.rb_ractor_struct.running_ec)
			assert.Equal(t, tc.objspace, vms.rb_ractor_struct.objspace)
		})
	}
}

func TestRuby41BaseLabels(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		version              uint32
		localIseq            uint64
		localBodyType        uint32
		wantBase, wantMethod string
	}{
		{"block", rubyVersion(4, 1, 0), 0x200, iseqTypeMethod, "outer", "outer"},
		{"self", rubyVersion(4, 1, 0), 0x180, iseqTypeMethod, "block in outer", "block in outer"},
		{"no local iseq", rubyVersion(4, 1, 0), 0, 0, "block in outer", ""},
		{"non-method parent", rubyVersion(4, 1, 0), 0x200, 0, "outer", ""},
		{"4.0 regression", rubyVersion(4, 0, 7), 0x200, iseqTypeMethod, "old base", "old method"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const body = 0x400
			const parentBody = 0x800
			r := &rubyData{version: tc.version}
			vms := &r.vmStructs
			vms.iseq_constant_body.location = 64
			vms.iseq_struct.body = 16
			vms.iseq_constant_body.local_iseq = 176
			vms.iseq_location_struct.base_label = 8
			vms.iseq_location_struct.label = 16
			vms.iseq_location_struct.size_of_iseq_location_struct = 24
			if tc.version >= rubyVersion(4, 1, 0) {
				applyRuby41Layout(r, "amd64")
			}
			memory := make([]byte, 0x2000)
			put := func(at, value uint64) { binary.LittleEndian.PutUint64(memory[at:], value) }
			put(0x180+uint64(vms.iseq_struct.body), body)
			put(0x200+uint64(vms.iseq_struct.body), parentBody)
			put(body+uint64(vms.iseq_constant_body.local_iseq), tc.localIseq)
			put(body+64, 0x1000) // cached source path
			put(body+64+uint64(vms.iseq_location_struct.label), 0x1100)
			put(parentBody+64+uint64(vms.iseq_location_struct.label), 0x1200)
			if tc.version < rubyVersion(4, 1, 0) {
				put(body+72, 0x1300)
				put(parentBody+72, 0x1400)
			}
			binary.LittleEndian.PutUint32(memory[parentBody:], tc.localBodyType)
			if tc.localIseq == 0x180 {
				binary.LittleEndian.PutUint32(memory[body:], tc.localBodyType)
			}
			inst, err := r.Attach(&rubyTestEbpfHandler{}, 1, 0,
				remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)})
			require.NoError(t, err)
			ri := inst.(*rubyInstance)
			for address, text := range map[libpf.Address]string{
				0x1000: "fixture.rb", 0x1100: "block in outer", 0x1200: "outer",
				0x1300: "old base", 0x1400: "old method",
			} {
				ri.addrToString.Add(address, libpf.Intern(text))
			}
			got, err := ri.readIseqBody(body, 0, 0)
			require.NoError(t, err)
			assert.Equal(t, libpf.Intern("block in outer"), got.label)
			assert.Equal(t, libpf.Intern(tc.wantBase), got.baseLabel)
			assert.Equal(t, libpf.Intern(tc.wantMethod), got.methodName)
			assert.Equal(t, libpf.Intern("fixture.rb"), got.sourceFileName)
		})
	}
}

func TestRuby41AttachZJIT(t *testing.T) {
	for _, address := range []libpf.Address{0, 0x2000} {
		r := &rubyData{version: rubyVersion(4, 1, 0), zjitEntryAddr: address}
		applyRuby41Layout(r, "arm64")
		handler := &rubyTestEbpfHandler{}
		_, err := r.Attach(handler, 1, 0x1000, remotememory.RemoteMemory{})
		require.NoError(t, err)
		require.Len(t, handler.procDataUpdates, 1)
		got := handler.procDataUpdates[0]
		var want uint64
		if address != 0 {
			want = uint64(address + 0x1000)
		}
		assert.Equal(t, want, got.Zjit_entry_addr)
		assert.Equal(t, uint8(24), got.Thread_ractor)
		assert.Equal(t, uint16(616), got.Ractor_objspace)
		assert.Equal(t, uint16(432), got.Running_ec)
	}
}
