// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// offsetMockMemory is an io.ReaderAt backed by (address, bytes) regions, used to
// exercise the Attach-time Ruby 4.0 layout probes without a live process.
type offsetMockMemory struct {
	regions map[uint64][]byte
}

func newOffsetMockMemory() *offsetMockMemory {
	return &offsetMockMemory{regions: make(map[uint64][]byte)}
}

func (m *offsetMockMemory) writeUint32(addr uint64, val uint32) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, val)
	m.regions[addr] = buf
}

func (m *offsetMockMemory) writeUint64(addr, val uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, val)
	m.regions[addr] = buf
}

func (m *offsetMockMemory) ReadAt(p []byte, off int64) (int, error) {
	if data, ok := m.regions[uint64(off)]; ok {
		n := copy(p, data)
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil
	}
	return 0, io.EOF
}

// ruby405Data returns rubyData carrying the version-derived stock Ruby 4.0.5
// offsets. A downstream 4.0.5 build may have either offset shifted by 8 bytes.
func ruby405Data() *rubyData {
	r := &rubyData{
		version:       rubyVersion(4, 0, 5),
		currentCtxPtr: 0x100000,
		currentVMPtr:  0x110000,
	}
	vms := &r.vmStructs
	vms.execution_context_struct.vm_stack = 0
	vms.execution_context_struct.vm_stack_size = 8
	vms.execution_context_struct.cfp = 16
	vms.size_of_value = 8
	vms.rb_ractor_struct.running_ec = 0x138
	vms.vm_struct.gc_objspace = 1248
	vms.objspace.flags = 28
	vms.objspace.size_of_flags = 4
	return r
}

// writeEC lays out an rb_execution_context_struct at ecAddr. When valid, the
// control-frame pointer lands inside the VM stack; otherwise it is out of range.
func (m *offsetMockMemory) writeEC(ecAddr uint64, valid bool) {
	const stackBase = 0x400000
	const slots = 1024 // stack spans [stackBase, stackBase+slots*8)
	cfp := uint64(stackBase + 0x800)
	if !valid {
		cfp = stackBase + slots*8 + 0x1000
	}
	m.writeUint64(ecAddr+0, stackBase)
	m.writeUint64(ecAddr+8, slots)
	m.writeUint64(ecAddr+16, cfp)
}

func TestChooseRubyRunningEcOffset(t *testing.T) {
	const (
		mainRactor = 0x200000
		baseOff    = 0x138
		shiftedOff = 0x140
	)

	t.Run("pshopify 4.0.5: shifted offset validates", func(t *testing.T) {
		mem := newOffsetMockMemory()
		mem.writeUint64(0x100000, mainRactor)
		mem.writeUint64(mainRactor+baseOff, 0x500000)
		mem.writeEC(0x500000, false)
		mem.writeUint64(mainRactor+shiftedOff, 0x600000)
		mem.writeEC(0x600000, true)

		r := ruby405Data()
		rm := remotememory.RemoteMemory{ReaderAt: mem}
		assert.Equal(t, uint16(shiftedOff), r.chooseRubyRunningEcOffset(rm, 0))
	})

	t.Run("stock 4.0.5: base offset validates", func(t *testing.T) {
		mem := newOffsetMockMemory()
		mem.writeUint64(0x100000, mainRactor)
		mem.writeUint64(mainRactor+baseOff, 0x600000)
		mem.writeEC(0x600000, true)
		mem.writeUint64(mainRactor+shiftedOff, 0x700000)
		mem.writeEC(0x700000, false)

		r := ruby405Data()
		rm := remotememory.RemoteMemory{ReaderAt: mem}
		assert.Equal(t, uint16(baseOff), r.chooseRubyRunningEcOffset(rm, 0))
	})

	t.Run("inconclusive probe falls back to base", func(t *testing.T) {
		mem := newOffsetMockMemory()
		mem.writeUint64(0x100000, mainRactor)
		r := ruby405Data()
		rm := remotememory.RemoteMemory{ReaderAt: mem}
		assert.Equal(t, uint16(baseOff), r.chooseRubyRunningEcOffset(rm, 0))
	})

	t.Run("no ractor symbol skips probe", func(t *testing.T) {
		r := ruby405Data()
		r.currentCtxPtr = 0
		rm := remotememory.RemoteMemory{ReaderAt: newOffsetMockMemory()}
		assert.Equal(t, uint16(baseOff), r.chooseRubyRunningEcOffset(rm, 0))
	})

	t.Run("4.0.6 uses loader offset without probing", func(t *testing.T) {
		r := ruby405Data()
		r.version = rubyVersion(4, 0, 6)
		r.vmStructs.rb_ractor_struct.running_ec = shiftedOff
		rm := remotememory.RemoteMemory{ReaderAt: newOffsetMockMemory()}
		assert.Equal(t, uint16(shiftedOff), r.chooseRubyRunningEcOffset(rm, 0))
	})
}

func TestChooseRubyVMObjspaceOffset(t *testing.T) {
	const (
		currentVMGlobal = 0x110000
		vm              = 0x300000
		baseOff         = 1248
		shiftedOff      = 1256
		objspaceBase    = 0x700000
		objspaceShifted = 0x710000
	)

	writeCandidate := func(mem *offsetMockMemory, offset, objspace uint64) {
		mem.writeUint64(vm+offset, objspace)
		mem.writeUint32(objspace+28, 0x1402)
	}

	t.Run("pshopify 4.0.5: shifted objspace validates", func(t *testing.T) {
		mem := newOffsetMockMemory()
		mem.writeUint64(currentVMGlobal, vm)
		// vm+baseOff is readable but null, matching Core's coverage_mode+padding.
		mem.writeUint64(vm+baseOff, 0)
		writeCandidate(mem, shiftedOff, objspaceShifted)

		r := ruby405Data()
		rm := remotememory.RemoteMemory{ReaderAt: mem}
		assert.Equal(t, uint16(shiftedOff), r.chooseRubyVMObjspaceOffset(rm, 0))
	})

	t.Run("stock 4.0.5: base is preferred when both are readable", func(t *testing.T) {
		mem := newOffsetMockMemory()
		mem.writeUint64(currentVMGlobal, vm)
		writeCandidate(mem, baseOff, objspaceBase)
		writeCandidate(mem, shiftedOff, objspaceShifted)

		r := ruby405Data()
		rm := remotememory.RemoteMemory{ReaderAt: mem}
		assert.Equal(t, uint16(baseOff), r.chooseRubyVMObjspaceOffset(rm, 0))
	})

	t.Run("TLS EC discovery still probes objspace independently", func(t *testing.T) {
		mem := newOffsetMockMemory()
		mem.writeUint64(currentVMGlobal, vm)
		mem.writeUint64(vm+baseOff, 0)
		writeCandidate(mem, shiftedOff, objspaceShifted)

		r := ruby405Data()
		r.staticTLSOffset = -0x78
		r.currentCtxPtr = 0
		rm := remotememory.RemoteMemory{ReaderAt: mem}
		assert.Equal(t, uint16(shiftedOff), r.chooseRubyVMObjspaceOffset(rm, 0))
	})

	t.Run("inconclusive probe falls back to base", func(t *testing.T) {
		mem := newOffsetMockMemory()
		mem.writeUint64(currentVMGlobal, vm)
		r := ruby405Data()
		rm := remotememory.RemoteMemory{ReaderAt: mem}
		assert.Equal(t, uint16(baseOff), r.chooseRubyVMObjspaceOffset(rm, 0))
	})

	t.Run("no current VM symbol skips probe", func(t *testing.T) {
		r := ruby405Data()
		r.currentVMPtr = 0
		rm := remotememory.RemoteMemory{ReaderAt: newOffsetMockMemory()}
		assert.Equal(t, uint16(baseOff), r.chooseRubyVMObjspaceOffset(rm, 0))
	})

	t.Run("4.0.6 uses loader offset without probing", func(t *testing.T) {
		r := ruby405Data()
		r.version = rubyVersion(4, 0, 6)
		r.vmStructs.vm_struct.gc_objspace = shiftedOff
		rm := remotememory.RemoteMemory{ReaderAt: newOffsetMockMemory()}
		assert.Equal(t, uint16(shiftedOff), r.chooseRubyVMObjspaceOffset(rm, 0))
	})
}
