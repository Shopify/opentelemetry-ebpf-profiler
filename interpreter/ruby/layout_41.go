// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"strings"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// Ruby's 4.1 development ABI is still changing. These offsets were checked with
// DWARF from this exact revision on Linux amd64 and arm64, not inferred from the
// 4.1.0 version string. Keep this exception narrower than general 4.1 support.
const ruby41Revision = "a68e42cfad16857e146d27044c9116cd4bae950b"

func rubyUses41Layout(version uint32, revision, description string) bool {
	if version != rubyVersion(4, 1, 0) {
		return false
	}
	if revision != "" {
		return revision == ruby41Revision
	}
	// ruby_revision is a local symbol and can disappear after stripping.
	// ruby_description is exported and includes the ten-character revision.
	return strings.HasPrefix(description, "ruby 4.1.0dev (") &&
		strings.Contains(description, " shopify "+ruby41Revision[:10]+")")
}

func applyRuby41Layout(r *rubyData, arch string) {
	vms := &r.vmStructs
	r.hasClassPath = true
	r.rubyFlSingleton = libpf.Address(RUBY_FL_USER1)
	vms.rclass_and_rb_classext_t.classext = 24
	vms.rb_classext_struct.classpath = 24
	vms.rb_classext_struct.as_singleton_class_attached_object = 104
	r.lastOpId = 174

	vms.iseq_struct.body = 8
	vms.iseq_constant_body.insn_info_body = 104
	vms.iseq_constant_body.insn_info_size = 120
	vms.iseq_constant_body.succ_index_table = 112
	vms.iseq_constant_body.local_iseq = 160
	// Read only the prefix through local_iseq; the trailing JIT fields depend
	// on the build configuration and are not needed for symbolization.
	vms.iseq_constant_body.size_of_iseq_constant_body = 168
	vms.iseq_location_struct.base_label = 0 // Removed; derived through local_iseq.
	vms.iseq_location_struct.label = 8
	vms.iseq_location_struct.size_of_iseq_location_struct = 16

	// GC state moved from VM-wide objspace to the current ractor's objspace.
	// vm.gc.global_objspace has a different type and must not be substituted.
	r.hasObjspace = true
	vms.vm_struct.gc_objspace = 0
	vms.thread_struct.ractor = 24
	vms.objspace.flags = 76
	if arch == "amd64" {
		vms.rb_ractor_struct.running_ec = 416
		vms.rb_ractor_struct.objspace = 600
	} else {
		vms.rb_ractor_struct.running_ec = 432
		vms.rb_ractor_struct.objspace = 616
	}
}
