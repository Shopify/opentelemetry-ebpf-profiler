// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package traceutil // import "go.opentelemetry.io/ebpf-profiler/traceutil"

import (
	"cmp"
	"encoding/binary"
	"hash/fnv"
	"slices"
	"strconv"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// HashLabels calculates an order-independent hash for custom sample labels.
func HashLabels(labels map[libpf.String]libpf.String) libpf.TraceHash {
	if len(labels) == 0 {
		return libpf.TraceHash{}
	}

	type label struct {
		key   string
		value string
	}
	ordered := make([]label, 0, len(labels))
	for key, value := range labels {
		ordered = append(ordered, label{key: key.String(), value: value.String()})
	}
	slices.SortFunc(ordered, func(a, b label) int {
		if keyOrder := cmp.Compare(a.key, b.key); keyOrder != 0 {
			return keyOrder
		}
		return cmp.Compare(a.value, b.value)
	})

	h := fnv.New128a()
	var length [8]byte
	for _, item := range ordered {
		binary.LittleEndian.PutUint64(length[:], uint64(len(item.key)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(item.key))
		binary.LittleEndian.PutUint64(length[:], uint64(len(item.value)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(item.value))
	}
	labelsHash, _ := libpf.TraceHashFromBytes(h.Sum(make([]byte, 0, 16)))
	return labelsHash
}

// HashTrace calculates the hash of a trace and returns it.
// Be aware that changes to this calculation will break the ability to
// look backwards for the same TraceHash in our backend.
func HashTrace(trace *libpf.Trace) libpf.TraceHash {
	var buf [24]byte
	h := fnv.New128a()
	for _, uniqueFrame := range trace.Frames {
		frame := uniqueFrame.Value()
		fileID := libpf.FileID{}
		if frame.Mapping.Valid() {
			fileID = frame.Mapping.Value().File.Value().FileID
		}
		_, _ = h.Write(fileID.Bytes())
		// Using FormatUint() or putting AppendUint() into a function leads
		// to escaping to heap (allocation).
		_, _ = h.Write(strconv.AppendUint(buf[:0], uint64(frame.AddressOrLineno), 10))
	}
	// make instead of nil avoids a heap allocation
	traceHash, _ := libpf.TraceHashFromBytes(h.Sum(make([]byte, 0, 16)))
	return traceHash
}
