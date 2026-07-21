//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	cebpf "github.com/cilium/ebpf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func loadTracers(t *testing.T) *ebpfMapsImpl {
	t.Helper()

	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	pidPageToMappingInfo, err := cebpf.NewMap(coll.Maps["pid_page_to_mapping_info"])
	require.NoError(t, err)

	return &ebpfMapsImpl{
		PidPageToMappingInfo: pidPageToMappingInfo,
		errCounter:           make(map[metrics.MetricID]int64),
	}
}

func TestDeleteHeapAllocLiveEntriesPurgesUnobservedPointers(t *testing.T) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	heapMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "test_heap_alloc_live",
		Type:       cebpf.Hash,
		KeySize:    16,
		ValueSize:  8,
		MaxEntries: 16,
	})
	require.NoError(t, err)
	defer heapMap.Close()

	type heapAllocKey struct {
		Pid uint32
		Pad uint32
		Ptr uint64
	}
	const targetPID = libpf.PID(42)
	keys := []heapAllocKey{
		{Pid: uint32(targetPID), Ptr: 0xaaa},
		{Pid: uint32(targetPID), Ptr: 0xbbb},
		{Pid: 99, Ptr: 0xccc},
	}
	for _, key := range keys {
		require.NoError(t, heapMap.Put(key, uint64(512)))
	}

	impl := &ebpfMapsImpl{HeapAllocLive: heapMap}
	// Only 0xaaa reached the userspace tracker. The map scan must also find
	// 0xbbb while retaining another process's allocation.
	require.NoError(t, impl.DeleteHeapAllocLiveEntries(targetPID, []uint64{0xaaa}))

	var value uint64
	assert.ErrorIs(t, heapMap.Lookup(keys[0], &value), cebpf.ErrKeyNotExist)
	assert.ErrorIs(t, heapMap.Lookup(keys[1], &value), cebpf.ErrKeyNotExist)
	require.NoError(t, heapMap.Lookup(keys[2], &value))
	assert.Equal(t, uint64(512), value)
}

func TestLPM(t *testing.T) {
	tests := map[string]struct {
		pid      libpf.PID
		page     uint64
		pageBits uint32
		rip      uint64
		fileID   uint64
		bias     uint64
	}{
		"direct": {pid: 1000, page: 0xAA55AA, pageBits: 64, rip: 0xAA55AA, fileID: 123, bias: 456},
		"random": {pid: 123, page: 0x500000, pageBits: 44, rip: 0x5a63b5, fileID: 456, bias: 789},
	}

	impl := loadTracers(t)

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			prefix := lpm.Prefix{
				Key:    test.page,
				Length: test.pageBits,
			}
			err := impl.UpdatePidPageMappingInfo(test.pid, prefix, test.fileID, test.bias)
			require.NoError(t, err)

			fileID, bias, err := impl.LookupPidPageInformation(test.pid, test.rip)
			if assert.NoError(t, err) {
				assert.Equal(t, test.fileID, uint64(fileID))
				assert.Equal(t, test.bias, bias)
			}

			_, err = impl.DeletePidPageMappingInfo(test.pid, []lpm.Prefix{prefix})
			require.NoError(t, err)
		})
	}
}

func TestBatchOperations(t *testing.T) {
	for _, mapType := range []cebpf.MapType{cebpf.Hash, cebpf.Array, cebpf.LPMTrie} {
		t.Run(mapType.String(), func(t *testing.T) {
			err := probeBatchOperations(mapType)
			if err != nil {
				require.ErrorIs(t, err, cebpf.ErrNotSupported)
			}

			err = probeBatchLookupAndDelete(mapType)
			if err != nil {
				require.ErrorIs(t, err, cebpf.ErrNotSupported)
			}
		})
	}
}
