// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tcpconnect

import (
	"math"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	created, err := New(map[string]any{
		"min_duration": "1ms", "sample_rate": 0.5, "max_entries": 128,
	})
	require.NoError(t, err)
	configured := created.(*probe)
	require.Equal(t, time.Millisecond, configured.minDuration)
	require.Equal(t, uint32(math.MaxUint32/2), configured.sampleThreshold)
	require.Equal(t, uint32(128), configured.maxEntries)
	require.Equal(t, SampleType, configured.ReportMetadata().SampleType)
}

func TestFindMemberOffsetIncludesAnonymousStruct(t *testing.T) {
	structure := &btf.Struct{Members: []btf.Member{
		{
			Offset: 64,
			Type: &btf.Struct{Members: []btf.Member{
				{Name: "sk_err", Offset: 32, Type: &btf.Int{}},
			}},
		},
	}}
	offset, ok := findMemberOffset(structure, "sk_err")
	require.True(t, ok)
	require.Equal(t, uint32(12), offset)
}
