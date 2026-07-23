// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tcpsequence

import (
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
)

func TestNewProfiles(t *testing.T) {
	send, err := NewSendACK(map[string]any{
		"min_duration": "1ms", "sample_rate": 1.0, "max_entries": 128,
	})
	require.NoError(t, err)
	require.Equal(t, SendACKSampleType, send.ReportMetadata().SampleType)
	require.Equal(t, time.Millisecond, send.(*probe).minDuration)

	receive, err := NewReceive(nil)
	require.NoError(t, err)
	require.Equal(t, ReceiveSampleType, receive.ReportMetadata().SampleType)
}

func TestNewProfilesRejectInvalidConfig(t *testing.T) {
	_, err := NewSendACK(map[string]any{"sample_rate": 2.0})
	require.ErrorContains(t, err, "sample_rate")
	_, err = NewReceive(map[string]any{"max_entries": 0})
	require.ErrorContains(t, err, "max_entries")
}

func TestMemberOffsetIncludesAnonymousStruct(t *testing.T) {
	structure := &btf.Struct{Members: []btf.Member{{
		Offset: 64,
		Type: &btf.Struct{Members: []btf.Member{{
			Name: "copied_seq", Offset: 32, Type: &btf.Int{},
		}}},
	}}}
	offset, ok := memberOffset(structure, "copied_seq")
	require.True(t, ok)
	require.Equal(t, uint32(12), offset)
}
