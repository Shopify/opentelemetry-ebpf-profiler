// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateLatencyProbes(t *testing.T) {
	for _, name := range []string{
		"block_io_queue_latency",
		"block_io_service_latency",
		"block_io_latency",
		"io_uring_latency",
		"tcp_connect_latency",
		"tcp_send_ack_latency",
		"tcp_receive_consumption_latency",
		"tcp_send_latency",
		"tcp_receive_latency",
		"vfs_read_latency",
		"vfs_write_latency",
	} {
		t.Run(name, func(t *testing.T) {
			probe, err := createCustomProbe(name, map[string]any{})
			require.NoError(t, err)
			require.Equal(t, name, probe.ReportMetadata().SampleType)
			require.Equal(t, "nanoseconds", probe.ReportMetadata().SampleUnit)
			require.True(t, probe.ReportMetadata().ReportValues)
		})
	}
}

func TestCreateLatencyProbeRejectsInvalidConfig(t *testing.T) {
	_, err := createCustomProbe("tcp_send_latency", map[string]any{"sample_rate": 2})
	require.ErrorContains(t, err, "sample_rate must be in the range")

	_, err = createCustomProbe("unknown", map[string]any{})
	require.ErrorContains(t, err, "unknown custom probe")
}
