// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package offcpu

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

func TestOffCPUTimeMetricValues(t *testing.T) {
	previous := offCPUTimeBPFMetrics{
		SwitchOuts:          100,
		SwitchIns:           90,
		UnmatchedSwitchIns:  5,
		Filtered:            60,
		Emitted:             25,
		StateUpdateFailures: 1,
	}
	current := offCPUTimeBPFMetrics{
		SwitchOuts:          150,
		SwitchIns:           140,
		UnmatchedSwitchIns:  6,
		Filtered:            95,
		Emitted:             39,
		StateUpdateFailures: 2,
	}

	got := make(map[metrics.MetricID]metrics.MetricValue)
	for _, metric := range offCPUTimeMetricValues(current, previous, 3) {
		got[metric.ID] = metric.Value
	}
	require.Equal(t, map[metrics.MetricID]metrics.MetricValue{
		metrics.IDOffCPUTimeSwitchOuts:          50,
		metrics.IDOffCPUTimeSwitchIns:           50,
		metrics.IDOffCPUTimeUnmatchedSwitchIns:  1,
		metrics.IDOffCPUTimeFiltered:            35,
		metrics.IDOffCPUTimeEmitted:             14,
		metrics.IDOffCPUTimeStateUpdateFailures: 1,
		metrics.IDOffCPUTimeMetricReadFailures:  3,
	}, got)
}

func TestOffCPUTimeBPFMetricsLayout(t *testing.T) {
	require.Equal(t, uintptr(48), unsafe.Sizeof(offCPUTimeBPFMetrics{}))
}

type testMetricsSubscription struct {
	closed  bool
	metrics []metrics.Metric
}

func (subscription *testMetricsSubscription) Close() error {
	subscription.closed = true
	return nil
}

func (subscription *testMetricsSubscription) CloseWithMetrics(final []metrics.Metric) error {
	subscription.closed = true
	subscription.metrics = final
	return nil
}

func TestFinalMetricsCloserPreservesDeltas(t *testing.T) {
	subscription := &testMetricsSubscription{}
	closer := &finalMetricsCloser{
		Closer: subscription,
		collect: func() []metrics.Metric {
			return []metrics.Metric{{ID: metrics.IDOffCPUTimeEmitted, Value: 3}}
		},
	}
	require.NoError(t, closer.Close())
	require.True(t, subscription.closed)
	require.Equal(t, []metrics.Metric{{ID: metrics.IDOffCPUTimeEmitted, Value: 3}},
		subscription.metrics)
}
