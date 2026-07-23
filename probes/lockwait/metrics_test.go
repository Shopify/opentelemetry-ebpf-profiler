// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package lockwait

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

func TestLockWaitMetricValues(t *testing.T) {
	previous := lockWaitBPFMetrics{
		Entries:             10,
		Returns:             9,
		UnmatchedReturns:    1,
		Filtered:            2,
		Emitted:             6,
		StateUpdateFailures: 1,
		StateOverwrites:     3,
		ActiveStates:        2,
	}
	current := lockWaitBPFMetrics{
		Entries:             15,
		Returns:             13,
		UnmatchedReturns:    2,
		Filtered:            4,
		Emitted:             8,
		StateUpdateFailures: 2,
		StateOverwrites:     6,
		ActiveStates:        7,
	}

	got := make(map[metrics.MetricID]metrics.MetricValue)
	for _, metric := range lockWaitMetricValues(current, previous, 4) {
		got[metric.ID] = metric.Value
	}
	require.Equal(t, map[metrics.MetricID]metrics.MetricValue{
		metrics.IDLockWaitEntries:             5,
		metrics.IDLockWaitReturns:             4,
		metrics.IDLockWaitUnmatchedReturns:    1,
		metrics.IDLockWaitFiltered:            2,
		metrics.IDLockWaitEmitted:             2,
		metrics.IDLockWaitStateUpdateFailures: 1,
		metrics.IDLockWaitStateOverwrites:     3,
		metrics.IDLockWaitActiveStates:        7,
		metrics.IDLockWaitMetricReadFailures:  4,
	}, got)
}

func TestLockWaitBPFMetricsLayout(t *testing.T) {
	require.Equal(t, uintptr(64), unsafe.Sizeof(lockWaitBPFMetrics{}))
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
			return []metrics.Metric{{ID: metrics.IDLockWaitEntries, Value: 3}}
		},
	}
	require.NoError(t, closer.Close())
	require.True(t, subscription.closed)
	require.Equal(t, []metrics.Metric{{ID: metrics.IDLockWaitEntries, Value: 3}},
		subscription.metrics)
}
