// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package offcpu // import "go.opentelemetry.io/ebpf-profiler/probes/offcpu"

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// offCPUTimeBPFMetrics mirrors OffCpuTimeMetrics in off_cpu_time.ebpf.c.
type offCPUTimeBPFMetrics struct {
	SwitchOuts          uint64
	SwitchIns           uint64
	UnmatchedSwitchIns  uint64
	Filtered            uint64
	Emitted             uint64
	StateUpdateFailures uint64
}

type offCPUTimeMetricsCollector struct {
	metricsMap   *ebpf.Map
	perCPUValues []offCPUTimeBPFMetrics

	mu            sync.Mutex
	previous      offCPUTimeBPFMetrics
	readFailures  uint64
	previousReads uint64
}

func newOffCPUTimeMetricsCollector(metricsMap *ebpf.Map) (*offCPUTimeMetricsCollector, error) {
	cpuCount, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("determine possible CPUs: %w", err)
	}
	return &offCPUTimeMetricsCollector{
		metricsMap:   metricsMap,
		perCPUValues: make([]offCPUTimeBPFMetrics, cpuCount),
	}, nil
}

func (collector *offCPUTimeMetricsCollector) snapshot() (offCPUTimeBPFMetrics, error) {
	key := uint32(0)
	if err := collector.metricsMap.Lookup(&key, &collector.perCPUValues); err != nil {
		return offCPUTimeBPFMetrics{}, err
	}
	var result offCPUTimeBPFMetrics
	for _, value := range collector.perCPUValues {
		result.SwitchOuts += value.SwitchOuts
		result.SwitchIns += value.SwitchIns
		result.UnmatchedSwitchIns += value.UnmatchedSwitchIns
		result.Filtered += value.Filtered
		result.Emitted += value.Emitted
		result.StateUpdateFailures += value.StateUpdateFailures
	}
	return result, nil
}

func counterDelta(current, previous uint64) metrics.MetricValue {
	return metrics.MetricValue(current - previous)
}

func offCPUTimeMetricValues(current, previous offCPUTimeBPFMetrics,
	readFailures uint64,
) []metrics.Metric {
	return []metrics.Metric{
		{ID: metrics.IDOffCPUTimeSwitchOuts,
			Value: counterDelta(current.SwitchOuts, previous.SwitchOuts)},
		{ID: metrics.IDOffCPUTimeSwitchIns,
			Value: counterDelta(current.SwitchIns, previous.SwitchIns)},
		{ID: metrics.IDOffCPUTimeUnmatchedSwitchIns,
			Value: counterDelta(current.UnmatchedSwitchIns, previous.UnmatchedSwitchIns)},
		{ID: metrics.IDOffCPUTimeFiltered,
			Value: counterDelta(current.Filtered, previous.Filtered)},
		{ID: metrics.IDOffCPUTimeEmitted,
			Value: counterDelta(current.Emitted, previous.Emitted)},
		{ID: metrics.IDOffCPUTimeStateUpdateFailures,
			Value: counterDelta(current.StateUpdateFailures, previous.StateUpdateFailures)},
		{ID: metrics.IDOffCPUTimeMetricReadFailures,
			Value: metrics.MetricValue(readFailures)},
	}
}

func (collector *offCPUTimeMetricsCollector) Collect() []metrics.Metric {
	collector.mu.Lock()
	defer collector.mu.Unlock()

	current, err := collector.snapshot()
	if err != nil {
		collector.readFailures++
		log.Debugf("Failed to read off-cpu time metrics: %v", err)
		reads := collector.readFailures
		delta := reads - collector.previousReads
		collector.previousReads = reads
		return []metrics.Metric{{
			ID: metrics.IDOffCPUTimeMetricReadFailures, Value: metrics.MetricValue(delta),
		}}
	}
	previous := collector.previous
	collector.previous = current
	reads := collector.readFailures
	readDelta := reads - collector.previousReads
	collector.previousReads = reads
	return offCPUTimeMetricValues(current, previous, readDelta)
}

type finalMetricsCloser struct {
	subscription tracer.MetricsSubscription
	collect      func() []metrics.Metric
}

func (closer *finalMetricsCloser) Close() error {
	return closer.subscription.CloseWithMetrics(closer.collect())
}
