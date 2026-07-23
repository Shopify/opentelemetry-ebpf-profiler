// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package lockwait // import "go.opentelemetry.io/ebpf-profiler/probes/lockwait"

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

type lockWaitBPFMetrics struct {
	Entries             uint64
	Returns             uint64
	UnmatchedReturns    uint64
	Filtered            uint64
	Emitted             uint64
	StateUpdateFailures uint64
	StateOverwrites     uint64
	ActiveStates        int64
}

type lockWaitMetricsCollector struct {
	metricsMap   *ebpf.Map
	startsMap    *ebpf.Map
	perCPUValues []lockWaitBPFMetrics

	mu               sync.Mutex
	previous         lockWaitBPFMetrics
	activeAdjustment atomic.Int64
	readFailures     atomic.Uint64
	previousReads    uint64
}

func newLockWaitMetricsCollector(metricsMap, startsMap *ebpf.Map) (*lockWaitMetricsCollector, error) {
	cpuCount, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("determine possible CPUs: %w", err)
	}
	return &lockWaitMetricsCollector{
		metricsMap:   metricsMap,
		startsMap:    startsMap,
		perCPUValues: make([]lockWaitBPFMetrics, cpuCount),
	}, nil
}

func (collector *lockWaitMetricsCollector) snapshot() (lockWaitBPFMetrics, error) {
	key := uint32(0)
	if err := collector.metricsMap.Lookup(&key, &collector.perCPUValues); err != nil {
		return lockWaitBPFMetrics{}, err
	}
	var result lockWaitBPFMetrics
	for _, value := range collector.perCPUValues {
		result.Entries += value.Entries
		result.Returns += value.Returns
		result.UnmatchedReturns += value.UnmatchedReturns
		result.Filtered += value.Filtered
		result.Emitted += value.Emitted
		result.StateUpdateFailures += value.StateUpdateFailures
		result.StateOverwrites += value.StateOverwrites
		result.ActiveStates += value.ActiveStates
	}
	result.ActiveStates += collector.activeAdjustment.Load()
	if result.ActiveStates < 0 {
		result.ActiveStates = 0
	}
	return result, nil
}

func counterDelta(current, previous uint64) metrics.MetricValue {
	return metrics.MetricValue(current - previous)
}

func lockWaitMetricValues(current, previous lockWaitBPFMetrics,
	readFailures uint64,
) []metrics.Metric {
	return []metrics.Metric{
		{ID: metrics.IDLockWaitEntries,
			Value: counterDelta(current.Entries, previous.Entries)},
		{ID: metrics.IDLockWaitReturns,
			Value: counterDelta(current.Returns, previous.Returns)},
		{ID: metrics.IDLockWaitUnmatchedReturns,
			Value: counterDelta(current.UnmatchedReturns, previous.UnmatchedReturns)},
		{ID: metrics.IDLockWaitFiltered,
			Value: counterDelta(current.Filtered, previous.Filtered)},
		{ID: metrics.IDLockWaitEmitted,
			Value: counterDelta(current.Emitted, previous.Emitted)},
		{ID: metrics.IDLockWaitStateUpdateFailures,
			Value: counterDelta(current.StateUpdateFailures, previous.StateUpdateFailures)},
		{ID: metrics.IDLockWaitStateOverwrites,
			Value: counterDelta(current.StateOverwrites, previous.StateOverwrites)},
		{ID: metrics.IDLockWaitActiveStates,
			Value: metrics.MetricValue(current.ActiveStates)},
		{ID: metrics.IDLockWaitMetricReadFailures,
			Value: metrics.MetricValue(readFailures)},
	}
}

func (collector *lockWaitMetricsCollector) Collect() []metrics.Metric {
	collector.mu.Lock()
	defer collector.mu.Unlock()

	current, err := collector.snapshot()
	if err != nil {
		collector.readFailures.Add(1)
		log.Debugf("Failed to read lock-wait metrics: %v", err)
		reads := collector.readFailures.Load()
		delta := reads - collector.previousReads
		collector.previousReads = reads
		return []metrics.Metric{{
			ID: metrics.IDLockWaitMetricReadFailures, Value: metrics.MetricValue(delta),
		}}
	}
	previous := collector.previous
	collector.previous = current
	reads := collector.readFailures.Load()
	readDelta := reads - collector.previousReads
	collector.previousReads = reads
	return lockWaitMetricValues(current, previous, readDelta)
}

func (collector *lockWaitMetricsCollector) ResetProcess(pid libpf.PID) error {
	iterator := collector.startsMap.Iterate()
	var key uint64
	var timestamp uint64
	keys := make([]uint64, 0)
	for iterator.Next(&key, &timestamp) {
		if libpf.PID(key>>32) == pid {
			keys = append(keys, key)
		}
	}
	var errs []error
	if err := iterator.Err(); err != nil {
		errs = append(errs, err)
	}

	// Deleting the current key while using BPF_MAP_GET_NEXT_KEY can restart
	// iteration from the first key. Gather first, then delete in a second pass.
	var deleted int64
	for _, key := range keys {
		if err := collector.startsMap.Delete(&key); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		deleted++
	}
	if deleted != 0 {
		collector.activeAdjustment.Add(-deleted)
	}
	return errors.Join(errs...)
}

type finalMetricsCloser struct {
	io.Closer
	collect func() []metrics.Metric
}

func (closer *finalMetricsCloser) Close() error {
	if finalizer, ok := closer.Closer.(interface {
		CloseWithMetrics([]metrics.Metric) error
	}); ok {
		return finalizer.CloseWithMetrics(closer.collect())
	}
	return closer.Closer.Close()
}
