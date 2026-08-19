// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"errors"
	"fmt"
	"math"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
)

// baseReporter encapsulates shared behavior between all the available reporters.
type baseReporter struct {
	cfg *Config

	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// runLoop handles the run loop
	runLoop *runLoop

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[samples.TraceEventsTree]

	// collectionStartTime tracks when the current collection window started.
	// Initialized when Start() is called. The duration of the first profile may be
	// slightly overestimated as it includes tracer setup time before samples arrive.
	collectionStartTime time.Time
}

var errUnknownProfileType = errors.New("unknown trace profile type")

func (b *baseReporter) Stop() {
	b.runLoop.Stop()
}

func (b *baseReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	if meta.ProfileType == nil {
		return fmt.Errorf("skip reporting trace: %w", errUnknownProfileType)
	}

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}

	key := samples.ResourceKey{
		APMServiceName: meta.APMServiceName,
		ContainerID:    meta.ContainerID,
		PID:            int64(meta.PID),
		ExecutablePath: meta.ExecutablePath,
	}
	sampleKey := samples.SampleKey{
		Hash:      traceutil.HashTrace(trace),
		Comm:      meta.Comm,
		TID:       int64(meta.TID),
		CPU:       int64(meta.CPU),
		SpanID:    meta.SpanID,
		TraceID:   meta.TraceID,
		ExtraMeta: extraMeta,
	}

	eventsTree := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&eventsTree)

	if _, exists := (*eventsTree)[key]; !exists {
		(*eventsTree)[key] = samples.ResourceToProfiles{
			EnvVars: meta.EnvVars,
			Events:  make(map[*samples.TypeMetadata]samples.SampleToEvents),
		}
	}

	rtp := (*eventsTree)[key]
	addTraceEvent(rtp.Events, meta.ProfileType, sampleKey, trace,
		uint64(meta.Timestamp), meta.Value)

	for _, derived := range meta.ProfileType.DerivedProfiles {
		value := derived.Value(trace)
		if value == 0 || derived.ProfileType == nil {
			continue
		}
		addTraceEvent(rtp.Events, derived.ProfileType, sampleKey, trace,
			uint64(meta.Timestamp), int64(min(value, uint64(math.MaxInt64))))
	}
	return nil
}

func addTraceEvent(eventsByType map[*samples.TypeMetadata]samples.SampleToEvents,
	profileType *samples.TypeMetadata, sampleKey samples.SampleKey, trace *libpf.Trace,
	timestamp uint64, value int64,
) {
	if _, exists := eventsByType[profileType]; !exists {
		eventsByType[profileType] = make(samples.SampleToEvents)
	}

	if events, exists := eventsByType[profileType][sampleKey]; exists {
		events.Timestamps = append(events.Timestamps, timestamp)
		events.Values = append(events.Values, value)
		return
	}

	eventsByType[profileType][sampleKey] = &samples.TraceEvents{
		Frames:     trace.Frames,
		Timestamps: []uint64{timestamp},
		Values:     []int64{value},
		Labels:     trace.CustomLabels,
	}
}
