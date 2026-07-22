// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package biostacks profiles block I/O queue latency by initialization stack.
package biostacks // import "go.opentelemetry.io/ebpf-profiler/probes/biostacks"

import (
	"fmt"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/probes/internal/probeutil"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	// SampleType is the profile sample type emitted by this probe.
	SampleType = "block_io_queue_latency"

	scratchMapName       = "block_io_stacks_scratch"
	inflightMapName      = "block_io_stacks_inflight"
	startProgramName     = "block_io_stacks_start"
	issueProgramName     = "block_io_stacks_issue"
	originVariableName   = "block_io_stacks_origin"
	minNSVariableName    = "block_io_stacks_min_ns"
	sampleVariableName   = "block_io_stacks_sample_threshold"
	defaultMaxEntries    = uint32(4 * 1024)
	maximumMaxEntries    = uint32(64 * 1024)
	startTracepointGroup = "block"
	startTracepointName  = "block_io_start"
	issueTracepointName  = "block_rq_issue"
)

type blockIOStacksProbe struct {
	minDuration     time.Duration
	sampleThreshold uint32
	maxEntries      uint32
}

// New creates a block I/O stack-latency probe. Supported fields are
// min_duration (a Go duration string), sample_rate in (0, 1], and max_entries.
func New(rawConfig any) (tracer.Probe, error) {
	cfg, err := probeutil.ParseLatencyConfig(
		rawConfig, "block I/O stacks", defaultMaxEntries, maximumMaxEntries)
	if err != nil {
		return nil, err
	}
	return &blockIOStacksProbe{
		minDuration:     cfg.MinDuration,
		sampleThreshold: cfg.SampleThreshold,
		maxEntries:      cfg.MaxEntries,
	}, nil
}

func (p *blockIOStacksProbe) ReportMetadata() *samples.TypeMetadata {
	return &samples.TypeMetadata{
		SampleType:   SampleType,
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	}
}

func (p *blockIOStacksProbe) Load(origin uint16, ctx *tracer.ProbeContext) (link.Link, error) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust memlock rlimit: %w", err)
	}
	defer restoreRlimit()

	collection, err := ctx.CollectionSpecWith(
		[]string{scratchMapName, inflightMapName},
		[]string{startProgramName, issueProgramName},
		[]string{originVariableName, minNSVariableName, sampleVariableName},
	)
	if err != nil {
		return nil, err
	}
	collection.Maps[inflightMapName].MaxEntries = p.maxEntries

	variables := map[string]any{
		originVariableName: origin,
		minNSVariableName:  uint64(p.minDuration),
		sampleVariableName: p.sampleThreshold,
	}
	for name, value := range variables {
		if err := collection.Variables[name].Set(value); err != nil {
			return nil, fmt.Errorf("failed to set eBPF variable %q: %w", name, err)
		}
	}
	resources := &probeutil.Resources{}
	ownedMaps, err := probeutil.LoadMaps(
		collection, []string{scratchMapName, inflightMapName}, resources)
	if err != nil {
		_ = resources.Close()
		return nil, err
	}
	if err := ctx.RewriteMaps(collection, ownedMaps); err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to rewrite block I/O maps: %w", err)
	}

	programs := make(map[string]*cebpf.Program, 2)
	if err := ctx.LoadProbeUnwinders(
		collection,
		programs,
		[]tracer.ProgLoaderHelper{
			{Name: issueProgramName, NoTailCallTarget: true, Enable: true},
			{Name: startProgramName, NoTailCallTarget: true, Enable: true},
		},
		0,
	); err != nil {
		for _, program := range programs {
			resources.Add(program)
		}
		_ = resources.Close()
		return nil, fmt.Errorf("failed to load block I/O programs: %w", err)
	}
	for _, program := range programs {
		resources.Add(program)
	}
	issueProgram := programs[issueProgramName]
	startProgram := programs[startProgramName]

	// Attach completion before start so activation can't leave unconsumable entries.
	issueLink, err := link.Tracepoint(
		startTracepointGroup, issueTracepointName, issueProgram, nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach %s tracepoint: %w", issueTracepointName, err)
	}
	resources.Add(issueLink)

	startLink, err := link.Tracepoint(
		startTracepointGroup, startTracepointName, startProgram, nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach %s tracepoint: %w", startTracepointName, err)
	}
	return resources.WrapLink(startLink), nil
}
