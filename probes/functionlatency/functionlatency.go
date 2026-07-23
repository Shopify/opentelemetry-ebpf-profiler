// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package functionlatency profiles time spent in synchronous kernel functions.
package functionlatency // import "go.opentelemetry.io/ebpf-profiler/probes/functionlatency"

import (
	"errors"
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
	startsMapName      = "function_latency_starts"
	entryProgramName   = "function_latency_entry"
	exitProgramName    = "function_latency_exit"
	originVariableName = "function_latency_origin"
	minNSVariableName  = "function_latency_min_ns"
	sampleVariableName = "function_latency_sample_threshold"
	defaultMaxEntries  = uint32(16 * 1024)
	maximumMaxEntries  = uint32(1024 * 1024)
)

// Definition describes one latency profile type and its kernel attachment.
type Definition struct {
	Symbol     string
	SampleType string
}

type functionLatencyProbe struct {
	definition      Definition
	minDuration     time.Duration
	sampleThreshold uint32
	maxEntries      uint32
}

// New creates a function-latency probe from collector configuration.
// Supported fields are min_duration (a Go duration string), sample_rate in
// (0, 1], and max_entries.
func New(definition Definition, rawConfig any) (tracer.Probe, error) {
	if definition.Symbol == "" {
		return nil, errors.New("kernel symbol is empty")
	}
	if definition.SampleType == "" {
		return nil, errors.New("sample type is empty")
	}

	cfg, err := probeutil.ParseLatencyConfig(
		rawConfig, "function latency", defaultMaxEntries, maximumMaxEntries)
	if err != nil {
		return nil, err
	}

	return &functionLatencyProbe{
		definition:      definition,
		minDuration:     cfg.MinDuration,
		sampleThreshold: cfg.SampleThreshold,
		maxEntries:      cfg.MaxEntries,
	}, nil
}

func (p *functionLatencyProbe) ReportMetadata() *samples.TypeMetadata {
	return &samples.TypeMetadata{
		SampleType:   p.definition.SampleType,
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	}
}

func (p *functionLatencyProbe) Load(origin uint16, ctx *tracer.ProbeContext) (link.Link, error) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust memlock rlimit: %w", err)
	}
	defer restoreRlimit()

	collection, err := ctx.CollectionSpecWith(
		[]string{startsMapName},
		[]string{entryProgramName, exitProgramName},
		[]string{originVariableName, minNSVariableName, sampleVariableName},
	)
	if err != nil {
		return nil, err
	}

	collection.Maps[startsMapName].MaxEntries = p.maxEntries
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
	ownedMaps, err := probeutil.LoadMaps(collection, []string{startsMapName}, resources)
	if err != nil {
		_ = resources.Close()
		return nil, err
	}
	if err := ctx.RewriteMaps(collection, ownedMaps); err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to rewrite function latency maps: %w", err)
	}

	programs := make(map[string]*cebpf.Program, 2)
	if err := ctx.LoadProbeUnwinders(
		collection,
		programs,
		[]tracer.ProgLoaderHelper{
			{Name: entryProgramName, NoTailCallTarget: true, Enable: true},
			{Name: exitProgramName, NoTailCallTarget: true, Enable: true},
		},
		0,
	); err != nil {
		for _, program := range programs {
			resources.Add(program)
		}
		_ = resources.Close()
		return nil, fmt.Errorf("failed to load function latency programs: %w", err)
	}
	for _, program := range programs {
		resources.Add(program)
	}

	// Attach completion before entry so activation can't leave unconsumable starts.
	exitLink, err := link.Kretprobe(p.definition.Symbol, programs[exitProgramName], nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach return kprobe to %q: %w", p.definition.Symbol, err)
	}
	resources.Add(exitLink)

	entryLink, err := link.Kprobe(p.definition.Symbol, programs[entryProgramName], nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach entry kprobe to %q: %w", p.definition.Symbol, err)
	}
	return resources.WrapLink(entryLink), nil
}
