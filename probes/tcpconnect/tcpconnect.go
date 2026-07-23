// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package tcpconnect profiles TCP handshake latency by the initiating stack.
package tcpconnect // import "go.opentelemetry.io/ebpf-profiler/probes/tcpconnect"

import (
	"fmt"
	"os"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/probes/internal/probeutil"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	// SampleType measures tcp_v4/v6_connect through ESTABLISHED or CLOSE.
	SampleType = "tcp_connect_latency"

	startsMapName           = "tcp_connect_starts"
	v4ProgramName           = "tcp_connect_v4_start"
	v6ProgramName           = "tcp_connect_v6_start"
	stateProgramName        = "tcp_connect_state"
	originVariableName      = "tcp_connect_origin"
	minNSVariableName       = "tcp_connect_min_ns"
	sampleVariableName      = "tcp_connect_sample_threshold"
	hasErrorVariableName    = "tcp_connect_has_sk_err"
	errorOffsetVariableName = "tcp_connect_sk_err_offset"
	v4Symbol                = "tcp_v4_connect"
	v6Symbol                = "tcp_v6_connect"
	stateTracepointName     = "inet_sock_set_state"
	defaultMaxEntries       = uint32(16 * 1024)
	maximumMaxEntries       = uint32(1024 * 1024)
)

type probe struct {
	minDuration     time.Duration
	sampleThreshold uint32
	maxEntries      uint32
}

// New creates a TCP handshake latency probe.
func New(rawConfig any) (tracer.Probe, error) {
	cfg, err := probeutil.ParseLatencyConfig(
		rawConfig, "TCP connect latency", defaultMaxEntries, maximumMaxEntries)
	if err != nil {
		return nil, err
	}
	return &probe{
		minDuration:     cfg.MinDuration,
		sampleThreshold: cfg.SampleThreshold,
		maxEntries:      cfg.MaxEntries,
	}, nil
}

func (p *probe) ReportMetadata() *samples.TypeMetadata {
	return &samples.TypeMetadata{
		SampleType: SampleType, SampleUnit: "nanoseconds", ReportValues: true,
	}
}

func (p *probe) Load(origin uint16, ctx *tracer.ProbeContext) (link.Link, error) {
	hasError, errorOffset := discoverSocketErrorOffset()
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust memlock rlimit: %w", err)
	}
	defer restoreRlimit()

	mapNames := []string{startsMapName}
	programNames := []string{v4ProgramName, v6ProgramName, stateProgramName}
	variableNames := []string{
		originVariableName, minNSVariableName, sampleVariableName,
		hasErrorVariableName, errorOffsetVariableName,
	}
	collection, err := ctx.CollectionSpecWith(mapNames, programNames, variableNames)
	if err != nil {
		return nil, err
	}
	collection.Maps[startsMapName].MaxEntries = p.maxEntries
	variables := map[string]any{
		originVariableName:      origin,
		minNSVariableName:       uint64(p.minDuration),
		sampleVariableName:      p.sampleThreshold,
		hasErrorVariableName:    hasError,
		errorOffsetVariableName: errorOffset,
	}
	for name, value := range variables {
		if err := collection.Variables[name].Set(value); err != nil {
			return nil, fmt.Errorf("failed to set eBPF variable %q: %w", name, err)
		}
	}

	resources := &probeutil.Resources{}
	ownedMaps, err := probeutil.LoadMaps(collection, mapNames, resources)
	if err != nil {
		_ = resources.Close()
		return nil, err
	}
	if err := ctx.RewriteMaps(collection, ownedMaps); err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to rewrite TCP connect maps: %w", err)
	}
	programs := make(map[string]*cebpf.Program, len(programNames))
	if err := ctx.LoadProbeUnwinders(
		collection,
		programs,
		[]tracer.ProgLoaderHelper{
			{Name: v4ProgramName, NoTailCallTarget: true, Enable: true},
			{Name: v6ProgramName, NoTailCallTarget: true, Enable: true},
			{Name: stateProgramName, NoTailCallTarget: true, Enable: true},
		},
		0,
	); err != nil {
		for _, program := range programs {
			resources.Add(program)
		}
		_ = resources.Close()
		return nil, fmt.Errorf("failed to load TCP connect programs: %w", err)
	}
	for _, program := range programs {
		resources.Add(program)
	}

	stateLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: stateTracepointName, Program: programs[stateProgramName],
	})
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach %s raw tracepoint: %w", stateTracepointName, err)
	}
	resources.Add(stateLink)

	v6Link, v6Err := link.Kprobe(v6Symbol, programs[v6ProgramName], nil)
	if v6Err == nil {
		resources.Add(v6Link)
	} else {
		log.Warnf("Unable to attach optional TCP IPv6 connect hook %s: %v", v6Symbol, v6Err)
	}
	v4Link, err := link.Kprobe(v4Symbol, programs[v4ProgramName], nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach TCP connect hook %s: %w", v4Symbol, err)
	}
	return resources.WrapLink(v4Link), nil
}

func discoverSocketErrorOffset() (bool, uint32) {
	file, err := os.Open("/sys/kernel/btf/vmlinux")
	if err != nil {
		return false, 0
	}
	defer file.Close()
	spec, err := btf.LoadSplitSpecFromReader(file, nil)
	if err != nil {
		return false, 0
	}
	var socket *btf.Struct
	if err := spec.TypeByName("sock", &socket); err != nil {
		return false, 0
	}
	if offset, ok := findMemberOffset(socket, "sk_err"); ok {
		return true, offset
	}
	return false, 0
}

func findMemberOffset(structure *btf.Struct, name string) (uint32, bool) {
	for _, member := range structure.Members {
		if member.Name == name {
			return uint32(member.Offset.Bytes()), true
		}
	}
	for _, member := range structure.Members {
		if member.Name != "" {
			continue
		}
		anonymous, ok := btf.UnderlyingType(member.Type).(*btf.Struct)
		if !ok {
			continue
		}
		if offset, found := findMemberOffset(anonymous, name); found {
			return uint32(member.Offset.Bytes()) + offset, true
		}
	}
	return 0, false
}
