// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package tcpsequence profiles TCP send-to-ACK and receive-consumption latency.
package tcpsequence // import "go.opentelemetry.io/ebpf-profiler/probes/tcpsequence"

import (
	"fmt"
	"os"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/probes/internal/probeutil"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	SendACKSampleType = "tcp_send_ack_latency"
	ReceiveSampleType = "tcp_receive_consumption_latency"

	defaultMaxEntries = uint32(16 * 1024)
	maximumMaxEntries = uint32(1024 * 1024)
)

type mode uint8

const (
	sendACK mode = iota
	receiveConsumption
)

type probe struct {
	mode            mode
	minDuration     time.Duration
	sampleThreshold uint32
	maxEntries      uint32
}

type tcpLayout struct {
	writeSequence   uint32
	sendUnacked     uint32
	copiedSequence  uint32
	skbControlBlock uint32
	skbSequence     uint32
	skbEndSequence  uint32
}

// NewSendACK creates a profile measuring tcp_sendmsg entry until cumulative ACK.
func NewSendACK(rawConfig any) (tracer.Probe, error) {
	return newProbe(sendACK, rawConfig)
}

// NewReceive creates a profile measuring data queueing until tcp_recvmsg consumes it.
func NewReceive(rawConfig any) (tracer.Probe, error) {
	return newProbe(receiveConsumption, rawConfig)
}

func newProbe(selected mode, rawConfig any) (tracer.Probe, error) {
	name := "TCP send-to-ACK latency"
	if selected == receiveConsumption {
		name = "TCP receive-consumption latency"
	}
	cfg, err := probeutil.ParseLatencyConfig(
		rawConfig, name, defaultMaxEntries, maximumMaxEntries)
	if err != nil {
		return nil, err
	}
	return &probe{
		mode: selected, minDuration: cfg.MinDuration,
		sampleThreshold: cfg.SampleThreshold, maxEntries: cfg.MaxEntries,
	}, nil
}

func (p *probe) ReportMetadata() *samples.TypeMetadata {
	sampleType := SendACKSampleType
	if p.mode == receiveConsumption {
		sampleType = ReceiveSampleType
	}
	return &samples.TypeMetadata{
		SampleType: sampleType, SampleUnit: "nanoseconds", ReportValues: true,
	}
}

func (p *probe) Load(origin uint16, ctx *tracer.ProbeContext) (link.Link, error) {
	layout, err := discoverTCPLayout(p.mode)
	if err != nil {
		return nil, err
	}
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust memlock rlimit: %w", err)
	}
	defer restoreRlimit()
	if p.mode == sendACK {
		return p.loadSendACK(origin, ctx, layout)
	}
	return p.loadReceive(origin, ctx, layout)
}

func (p *probe) loadSendACK(
	origin uint16, ctx *tracer.ProbeContext, layout tcpLayout,
) (link.Link, error) {
	maps := []string{
		"tcp_ack_send_calls", "tcp_ack_track_calls", "tcp_ack_active_sockets",
	}
	programs := []string{
		"tcp_ack_send_entry", "tcp_ack_send_exit",
		"tcp_ack_track_entry", "tcp_ack_track_exit", "tcp_ack_close",
	}
	variables := map[string]any{
		"tcp_ack_origin":           origin,
		"tcp_ack_min_ns":           uint64(p.minDuration),
		"tcp_ack_sample_threshold": p.sampleThreshold,
		"tcp_ack_has_layout":       true,
		"tcp_ack_write_seq_offset": layout.writeSequence,
		"tcp_ack_snd_una_offset":   layout.sendUnacked,
	}
	_, resources, loaded, err := p.load(ctx, maps, programs, variables)
	if err != nil {
		return nil, err
	}
	closeLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "inet_sock_set_state", Program: loaded["tcp_ack_close"],
	})
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach TCP send close tracking: %w", err)
	}
	resources.Add(closeLink)
	attachments := []struct {
		program string
		symbol  string
		ret     bool
	}{
		{"tcp_ack_track_exit", "tcp_ack", true},
		{"tcp_ack_track_entry", "tcp_ack", false},
		{"tcp_ack_send_exit", "tcp_sendmsg", true},
	}
	for _, attachment := range attachments {
		probeLink, attachErr := attachKprobe(
			attachment.symbol, loaded[attachment.program], attachment.ret)
		if attachErr != nil {
			_ = resources.Close()
			return nil, fmt.Errorf("failed to attach %s to %s: %w",
				attachment.program, attachment.symbol, attachErr)
		}
		resources.Add(probeLink)
	}
	entryLink, err := link.Kprobe("tcp_sendmsg", loaded["tcp_ack_send_entry"], nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach TCP send entry: %w", err)
	}
	return resources.WrapLink(entryLink), nil
}

func (p *probe) loadReceive(
	origin uint16, ctx *tracer.ProbeContext, layout tcpLayout,
) (link.Link, error) {
	maps := []string{"tcp_receive_calls"}
	programs := []string{
		"tcp_receive_data", "tcp_receive_entry", "tcp_receive_exit", "tcp_receive_close",
	}
	variables := map[string]any{
		"tcp_receive_origin":             origin,
		"tcp_receive_min_ns":             uint64(p.minDuration),
		"tcp_receive_sample_threshold":   p.sampleThreshold,
		"tcp_receive_has_layout":         true,
		"tcp_receive_copied_seq_offset":  layout.copiedSequence,
		"tcp_receive_skb_cb_offset":      layout.skbControlBlock,
		"tcp_receive_skb_seq_offset":     layout.skbSequence,
		"tcp_receive_skb_end_seq_offset": layout.skbEndSequence,
	}
	_, resources, loaded, err := p.load(ctx, maps, programs, variables)
	if err != nil {
		return nil, err
	}
	closeLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "inet_sock_set_state", Program: loaded["tcp_receive_close"],
	})
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach TCP receive close tracking: %w", err)
	}
	resources.Add(closeLink)
	dataLink, err := link.Kprobe("tcp_data_queue", loaded["tcp_receive_data"], nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach TCP receive data queue: %w", err)
	}
	resources.Add(dataLink)
	exitLink, err := link.Kretprobe("tcp_recvmsg", loaded["tcp_receive_exit"], nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach TCP receive exit: %w", err)
	}
	resources.Add(exitLink)
	entryLink, err := link.Kprobe("tcp_recvmsg", loaded["tcp_receive_entry"], nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach TCP receive entry: %w", err)
	}
	return resources.WrapLink(entryLink), nil
}

func (p *probe) load(
	ctx *tracer.ProbeContext,
	mapNames, programNames []string,
	variables map[string]any,
) (*cebpf.CollectionSpec, *probeutil.Resources, map[string]*cebpf.Program, error) {
	variableNames := make([]string, 0, len(variables))
	for name := range variables {
		variableNames = append(variableNames, name)
	}
	collection, err := ctx.CollectionSpecWith(mapNames, programNames, variableNames)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, name := range mapNames {
		collection.Maps[name].MaxEntries = p.maxEntries
	}
	for name, value := range variables {
		if err := collection.Variables[name].Set(value); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to set eBPF variable %q: %w", name, err)
		}
	}
	resources := &probeutil.Resources{}
	ownedMaps, err := probeutil.LoadMaps(collection, mapNames, resources)
	if err != nil {
		_ = resources.Close()
		return nil, nil, nil, err
	}
	if err := ctx.RewriteMaps(collection, ownedMaps); err != nil {
		_ = resources.Close()
		return nil, nil, nil, fmt.Errorf("failed to rewrite TCP sequence maps: %w", err)
	}
	loaded := make(map[string]*cebpf.Program, len(programNames))
	helpers := make([]tracer.ProgLoaderHelper, 0, len(programNames))
	for _, name := range programNames {
		helpers = append(helpers, tracer.ProgLoaderHelper{
			Name: name, NoTailCallTarget: true, Enable: true,
		})
	}
	if err := ctx.LoadProbeUnwinders(collection, loaded, helpers, 0); err != nil {
		for _, program := range loaded {
			resources.Add(program)
		}
		_ = resources.Close()
		return nil, nil, nil, fmt.Errorf("failed to load TCP sequence programs: %w", err)
	}
	for _, program := range loaded {
		resources.Add(program)
	}
	return collection, resources, loaded, nil
}

func attachKprobe(symbol string, program *cebpf.Program, ret bool) (link.Link, error) {
	if ret {
		return link.Kretprobe(symbol, program, nil)
	}
	return link.Kprobe(symbol, program, nil)
}

func discoverTCPLayout(selected mode) (tcpLayout, error) {
	file, err := os.Open("/sys/kernel/btf/vmlinux")
	if err != nil {
		return tcpLayout{}, fmt.Errorf("TCP sequence profiles require kernel BTF: %w", err)
	}
	defer file.Close()
	spec, err := btf.LoadSplitSpecFromReader(file, nil)
	if err != nil {
		return tcpLayout{}, fmt.Errorf("failed to load kernel BTF: %w", err)
	}
	lookupType := func(name string) (*btf.Struct, error) {
		var structure *btf.Struct
		if err := spec.TypeByName(name, &structure); err != nil {
			return nil, fmt.Errorf("kernel BTF is missing struct %s: %w", name, err)
		}
		return structure, nil
	}
	lookupMember := func(structure *btf.Struct, name string) (uint32, error) {
		offset, ok := memberOffset(structure, name)
		if !ok {
			return 0, fmt.Errorf("kernel BTF is missing %s.%s", structure.Name, name)
		}
		return offset, nil
	}
	tcpSocket, err := lookupType("tcp_sock")
	if err != nil {
		return tcpLayout{}, err
	}
	layout := tcpLayout{}
	if selected == sendACK {
		if layout.writeSequence, err = lookupMember(tcpSocket, "write_seq"); err != nil {
			return tcpLayout{}, err
		}
		if layout.sendUnacked, err = lookupMember(tcpSocket, "snd_una"); err != nil {
			return tcpLayout{}, err
		}
		return layout, nil
	}
	if layout.copiedSequence, err = lookupMember(tcpSocket, "copied_seq"); err != nil {
		return tcpLayout{}, err
	}
	skb, err := lookupType("sk_buff")
	if err != nil {
		return tcpLayout{}, err
	}
	controlBlock, err := lookupType("tcp_skb_cb")
	if err != nil {
		return tcpLayout{}, err
	}
	if layout.skbControlBlock, err = lookupMember(skb, "cb"); err != nil {
		return tcpLayout{}, err
	}
	if layout.skbSequence, err = lookupMember(controlBlock, "seq"); err != nil {
		return tcpLayout{}, err
	}
	if layout.skbEndSequence, err = lookupMember(controlBlock, "end_seq"); err != nil {
		return tcpLayout{}, err
	}
	return layout, nil
}

func memberOffset(structure *btf.Struct, name string) (uint32, bool) {
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
		if offset, found := memberOffset(anonymous, name); found {
			return uint32(member.Offset.Bytes()) + offset, true
		}
	}
	return 0, false
}
