// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package iouring profiles io_uring submission-to-CQE latency.
package iouring // import "go.opentelemetry.io/ebpf-profiler/probes/iouring"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/probes/internal/probeutil"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	// SampleType is the profile sample type emitted by this probe.
	SampleType = "io_uring_latency"

	requestsMapName       = "io_uring_requests"
	correlationsMapName   = "io_uring_correlations"
	requestAliasesMapName = "io_uring_request_aliases"
	submitProgramName     = "io_uring_submit"
	issueProgramName      = "io_uring_issue"
	completeProgramName   = "io_uring_complete"

	originVariableName                 = "io_uring_origin"
	minNSVariableName                  = "io_uring_min_ns"
	sampleVariableName                 = "io_uring_sample_threshold"
	submitHasReqVariableName           = "io_uring_submit_has_req"
	submitCtxOffsetVariableName        = "io_uring_submit_ctx_offset"
	submitReqOffsetVariableName        = "io_uring_submit_req_offset"
	submitUserDataOffsetVariableName   = "io_uring_submit_user_data_offset"
	submitOpcodeOffsetVariableName     = "io_uring_submit_opcode_offset"
	submitSQThreadOffsetVariableName   = "io_uring_submit_sq_thread_offset"
	completeHasReqVariableName         = "io_uring_complete_has_req"
	completeHasFlagsVariableName       = "io_uring_complete_has_flags"
	completeCtxOffsetVariableName      = "io_uring_complete_ctx_offset"
	completeReqOffsetVariableName      = "io_uring_complete_req_offset"
	completeUserDataOffsetVariableName = "io_uring_complete_user_data_offset"
	completeResultOffsetVariableName   = "io_uring_complete_result_offset"
	completeResultSizeVariableName     = "io_uring_complete_result_size"
	completeFlagsOffsetVariableName    = "io_uring_complete_flags_offset"
	tracepointGroup                    = "io_uring"
	completeTracepointName             = "io_uring_complete"
	issueSymbol                        = "io_issue_sqe"
	defaultMaxEntries                  = uint32(16 * 1024)
	maximumMaxEntries                  = uint32(1024 * 1024)
)

var tracefsEventRoots = []string{
	"/sys/kernel/tracing/events",
	"/sys/kernel/debug/tracing/events",
}

type probe struct {
	minDuration     time.Duration
	sampleThreshold uint32
	maxEntries      uint32
}

// New creates an io_uring latency probe. Supported fields are min_duration (a
// Go duration string), sample_rate in (0, 1], and max_entries.
func New(rawConfig any) (tracer.Probe, error) {
	cfg, err := probeutil.ParseLatencyConfig(
		rawConfig, "io_uring latency", defaultMaxEntries, maximumMaxEntries)
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
		SampleType:   SampleType,
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	}
}

func (p *probe) Load(origin uint16, ctx *tracer.ProbeContext) (link.Link, error) {
	layout, err := discoverLayout(tracefsEventRoots)
	if err != nil {
		return nil, err
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust memlock rlimit: %w", err)
	}
	defer restoreRlimit()

	mapNames := []string{requestsMapName, correlationsMapName, requestAliasesMapName}
	programNames := []string{submitProgramName, issueProgramName, completeProgramName}
	variableNames := []string{
		originVariableName,
		minNSVariableName,
		sampleVariableName,
		submitHasReqVariableName,
		submitCtxOffsetVariableName,
		submitReqOffsetVariableName,
		submitUserDataOffsetVariableName,
		submitOpcodeOffsetVariableName,
		submitSQThreadOffsetVariableName,
		completeHasReqVariableName,
		completeHasFlagsVariableName,
		completeCtxOffsetVariableName,
		completeReqOffsetVariableName,
		completeUserDataOffsetVariableName,
		completeResultOffsetVariableName,
		completeResultSizeVariableName,
		completeFlagsOffsetVariableName,
	}
	collection, err := ctx.CollectionSpecWith(mapNames, programNames, variableNames)
	if err != nil {
		return nil, err
	}
	collection.Maps[requestsMapName].MaxEntries = p.maxEntries
	collection.Maps[correlationsMapName].MaxEntries = p.maxEntries
	collection.Maps[requestAliasesMapName].MaxEntries = p.maxEntries

	variables := map[string]any{
		originVariableName:                 origin,
		minNSVariableName:                  uint64(p.minDuration),
		sampleVariableName:                 p.sampleThreshold,
		submitHasReqVariableName:           layout.submitHasReq,
		submitCtxOffsetVariableName:        layout.submit.fields["ctx"].offset,
		submitReqOffsetVariableName:        layout.submit.fields["req"].offset,
		submitUserDataOffsetVariableName:   layout.submit.fields["user_data"].offset,
		submitOpcodeOffsetVariableName:     layout.submit.fields["opcode"].offset,
		submitSQThreadOffsetVariableName:   layout.submit.fields["sq_thread"].offset,
		completeHasReqVariableName:         layout.completeHasReq,
		completeHasFlagsVariableName:       layout.completeHasFlags,
		completeCtxOffsetVariableName:      layout.complete.fields["ctx"].offset,
		completeReqOffsetVariableName:      layout.complete.fields["req"].offset,
		completeUserDataOffsetVariableName: layout.complete.fields["user_data"].offset,
		completeResultOffsetVariableName:   layout.complete.fields["res"].offset,
		completeResultSizeVariableName:     layout.complete.fields["res"].size,
		completeFlagsOffsetVariableName:    layout.complete.fields["cflags"].offset,
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
		return nil, fmt.Errorf("failed to rewrite io_uring maps: %w", err)
	}

	programs := make(map[string]*cebpf.Program, len(programNames))
	if err := ctx.LoadProbeUnwinders(
		collection,
		programs,
		[]tracer.ProgLoaderHelper{
			{Name: submitProgramName, NoTailCallTarget: true, Enable: true},
			{Name: issueProgramName, NoTailCallTarget: true, Enable: true},
			{Name: completeProgramName, NoTailCallTarget: true, Enable: true},
		},
		0,
	); err != nil {
		for _, program := range programs {
			resources.Add(program)
		}
		_ = resources.Close()
		return nil, fmt.Errorf("failed to load io_uring programs: %w", err)
	}
	for _, program := range programs {
		resources.Add(program)
	}

	// Attach completion before starts so activation cannot leave requests that
	// have no completion consumer. Reverse resource closure disables starts first.
	completeLink, err := link.Tracepoint(
		tracepointGroup, completeTracepointName, programs[completeProgramName], nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach %s tracepoint: %w", completeTracepointName, err)
	}
	resources.Add(completeLink)

	// io_issue_sqe gives the existing profiler unwinder a pt_regs context. Some
	// kernels inline or hide this symbol; the submission tracepoint still emits
	// a correctly attributed kernel-stack fallback in that case.
	issueLink, issueErr := link.Kprobe(issueSymbol, programs[issueProgramName], nil)
	if issueErr != nil {
		log.Warnf("Unable to attach io_uring full-stack hook %s; using kernel-stack fallback: %v",
			issueSymbol, issueErr)
	} else {
		resources.Add(issueLink)
	}

	submitLink, err := link.Tracepoint(
		tracepointGroup, layout.submit.name, programs[submitProgramName], nil)
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach %s tracepoint: %w", layout.submit.name, err)
	}
	return resources.WrapLink(submitLink), nil
}

type tracepointField struct {
	offset uint32
	size   uint32
}

type tracepointLayout struct {
	name   string
	fields map[string]tracepointField
}

type ioUringLayout struct {
	submit           tracepointLayout
	complete         tracepointLayout
	submitHasReq     bool
	completeHasReq   bool
	completeHasFlags bool
}

func discoverLayout(roots []string) (*ioUringLayout, error) {
	var submit tracepointLayout
	var submitErrs []error
	for _, name := range []string{"io_uring_submit_req", "io_uring_submit_sqe"} {
		layout, err := readTracepointLayout(roots, tracepointGroup, name)
		if err == nil {
			submit = layout
			break
		}
		submitErrs = append(submitErrs, err)
	}
	if submit.name == "" {
		return nil, fmt.Errorf("no supported io_uring submission tracepoint: %w", errors.Join(submitErrs...))
	}
	complete, err := readTracepointLayout(
		roots, tracepointGroup, completeTracepointName)
	if err != nil {
		return nil, fmt.Errorf("io_uring completion tracepoint is unavailable: %w", err)
	}

	if err := requireFields(submit, map[string]uint32{
		"ctx": 8, "user_data": 8, "opcode": 1, "sq_thread": 1,
	}); err != nil {
		return nil, err
	}
	if err := requireFields(complete, map[string]uint32{
		"ctx": 8, "user_data": 8,
	}); err != nil {
		return nil, err
	}
	result, ok := complete.fields["res"]
	if !ok || (result.size != 4 && result.size != 8) {
		return nil, fmt.Errorf("tracepoint %s field %q must be 4 or 8 bytes",
			complete.name, "res")
	}
	return &ioUringLayout{
		submit:           submit,
		complete:         complete,
		submitHasReq:     hasSizedField(submit, "req", 8),
		completeHasReq:   hasSizedField(complete, "req", 8),
		completeHasFlags: hasSizedField(complete, "cflags", 4),
	}, nil
}

func readTracepointLayout(roots []string, group, name string) (tracepointLayout, error) {
	var errs []error
	for _, root := range roots {
		path := filepath.Join(root, group, name, "format")
		contents, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		fields, err := parseTracepointFormat(string(contents))
		if err != nil {
			return tracepointLayout{}, fmt.Errorf("parsing %s: %w", path, err)
		}
		return tracepointLayout{name: name, fields: fields}, nil
	}
	return tracepointLayout{}, fmt.Errorf("reading %s/%s format: %w", group, name, errors.Join(errs...))
}

func parseTracepointFormat(contents string) (map[string]tracepointField, error) {
	fields := make(map[string]tracepointField)
	for _, line := range strings.Split(contents, "\n") {
		parts := strings.Split(line, ";")
		if len(parts) < 3 {
			continue
		}
		declaration := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(declaration, "field:") {
			continue
		}
		declarationParts := strings.Fields(strings.TrimPrefix(declaration, "field:"))
		if len(declarationParts) == 0 {
			continue
		}
		name := strings.TrimLeft(declarationParts[len(declarationParts)-1], "*")
		if bracket := strings.IndexByte(name, '['); bracket >= 0 {
			name = name[:bracket]
		}
		var field tracepointField
		for _, part := range parts[1:] {
			keyValue := strings.SplitN(strings.TrimSpace(part), ":", 2)
			if len(keyValue) != 2 {
				continue
			}
			value, err := strconv.ParseUint(strings.TrimSpace(keyValue[1]), 10, 32)
			if err != nil {
				continue
			}
			switch keyValue[0] {
			case "offset":
				field.offset = uint32(value)
			case "size":
				field.size = uint32(value)
			}
		}
		if name != "" && field.size != 0 {
			fields[name] = field
		}
	}
	if len(fields) == 0 {
		return nil, errors.New("format contains no fields")
	}
	return fields, nil
}

func hasSizedField(layout tracepointLayout, name string, size uint32) bool {
	field, ok := layout.fields[name]
	return ok && field.size == size
}

func requireFields(layout tracepointLayout, required map[string]uint32) error {
	for name, expectedSize := range required {
		field, ok := layout.fields[name]
		if !ok {
			return fmt.Errorf("tracepoint %s has no %q field", layout.name, name)
		}
		if field.size != expectedSize {
			return fmt.Errorf(
				"tracepoint %s field %q has size %d, expected %d",
				layout.name, name, field.size, expectedSize)
		}
		if field.offset > 4096 {
			return fmt.Errorf("tracepoint %s field %q has invalid offset %d",
				layout.name, name, field.offset)
		}
	}
	return nil
}
