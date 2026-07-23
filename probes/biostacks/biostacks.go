// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package biostacks profiles block request queue, service, and full latency.
package biostacks // import "go.opentelemetry.io/ebpf-profiler/probes/biostacks"

import (
	"errors"
	"fmt"
	"os"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/internal/linux"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/probes/internal/probeutil"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	// SampleType is retained as the queue-latency profile name.
	SampleType = "block_io_queue_latency"
	// ServiceSampleType measures request issue through final completion.
	ServiceSampleType = "block_io_service_latency"
	// FullSampleType measures bio submission through final request completion.
	FullSampleType = "block_io_latency"

	bioStartsMapName    = "block_io_bio_starts"
	requestsMapName     = "block_io_requests"
	submitProgramName   = "block_io_submit_bio"
	insertProgramName   = "block_io_insert"
	issueProgramName    = "block_io_issue"
	completeProgramName = "block_io_complete"

	originVariableName             = "block_io_origin"
	modeVariableName               = "block_io_mode"
	oldRQArgsVariableName          = "block_io_old_rq_args"
	minNSVariableName              = "block_io_min_ns"
	sampleVariableName             = "block_io_sample_threshold"
	hasBTFVariableName             = "block_io_has_btf_layout"
	hasDirectDiskVariableName      = "block_io_has_direct_disk"
	requestBioOffsetVariableName   = "block_io_request_bio_offset"
	requestFlagsOffsetVariableName = "block_io_request_flags_offset"
	requestBytesOffsetVariableName = "block_io_request_bytes_offset"
	requestQueueOffsetVariableName = "block_io_request_queue_offset"
	requestDiskOffsetVariableName  = "block_io_request_disk_offset"
	queueDiskOffsetVariableName    = "block_io_queue_disk_offset"
	diskMajorOffsetVariableName    = "block_io_disk_major_offset"
	diskMinorOffsetVariableName    = "block_io_disk_minor_offset"
	bioFlagsOffsetVariableName     = "block_io_bio_flags_offset"

	insertTracepointName   = "block_rq_insert"
	issueTracepointName    = "block_rq_issue"
	completeTracepointName = "block_rq_complete"
	submitBioSymbol        = "submit_bio_noacct"
	defaultMaxEntries      = uint32(4 * 1024)
	maximumMaxEntries      = uint32(1024 * 1024)
)

type mode uint8

const (
	queueMode mode = iota + 1
	serviceMode
	fullMode
)

type blockIOProbe struct {
	sampleType      string
	mode            mode
	minDuration     time.Duration
	sampleThreshold uint32
	maxEntries      uint32
}

// New creates a queue-latency probe for backwards compatibility.
func New(rawConfig any) (tracer.Probe, error) {
	return NewForSampleType(SampleType, rawConfig)
}

// NewForSampleType creates one block lifecycle latency probe.
func NewForSampleType(sampleType string, rawConfig any) (tracer.Probe, error) {
	profileMode, err := modeForSampleType(sampleType)
	if err != nil {
		return nil, err
	}
	cfg, err := probeutil.ParseLatencyConfig(
		rawConfig, "block I/O", defaultMaxEntries, maximumMaxEntries)
	if err != nil {
		return nil, err
	}
	return &blockIOProbe{
		sampleType:      sampleType,
		mode:            profileMode,
		minDuration:     cfg.MinDuration,
		sampleThreshold: cfg.SampleThreshold,
		maxEntries:      cfg.MaxEntries,
	}, nil
}

func modeForSampleType(sampleType string) (mode, error) {
	switch sampleType {
	case SampleType:
		return queueMode, nil
	case ServiceSampleType:
		return serviceMode, nil
	case FullSampleType:
		return fullMode, nil
	default:
		return 0, fmt.Errorf("unsupported block I/O sample type %q", sampleType)
	}
}

func (p *blockIOProbe) ReportMetadata() *samples.TypeMetadata {
	return &samples.TypeMetadata{
		SampleType:   p.sampleType,
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	}
}

func (p *blockIOProbe) Load(origin uint16, ctx *tracer.ProbeContext) (link.Link, error) {
	layout, err := discoverBlockLayout()
	if err != nil {
		return nil, err
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust memlock rlimit: %w", err)
	}
	defer restoreRlimit()

	mapNames := []string{bioStartsMapName, requestsMapName}
	programNames := []string{
		submitProgramName, insertProgramName, issueProgramName, completeProgramName,
	}
	variableNames := []string{
		originVariableName, modeVariableName, oldRQArgsVariableName,
		minNSVariableName, sampleVariableName, hasBTFVariableName,
		hasDirectDiskVariableName, requestBioOffsetVariableName,
		requestFlagsOffsetVariableName, requestBytesOffsetVariableName,
		requestQueueOffsetVariableName, requestDiskOffsetVariableName,
		queueDiskOffsetVariableName, diskMajorOffsetVariableName,
		diskMinorOffsetVariableName, bioFlagsOffsetVariableName,
	}
	collection, err := ctx.CollectionSpecWith(mapNames, programNames, variableNames)
	if err != nil {
		return nil, err
	}
	collection.Maps[bioStartsMapName].MaxEntries = p.maxEntries
	collection.Maps[requestsMapName].MaxEntries = p.maxEntries

	variables := map[string]any{
		originVariableName:             origin,
		modeVariableName:               uint8(p.mode),
		oldRQArgsVariableName:          layout.oldRQArgs,
		minNSVariableName:              uint64(p.minDuration),
		sampleVariableName:             p.sampleThreshold,
		hasBTFVariableName:             layout.hasBTF,
		hasDirectDiskVariableName:      layout.hasDirectDisk,
		requestBioOffsetVariableName:   layout.requestBioOffset,
		requestFlagsOffsetVariableName: layout.requestFlagsOffset,
		requestBytesOffsetVariableName: layout.requestBytesOffset,
		requestQueueOffsetVariableName: layout.requestQueueOffset,
		requestDiskOffsetVariableName:  layout.requestDiskOffset,
		queueDiskOffsetVariableName:    layout.queueDiskOffset,
		diskMajorOffsetVariableName:    layout.diskMajorOffset,
		diskMinorOffsetVariableName:    layout.diskMinorOffset,
		bioFlagsOffsetVariableName:     layout.bioFlagsOffset,
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
		return nil, fmt.Errorf("failed to rewrite block I/O maps: %w", err)
	}

	programs := make(map[string]*cebpf.Program, len(programNames))
	if err := ctx.LoadProbeUnwinders(
		collection,
		programs,
		[]tracer.ProgLoaderHelper{
			{Name: submitProgramName, NoTailCallTarget: true, Enable: true},
			{Name: insertProgramName, NoTailCallTarget: true, Enable: true},
			{Name: issueProgramName, NoTailCallTarget: true, Enable: true},
			{Name: completeProgramName, NoTailCallTarget: true, Enable: true},
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

	completeLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: completeTracepointName, Program: programs[completeProgramName],
	})
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach %s raw tracepoint: %w", completeTracepointName, err)
	}
	resources.Add(completeLink)

	issueLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: issueTracepointName, Program: programs[issueProgramName],
	})
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach %s raw tracepoint: %w", issueTracepointName, err)
	}
	resources.Add(issueLink)

	insertLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: insertTracepointName, Program: programs[insertProgramName],
	})
	if err != nil {
		_ = resources.Close()
		return nil, fmt.Errorf("failed to attach %s raw tracepoint: %w", insertTracepointName, err)
	}

	if layout.hasBTF {
		submitLink, attachErr := link.Kprobe(submitBioSymbol, programs[submitProgramName], nil)
		if attachErr == nil {
			resources.Add(insertLink)
			return resources.WrapLink(submitLink), nil
		}
		log.Warnf("Unable to attach block I/O full-stack hook %s; using kernel-stack fallback: %v",
			submitBioSymbol, attachErr)
	}
	return resources.WrapLink(insertLink), nil
}

type blockLayout struct {
	oldRQArgs          bool
	hasBTF             bool
	hasDirectDisk      bool
	requestBioOffset   uint32
	requestFlagsOffset uint32
	requestBytesOffset uint32
	requestQueueOffset uint32
	requestDiskOffset  uint32
	queueDiskOffset    uint32
	diskMajorOffset    uint32
	diskMinorOffset    uint32
	bioFlagsOffset     uint32
}

func discoverBlockLayout() (*blockLayout, error) {
	major, minor, _, err := linux.GetCurrentKernelVersion()
	if err != nil {
		return nil, fmt.Errorf("determine block tracepoint argument layout: %w", err)
	}
	layout := &blockLayout{oldRQArgs: major < 5 || (major == 5 && minor < 11)}

	file, err := os.Open("/sys/kernel/btf/vmlinux")
	if err != nil {
		log.Warnf("Kernel BTF unavailable; block profiles will use kernel-stack fallback: %v", err)
		return layout, nil
	}
	defer file.Close()
	spec, err := btf.LoadSplitSpecFromReader(file, nil)
	if err != nil {
		log.Warnf("Unable to parse kernel BTF; block profiles will use kernel-stack fallback: %v", err)
		return layout, nil
	}
	if err := populateBlockBTFLayout(spec, layout); err != nil {
		log.Warnf("Incomplete block BTF layout; block profiles will use kernel-stack fallback: %v", err)
		return layout, nil
	}
	layout.hasBTF = true
	return layout, nil
}

func populateBlockBTFLayout(spec *btf.Spec, layout *blockLayout) error {
	var request, bio, disk *btf.Struct
	if err := spec.TypeByName("request", &request); err != nil {
		return err
	}
	if err := spec.TypeByName("bio", &bio); err != nil {
		return err
	}
	if err := spec.TypeByName("gendisk", &disk); err != nil {
		return err
	}

	var err error
	if layout.requestBioOffset, _, err = btfMember(request, "bio"); err != nil {
		return err
	}
	if layout.requestFlagsOffset, _, err = btfMember(request, "cmd_flags"); err != nil {
		return err
	}
	if layout.requestBytesOffset, _, err = btfMember(request, "__data_len"); err != nil {
		return err
	}
	if layout.requestQueueOffset, _, err = btfMember(request, "q"); err != nil {
		return err
	}
	if layout.bioFlagsOffset, _, err = btfMember(bio, "bi_opf"); err != nil {
		return err
	}
	if layout.diskMajorOffset, _, err = btfMember(disk, "major"); err != nil {
		return err
	}
	if layout.diskMinorOffset, _, err = btfMember(disk, "first_minor"); err != nil {
		return err
	}

	if offset, _, directErr := btfMember(request, "rq_disk"); directErr == nil {
		layout.hasDirectDisk = true
		layout.requestDiskOffset = offset
		return nil
	}

	_, queueType, err := btfMember(request, "q")
	if err != nil {
		return err
	}
	queue, err := pointedStruct(queueType)
	if err != nil {
		return err
	}
	layout.queueDiskOffset, _, err = btfMember(queue, "disk")
	return err
}

func btfMember(structure *btf.Struct, name string) (uint32, btf.Type, error) {
	for _, member := range structure.Members {
		if member.Name == name {
			return uint32(member.Offset.Bytes()), member.Type, nil
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
		offset, typ, err := btfMember(anonymous, name)
		if err == nil {
			return uint32(member.Offset.Bytes()) + offset, typ, nil
		}
	}
	return 0, nil, fmt.Errorf("BTF struct %s has no member %q", structure.Name, name)
}

func pointedStruct(typ btf.Type) (*btf.Struct, error) {
	pointer, ok := btf.UnderlyingType(typ).(*btf.Pointer)
	if !ok {
		return nil, errors.New("BTF member is not a pointer")
	}
	structure, ok := btf.UnderlyingType(pointer.Target).(*btf.Struct)
	if !ok {
		return nil, errors.New("BTF pointer does not target a struct")
	}
	return structure, nil
}
