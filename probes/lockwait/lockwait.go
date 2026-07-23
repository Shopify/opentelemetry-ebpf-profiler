// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package lockwait // import "go.opentelemetry.io/ebpf-profiler/probes/lockwait"

import (
	"errors"
	"fmt"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/probes/internal/probeutil"
	"go.opentelemetry.io/ebpf-profiler/probes/usertarget"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	startsMapName      = "lock_wait_starts"
	metricsMapName     = "lock_wait_metrics"
	entryProgramName   = "lock_wait_entry"
	exitProgramName    = "lock_wait_exit"
	originVariableName = "lock_wait_origin"
	minNSVariableName  = "lock_wait_min_ns"
	sampleVariableName = "lock_wait_sample_threshold"
	returnModeName     = "lock_wait_return_mode"
	successCountName   = "lock_wait_success_count"
	defaultMaxEntries  = uint32(16 * 1024)
	maximumMaxEntries  = uint32(64 * 1024)
	defaultSampleType  = "lock_wait_latency"
	minimumTargetLinks = uint32(2)
)

var successValueNames = [...]string{
	"lock_wait_success_0",
	"lock_wait_success_1",
	"lock_wait_success_2",
	"lock_wait_success_3",
}

type lockWaitProbe struct {
	definition      Definition
	minDuration     time.Duration
	sampleThreshold uint32
	maxEntries      uint32
}

// New creates a generic lock-wait probe from a runtime descriptor. Config
// supports min_duration, sample_rate, and max_entries.
func New(definition Definition, rawConfig any) (tracer.Probe, error) {
	if definition.SampleType == "" {
		definition.SampleType = defaultSampleType
	}
	if err := validateSampleType(definition.SampleType); err != nil {
		return nil, err
	}
	if err := definition.Labels.validate(); err != nil {
		return nil, err
	}
	abi, err := definition.ABI.validated()
	if err != nil {
		return nil, err
	}
	// pid_tgid state has no attach cookie. Permit symbol aliases as fallbacks,
	// but fail safe if more than one distinct point resolves in one object.
	definition.Target.MaxResolvedPoints = 1
	target, err := definition.Target.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid lock-wait target: %w", err)
	}
	// Every resolved point needs one entry and one return link. A smaller
	// target bound can never attach and would otherwise fail silently at runtime.
	if target.MaxLinks < minimumTargetLinks {
		return nil, fmt.Errorf("invalid lock-wait target: max_links must be at least %d",
			minimumTargetLinks)
	}
	cfg, err := probeutil.ParseLatencyConfig(
		rawConfig, "lock wait", defaultMaxEntries, maximumMaxEntries)
	if err != nil {
		return nil, err
	}
	definition.Target = target
	definition.ABI = abi
	return &lockWaitProbe{
		definition:      definition,
		minDuration:     cfg.MinDuration,
		sampleThreshold: cfg.SampleThreshold,
		maxEntries:      cfg.MaxEntries,
	}, nil
}

func (probe *lockWaitProbe) ReportMetadata() *samples.TypeMetadata {
	return &samples.TypeMetadata{
		SampleType:   probe.definition.SampleType,
		SampleUnit:   "nanoseconds",
		ReportValues: true,
		StaticLabels: probe.definition.Labels.profileLabels(),
	}
}

func failLoad(resources *probeutil.Resources, err error) (link.Link, error) {
	return nil, errors.Join(err, resources.Close())
}

func (probe *lockWaitProbe) Load(origin uint16, ctx *tracer.ProbeContext) (link.Link, error) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust memlock rlimit: %w", err)
	}
	defer restoreRlimit()

	variableNames := []string{
		originVariableName, minNSVariableName, sampleVariableName, returnModeName,
		successCountName,
	}
	variableNames = append(variableNames, successValueNames[:]...)
	collection, err := ctx.CollectionSpecWith(
		[]string{startsMapName, metricsMapName},
		[]string{entryProgramName, exitProgramName},
		variableNames,
	)
	if err != nil {
		return nil, err
	}
	collection.Maps[startsMapName].MaxEntries = probe.maxEntries

	variables := map[string]any{
		originVariableName: origin,
		minNSVariableName:  uint64(probe.minDuration),
		sampleVariableName: probe.sampleThreshold,
		returnModeName:     uint32(probe.definition.ABI.ReturnValueMode),
		successCountName:   uint32(len(probe.definition.ABI.SuccessfulReturnValues)),
	}
	for index, name := range successValueNames {
		var value int64
		if index < len(probe.definition.ABI.SuccessfulReturnValues) {
			value = probe.definition.ABI.SuccessfulReturnValues[index]
		}
		variables[name] = value
	}
	for name, value := range variables {
		if err := collection.Variables[name].Set(value); err != nil {
			return nil, fmt.Errorf("failed to set eBPF variable %q: %w", name, err)
		}
	}

	resources := &probeutil.Resources{}
	ownedMaps, err := probeutil.LoadMaps(
		collection, []string{startsMapName, metricsMapName}, resources)
	if err != nil {
		return failLoad(resources, err)
	}
	if err := ctx.RewriteMaps(collection, ownedMaps); err != nil {
		return failLoad(resources, fmt.Errorf("failed to rewrite lock-wait maps: %w", err))
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
		return failLoad(resources, fmt.Errorf("failed to load lock-wait programs: %w", err))
	}
	for _, program := range programs {
		resources.Add(program)
	}

	collector, err := newLockWaitMetricsCollector(
		ownedMaps[metricsMapName], ownedMaps[startsMapName])
	if err != nil {
		return failLoad(resources, err)
	}
	subscription, err := ctx.RegisterMetricsCollector(collector.Collect)
	if err != nil {
		return failLoad(resources, fmt.Errorf("register lock-wait metrics: %w", err))
	}
	resources.Add(&finalMetricsCloser{Closer: subscription, collect: collector.Collect})

	manager, err := usertarget.New(
		probe.definition.Target,
		usertarget.Programs{
			Entry:  programs[entryProgramName],
			Return: programs[exitProgramName],
		},
		usertarget.Options{ResetProcess: collector.ResetProcess},
	)
	if err != nil {
		return failLoad(resources, err)
	}
	managerLink, err := manager.Start(ctx)
	if err != nil {
		return failLoad(resources, fmt.Errorf("start lock-wait target: %w", err))
	}
	return resources.WrapLink(managerLink), nil
}
