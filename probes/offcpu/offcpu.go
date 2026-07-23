// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package offcpu profiles how long stacks spend off CPU.
//
// It measures the wall-clock nanoseconds between a thread being switched out
// and being switched back in, and attributes that duration to the blocked
// stack. This is the classic offcputime semantics: the value answers "how
// long was this stack waiting" rather than "how often did this stack leave
// the CPU".
package offcpu // import "go.opentelemetry.io/ebpf-profiler/probes/offcpu"

import (
	"bufio"
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
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/probes/internal/probeutil"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// SampleType identifies off-CPU time samples. It is fixed rather than
// descriptor-supplied so downstream duration classification cannot drift.
const SampleType = "off_cpu_time"

const (
	startsMapName        = "off_cpu_time_starts"
	metricsMapName       = "off_cpu_time_metrics"
	switchOutProgramName = "off_cpu_time_switch_out"
	switchInProgramName  = "off_cpu_time_switch_in"
	originVariableName   = "off_cpu_time_origin"
	minNSVariableName    = "off_cpu_time_min_ns"
	sampleVariableName   = "off_cpu_time_sample_threshold"
	stateEnabledVariable = "off_cpu_time_state_enabled"

	// The profiler supports only 64-bit x86_64/aarch64 kernels. Both expose
	// prev_state at byte 32 as an 8-byte signed long in sched_switch; this
	// layout is validated against tracefs before direct context access is enabled.
	expectedStateOffset = uint32(32)
	expectedStateSize   = uint32(8)

	// stateUnavailable is the sentinel the eBPF side reports when no thread
	// state was captured for a sample. Must match OFF_CPU_TIME_STATE_UNAVAILABLE.
	stateUnavailable = ^uint64(0)

	// threadStateLabelKey is the per-sample label carrying the switch-out
	// thread state. It separates voluntary blocking (interruptible,
	// uninterruptible, ...) from runnable threads descheduled by CPU
	// pressure (running, preempted) so profiles can be filtered on either.
	threadStateLabelKey = "thread.state"

	// switchOutTracepointGroup/Name identify the tracepoint that observes
	// threads leaving the CPU. It fires in the outgoing thread's context.
	switchOutTracepointGroup = "sched"
	switchOutTracepointName  = "sched_switch"

	// switchInSymbolPrefix is the kernel function that runs in the incoming
	// thread's context right after a context switch. Compilers emit optimized
	// variants (for example finish_task_switch.isra.0), so attachment resolves
	// the symbol by prefix from kallsyms, mirroring the built-in off-CPU hook.
	switchInSymbolPrefix = "finish_task_switch"

	// The pending set is one entry per sleeping thread system-wide, so the
	// default is larger than the per-function latency probes.
	defaultMaxEntries = uint32(64 * 1024)
	maximumMaxEntries = uint32(1024 * 1024)
)

// kallsymsPath is a variable to allow tests to substitute a fixture.
var kallsymsPath = "/proc/kallsyms"

// tracefsRoots lists the mount points searched for tracepoint format files.
// A variable to allow tests to substitute fixtures.
var tracefsRoots = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

type offCPUTimeProbe struct {
	minDuration     time.Duration
	sampleThreshold uint32
	maxEntries      uint32
}

// New creates an off-CPU time probe from collector configuration. Supported
// fields are min_duration (a Go duration string), sample_rate in (0, 1], and
// max_entries.
//
// min_duration is the primary overhead and volume control: durations are
// always measured exactly, and only wakeups whose measured off-CPU time
// reaches the threshold are unwound and reported. sample_rate applies to
// qualifying wakeups, not to switch-outs, so long waits are never lost to
// sampling.
func New(rawConfig any) (tracer.Probe, error) {
	cfg, err := probeutil.ParseLatencyConfig(
		rawConfig, "off-cpu time", defaultMaxEntries, maximumMaxEntries)
	if err != nil {
		return nil, err
	}

	return &offCPUTimeProbe{
		minDuration:     cfg.MinDuration,
		sampleThreshold: cfg.SampleThreshold,
		maxEntries:      cfg.MaxEntries,
	}, nil
}

func (p *offCPUTimeProbe) ReportMetadata() *samples.TypeMetadata {
	return &samples.TypeMetadata{
		SampleType:   SampleType,
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	}
}

func failLoad(resources *probeutil.Resources, err error) (link.Link, error) {
	return nil, errors.Join(err, resources.Close())
}

func (p *offCPUTimeProbe) Load(origin uint16, ctx *tracer.ProbeContext) (link.Link, error) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust memlock rlimit: %w", err)
	}
	defer restoreRlimit()

	collection, err := ctx.CollectionSpecWith(
		[]string{startsMapName, metricsMapName},
		[]string{switchOutProgramName, switchInProgramName},
		[]string{
			originVariableName, minNSVariableName, sampleVariableName,
			stateEnabledVariable,
		},
	)
	if err != nil {
		return nil, err
	}
	collection.Maps[startsMapName].MaxEntries = p.maxEntries

	// The tracepoint encoding of prev_state is not a stable ABI, so the field
	// location is resolved from the tracefs format file rather than assumed.
	// Failure only disables the thread.state label; durations are unaffected.
	stateEnabled := uint32(0)
	stateOffset, stateSize, stateErr := resolveSchedSwitchStateField()
	if stateErr != nil {
		log.Infof("Off-CPU time probe continues without thread state: %v", stateErr)
	} else if stateOffset != expectedStateOffset || stateSize != expectedStateSize {
		log.Infof(
			"Off-CPU time probe continues without thread state: unexpected sched_switch "+
				"prev_state layout offset=%d size=%d (expected offset=%d size=%d)",
			stateOffset, stateSize, expectedStateOffset, expectedStateSize)
	} else {
		stateEnabled = 1
		log.Infof("Off-CPU time thread-state capture enabled: prev_state offset=%d size=%d",
			stateOffset, stateSize)
	}

	variables := map[string]any{
		originVariableName:   origin,
		minNSVariableName:    uint64(p.minDuration),
		sampleVariableName:   p.sampleThreshold,
		stateEnabledVariable: stateEnabled,
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
		return failLoad(resources, fmt.Errorf("failed to rewrite off-cpu time maps: %w", err))
	}

	programs := make(map[string]*cebpf.Program, 2)
	if err := ctx.LoadProbeUnwinders(
		collection,
		programs,
		[]tracer.ProgLoaderHelper{
			{Name: switchOutProgramName, NoTailCallTarget: true, Enable: true},
			{Name: switchInProgramName, NoTailCallTarget: true, Enable: true},
		},
		0,
	); err != nil {
		for _, program := range programs {
			resources.Add(program)
		}
		return failLoad(resources, fmt.Errorf("failed to load off-cpu time programs: %w", err))
	}
	for _, program := range programs {
		resources.Add(program)
	}

	collector, err := newOffCPUTimeMetricsCollector(ownedMaps[metricsMapName])
	if err != nil {
		return failLoad(resources, err)
	}
	subscription, err := ctx.RegisterMetricsCollector(collector.Collect)
	if err != nil {
		return failLoad(resources, fmt.Errorf("register off-cpu time metrics: %w", err))
	}
	resources.Add(&finalMetricsCloser{Closer: subscription, collect: collector.Collect})

	// Attach the consumer (switch-in) before the producer so activation can't
	// leave unconsumable start records, mirroring the other latency probes.
	if err := attachSwitchIn(programs[switchInProgramName], resources); err != nil {
		return failLoad(resources, err)
	}

	switchOutLink, err := link.Tracepoint(
		switchOutTracepointGroup, switchOutTracepointName,
		programs[switchOutProgramName], nil)
	if err != nil {
		return failLoad(resources, fmt.Errorf("failed to attach %s/%s tracepoint: %w",
			switchOutTracepointGroup, switchOutTracepointName, err))
	}
	return resources.WrapLink(switchOutLink), nil
}

// attachSwitchIn attaches the switch-in program to every finish_task_switch
// variant present in kallsyms. At least one attachment must succeed.
func attachSwitchIn(program *cebpf.Program, resources *probeutil.Resources) error {
	symbols, err := resolveSwitchInSymbols()
	if err != nil || len(symbols) == 0 {
		// kallsyms may be unreadable in restricted environments; fall back to
		// the plain symbol and let the kernel resolve it.
		if err != nil {
			log.Debugf("Failed to resolve %s from kallsyms: %v", switchInSymbolPrefix, err)
		}
		symbols = []string{switchInSymbolPrefix}
	}

	var errs []error
	attached := 0
	for _, symbol := range symbols {
		switchInLink, linkErr := link.Kprobe(symbol, program, nil)
		if linkErr != nil {
			errs = append(errs, fmt.Errorf("attach kprobe %q: %w", symbol, linkErr))
			continue
		}
		resources.Add(switchInLink)
		attached++
	}
	if attached == 0 {
		return fmt.Errorf("failed to attach to any of %d %s symbols: %w",
			len(symbols), switchInSymbolPrefix, errors.Join(errs...))
	}
	return nil
}

// LabelTrace implements tracer.TraceLabeler. It converts the switch-out
// thread state carried in the trace's user-data slot into the low-cardinality
// thread.state sample label, merging with any runtime labels already present.
func (p *offCPUTimeProbe) LabelTrace(trace *libpf.EbpfTrace) {
	if trace.AsyncUserData == stateUnavailable {
		return
	}
	if trace.CustomLabels == nil {
		trace.CustomLabels = make(map[libpf.String]libpf.String, 1)
	}
	trace.CustomLabels[libpf.Intern(threadStateLabelKey)] =
		libpf.Intern(threadStateName(trace.AsyncUserData))
}

// threadStateName decodes the sched_switch tracepoint prev_state encoding
// used since kernel 4.14: 0 for a still-runnable thread that entered the
// scheduler voluntarily, single TASK_REPORT bits decoded from
// task_state_index, and TASK_REPORT_MAX (0x100) for involuntary preemption.
// Unrecognized encodings collapse to "other" to bound label cardinality.
func threadStateName(state uint64) string {
	switch state {
	case 0x0000:
		return "running"
	case 0x0001:
		return "interruptible"
	case 0x0002:
		return "uninterruptible"
	case 0x0004:
		return "stopped"
	case 0x0008:
		return "traced"
	case 0x0010:
		return "exit_dead"
	case 0x0020:
		return "zombie"
	case 0x0040:
		return "parked"
	case 0x0080:
		return "idle"
	case 0x0100:
		return "preempted"
	default:
		return "other"
	}
}

// resolveSchedSwitchStateField locates the prev_state field in the raw
// sched_switch tracepoint buffer by parsing the tracefs format file, e.g.:
//
//	field:long prev_state;	offset:32;	size:8;	signed:1;
func resolveSchedSwitchStateField() (offset, size uint32, err error) {
	var firstErr error
	for _, root := range tracefsRoots {
		path := filepath.Join(root, "events", switchOutTracepointGroup,
			switchOutTracepointName, "format")
		offset, size, err := parseTracepointField(path, "prev_state")
		if err == nil {
			return offset, size, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return 0, 0, firstErr
}

func parseTracepointField(path, field string) (offset, size uint32, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "field:") ||
			!strings.Contains(line, " "+field+";") {
			continue
		}
		parsedOffset, offsetErr := tracepointFieldAttribute(line, "offset")
		parsedSize, sizeErr := tracepointFieldAttribute(line, "size")
		if offsetErr != nil || sizeErr != nil {
			return 0, 0, fmt.Errorf("malformed format line %q in %s", line, path)
		}
		return parsedOffset, parsedSize, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return 0, 0, fmt.Errorf("field %q not found in %s", field, path)
}

func tracepointFieldAttribute(line, attribute string) (uint32, error) {
	marker := attribute + ":"
	start := strings.Index(line, marker)
	if start < 0 {
		return 0, fmt.Errorf("attribute %q not found", attribute)
	}
	rest := line[start+len(marker):]
	end := strings.IndexByte(rest, ';')
	if end < 0 {
		return 0, fmt.Errorf("attribute %q not terminated", attribute)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(rest[:end]), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

// resolveSwitchInSymbols returns the text symbols from kallsyms that are
// finish_task_switch or an optimized clone of it (finish_task_switch.<suffix>).
func resolveSwitchInSymbols() ([]string, error) {
	file, err := os.Open(kallsymsPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := make(map[string]struct{})
	var symbols []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Format: address type name [module]
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "t" && fields[1] != "T" {
			continue
		}
		name := fields[2]
		if name != switchInSymbolPrefix &&
			!strings.HasPrefix(name, switchInSymbolPrefix+".") {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		symbols = append(symbols, name)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return symbols, nil
}
