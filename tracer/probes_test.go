// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"errors"
	"math"
	"slices"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

type testProbe struct {
	metadata *samples.TypeMetadata
	load     func(uint16, *ProbeContext) (link.Link, error)
}

func (p *testProbe) Load(origin uint16, ctx *ProbeContext) (link.Link, error) {
	return p.load(origin, ctx)
}

func (p *testProbe) ReportMetadata() *samples.TypeMetadata {
	return p.metadata
}

func TestCollectionSpecWithSelectsProbeResources(t *testing.T) {
	ctx := &ProbeContext{sysVars: SysConfigVars{
		tpbase_offset:       1,
		task_stack_offset:   2,
		stack_ptregs_offset: 3,
		vma_lookup_enabled:  true,
		vma_vm_file_offset:  4,
		vma_vm_flags_offset: 5,
	}}
	collection, err := ctx.CollectionSpecWith(
		[]string{"sched_times"},
		[]string{genericProgName},
		[]string{"origin_id_probe"},
	)
	require.NoError(t, err)
	require.Equal(t, []string{".rodata", ".rodata.var", "sched_times"}, sortedKeys(collection.Maps))
	require.Equal(t, []string{genericProgName}, sortedKeys(collection.Programs))
	require.Contains(t, collection.Variables, "origin_id_probe")
	require.Len(t, collection.Variables, 8)
}

func TestRemoveDynamicProbeResources(t *testing.T) {
	collection := &cebpf.CollectionSpec{
		Maps: map[string]*cebpf.MapSpec{
			"off_cpu_time_starts": nil,
			"shared_map":          nil,
		},
		Programs: map[string]*cebpf.ProgramSpec{
			"off_cpu_time_switch_in": nil,
			genericProgName:          nil,
		},
		Variables: map[string]*cebpf.VariableSpec{
			"off_cpu_time_origin": nil,
			"shared_variable":     nil,
		},
	}

	removeDynamicProbeResources(collection, []string{"off_cpu_time"})
	require.NotContains(t, collection.Maps, "off_cpu_time_starts")
	require.NotContains(t, collection.Programs, "off_cpu_time_switch_in")
	require.NotContains(t, collection.Variables, "off_cpu_time_origin")
	require.Contains(t, collection.Maps, "shared_map")
	require.Contains(t, collection.Programs, genericProgName)
	require.Contains(t, collection.Variables, "shared_variable")
}

func TestCollectionSpecWithRejectsMissingResources(t *testing.T) {
	ctx := &ProbeContext{}
	_, err := ctx.CollectionSpecWith([]string{"missing_map"}, nil, nil)
	require.ErrorContains(t, err, `map "missing_map"`)
	_, err = ctx.CollectionSpecWith(nil, []string{"missing_program"}, nil)
	require.ErrorContains(t, err, `program "missing_program"`)
	_, err = ctx.CollectionSpecWith(nil, nil, []string{"missing_variable"})
	require.ErrorContains(t, err, `variable "missing_variable"`)
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func TestProbeMetricCollectorsAggregateAndUnregister(t *testing.T) {
	trc := &Tracer{probeMetricCollectors: make(map[uint64]*probeMetricCollector)}
	first, err := trc.registerProbeMetrics(func() []metrics.Metric {
		return []metrics.Metric{
			{ID: metrics.IDUnwindNativeAttempts, Value: 2},
			{ID: metrics.IDHashmapPidPageToMappingInfo, Value: 3},
		}
	})
	require.NoError(t, err)
	second, err := trc.registerProbeMetrics(func() []metrics.Metric {
		return []metrics.Metric{
			{ID: metrics.IDUnwindNativeAttempts, Value: 5},
			{ID: metrics.IDHashmapPidPageToMappingInfo, Value: 7},
		}
	})
	require.NoError(t, err)

	require.Equal(t, []metrics.Metric{
		{ID: metrics.IDUnwindNativeAttempts, Value: 7},
		{ID: metrics.IDHashmapPidPageToMappingInfo, Value: 10},
	}, trc.collectProbeMetrics())

	require.NoError(t, first.Close())
	require.Equal(t, []metrics.Metric{
		{ID: metrics.IDUnwindNativeAttempts, Value: 5},
		{ID: metrics.IDHashmapPidPageToMappingInfo, Value: 7},
	}, trc.collectProbeMetrics())
	require.NoError(t, second.Close())
	require.Empty(t, trc.collectProbeMetrics())
}

func TestProbeMetricCollectorCloseRetainsFinalCounterDeltas(t *testing.T) {
	trc := &Tracer{
		probeMetricCollectors: make(map[uint64]*probeMetricCollector),
		pendingProbeMetrics:   make(metrics.Summary),
	}
	subscription, err := trc.registerProbeMetrics(func() []metrics.Metric { return nil })
	require.NoError(t, err)
	finalizer, ok := subscription.(interface {
		CloseWithMetrics([]metrics.Metric) error
	})
	require.True(t, ok)
	require.NoError(t, finalizer.CloseWithMetrics([]metrics.Metric{
		{ID: metrics.IDUnwindNativeFrames, Value: 3},
		{ID: metrics.IDHashmapPidPageToMappingInfo, Value: 7},
	}))
	require.Equal(t, []metrics.Metric{{
		ID: metrics.IDUnwindNativeFrames, Value: 3,
	}}, trc.collectProbeMetrics())
	require.Empty(t, trc.collectProbeMetrics())
}

func TestProbeMetricCollectorCloseWaitsForInflightCallback(t *testing.T) {
	trc := &Tracer{probeMetricCollectors: make(map[uint64]*probeMetricCollector)}
	started := make(chan struct{})
	release := make(chan struct{})
	subscription, err := trc.registerProbeMetrics(func() []metrics.Metric {
		close(started)
		<-release
		return nil
	})
	require.NoError(t, err)
	collectionDone := make(chan struct{})
	go func() {
		defer close(collectionDone)
		trc.collectProbeMetrics()
	}()
	<-started

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		require.NoError(t, subscription.Close())
	}()
	select {
	case <-closeDone:
		t.Fatal("collector close returned during an in-flight callback")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-collectionDone
	<-closeDone
	require.Empty(t, trc.collectProbeMetrics())
}

func TestProbeMetricCollectorPanicIsIsolated(t *testing.T) {
	trc := &Tracer{probeMetricCollectors: make(map[uint64]*probeMetricCollector)}
	_, err := trc.registerProbeMetrics(func() []metrics.Metric { panic("boom") })
	require.NoError(t, err)
	_, err = trc.registerProbeMetrics(func() []metrics.Metric {
		return []metrics.Metric{{ID: metrics.IDHashmapPidPageToMappingInfo, Value: 7}}
	})
	require.NoError(t, err)
	require.Equal(t, []metrics.Metric{{
		ID: metrics.IDHashmapPidPageToMappingInfo, Value: 7,
	}}, trc.collectProbeMetrics())
}

func TestRegisterProbeMetricsRejectsNil(t *testing.T) {
	trc := &Tracer{probeMetricCollectors: make(map[uint64]*probeMetricCollector)}
	_, err := trc.registerProbeMetrics(nil)
	require.ErrorContains(t, err, "nil")
}

func TestEnableRegistersOriginBeforeLoadingAndRollsBackOnError(t *testing.T) {
	loadErr := errors.New("load failed")
	metadata := &samples.TypeMetadata{SampleType: "test", SampleUnit: "count"}
	maps := map[string]*cebpf.Map{"shared": nil}
	systemVars := SysConfigVars{task_stack_offset: 42}
	trc := &Tracer{
		ebpfMaps:          maps,
		origins:           &originRegistry{},
		sysConfigVars:     systemVars,
		kprobeChainLoaded: true,
		hooks:             make(map[hookPoint]link.Link),
	}

	probe := &testProbe{
		metadata: metadata,
		load: func(origin uint16, gotCtx *ProbeContext) (link.Link, error) {
			require.Equal(t, uint16(1), origin)
			require.Same(t, metadata, trc.origins.lookup(origin))
			require.Equal(t, maps, gotCtx.maps)
			require.Equal(t, systemVars, gotCtx.sysVars)
			return nil, loadErr
		},
	}

	err := trc.Enable(probe)
	require.ErrorIs(t, err, loadErr)
	require.Nil(t, trc.origins.lookup(1))
	require.Empty(t, trc.hooks)
}

func TestEnableRejectsMissingKprobeChain(t *testing.T) {
	loadCalled := false
	trc := &Tracer{}
	probe := &testProbe{
		metadata: &samples.TypeMetadata{SampleType: "test", SampleUnit: "count"},
		load: func(uint16, *ProbeContext) (link.Link, error) {
			loadCalled = true
			return nil, nil
		},
	}

	err := trc.Enable(probe)
	require.ErrorContains(t, err, "kprobe unwinder chain")
	require.False(t, loadCalled)
}

func TestOriginRegistryRejectsExhaustion(t *testing.T) {
	registry := &originRegistry{}
	registry.lastID.Store(math.MaxUint16)
	_, err := registry.register(&samples.TypeMetadata{SampleType: "test", SampleUnit: "count"})
	require.ErrorContains(t, err, "maximum number")
}

func TestEnableRejectsNilProbe(t *testing.T) {
	trc := &Tracer{}
	require.EqualError(t, trc.Enable(nil), "probe is nil")
}

func TestEnableRejectsNilMetadata(t *testing.T) {
	loadCalled := false
	trc := &Tracer{origins: &originRegistry{}, kprobeChainLoaded: true}
	probe := &testProbe{
		load: func(uint16, *ProbeContext) (link.Link, error) {
			loadCalled = true
			return nil, nil
		},
	}

	err := trc.Enable(probe)
	require.EqualError(t, err, "probe report metadata is nil")
	require.False(t, loadCalled)
}

func TestEnableRejectsNilLinkAndRollsBackOrigin(t *testing.T) {
	trc := &Tracer{
		origins:           &originRegistry{},
		kprobeChainLoaded: true,
		hooks:             make(map[hookPoint]link.Link),
	}
	probe := &testProbe{
		metadata: &samples.TypeMetadata{SampleType: "test", SampleUnit: "count"},
		load: func(uint16, *ProbeContext) (link.Link, error) {
			return nil, nil
		},
	}

	err := trc.Enable(probe)
	require.EqualError(t, err, "probe returned a nil link")
	require.Nil(t, trc.origins.lookup(1))
	require.Empty(t, trc.hooks)
}
