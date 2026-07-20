// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"errors"
	"slices"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
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
	collection, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	for _, name := range dynamicProbeResources.maps {
		require.Contains(t, collection.Maps, name)
	}
	for _, name := range dynamicProbeResources.programs {
		require.Contains(t, collection.Programs, name)
	}
	for _, name := range dynamicProbeResources.variables {
		require.Contains(t, collection.Variables, name)
	}

	removeDynamicProbeResources(collection)
	for _, name := range dynamicProbeResources.maps {
		require.NotContains(t, collection.Maps, name)
	}
	for _, name := range dynamicProbeResources.programs {
		require.NotContains(t, collection.Programs, name)
	}
	for _, name := range dynamicProbeResources.variables {
		require.NotContains(t, collection.Variables, name)
	}
	require.Contains(t, collection.Programs, genericProgName)
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
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
