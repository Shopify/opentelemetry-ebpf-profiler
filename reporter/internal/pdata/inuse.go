// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"path/filepath"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/liveheap"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// appendInuseProfiles appends inuse_space and inuse_objects profiles to the
// existing Profiles object, sharing the same dictionary and ordered sets.
// Profiles are added to an unambiguous existing ResourceProfiles entry matched
// by PID plus allocation-time process metadata so PID reuse cannot cross-attribute data.
func appendInuseProfiles(
	profiles pprofile.Profiles,
	dic pprofile.ProfilesDictionary,
	attrMgr *samples.AttrTableManager,
	stringSet orderedset.OrderedSet[string],
	funcSet orderedset.OrderedSet[funcInfo],
	locationSet orderedset.OrderedSet[locationInfo],
	mappingSet orderedset.OrderedSet[libpf.FrameMapping],
	stackSet orderedset.OrderedSet[stackInfo],
	agentName, agentVersion string,
	collectionStartTime, collectionEndTime time.Time,
	entries []liveheap.InuseEntry,
	processMeta func(libpf.PID) liveheap.ProcessMeta,
	extraSampleAttrProd samples.SampleAttrProducer,
) {
	type processKey struct {
		PID  libpf.PID
		Meta liveheap.ProcessMeta
	}
	// Group by allocation-time process identity, not PID alone. Legacy entries
	// without embedded metadata use one resolver result cached per PID.
	byProcess := make(map[processKey][]liveheap.InuseEntry)
	fallbackMeta := make(map[libpf.PID]liveheap.ProcessMeta)
	fallbackResolved := make(map[libpf.PID]bool)
	for _, entry := range entries {
		meta := entry.ProcessMeta
		if meta.ExecutablePath == libpf.NullString && meta.ContainerID == libpf.NullString &&
			processMeta != nil {
			if !fallbackResolved[entry.PID] {
				fallbackMeta[entry.PID] = processMeta(entry.PID)
				fallbackResolved[entry.PID] = true
			}
			meta = fallbackMeta[entry.PID]
		}
		key := processKey{PID: entry.PID, Meta: meta}
		byProcess[key] = append(byProcess[key], entry)
	}

	// Keep every resource candidate for a PID. A map to one entry would choose
	// arbitrarily if an export interval contains samples from an exited process
	// and its PID-reused replacement.
	resourcesByPID := make(map[libpf.PID][]pprofile.ResourceProfiles)
	for i := range profiles.ResourceProfiles().Len() {
		rp := profiles.ResourceProfiles().At(i)
		pidVal, ok := rp.Resource().Attributes().Get(string(semconv.ProcessPIDKey))
		if ok {
			pid := libpf.PID(pidVal.Int())
			resourcesByPID[pid] = append(resourcesByPID[pid], rp)
		}
	}

	for key, processEntries := range byProcess {
		pid := key.PID
		meta := key.Meta
		hasMeta := meta.ExecutablePath != libpf.NullString ||
			meta.ContainerID != libpf.NullString

		// Reuse only one unambiguous resource whose executable/container metadata
		// exactly matches the current process. Otherwise create a fresh resource.
		rp, found := matchingInuseResource(resourcesByPID[pid], meta, hasMeta)
		if !found {
			rp = profiles.ResourceProfiles().AppendEmpty()
			rp.SetSchemaUrl(semconv.SchemaURL)
			attrs := rp.Resource().Attributes()
			attrs.PutInt(string(semconv.ProcessPIDKey), int64(pid))
			if meta.ExecutablePath != libpf.NullString {
				attrs.PutStr(string(semconv.ProcessExecutablePathKey), meta.ExecutablePath.String())
				_, exeName := filepath.Split(meta.ExecutablePath.String())
				attrs.PutStr(string(semconv.ProcessExecutableNameKey), exeName)
			}
			if meta.ContainerID != libpf.NullString {
				attrs.PutStr(string(semconv.ContainerIDKey), meta.ContainerID.String())
			}
		}

		// Find or create a ScopeProfiles within this resource.
		var sp pprofile.ScopeProfiles
		if rp.ScopeProfiles().Len() > 0 {
			sp = rp.ScopeProfiles().At(0)
		} else {
			sp = rp.ScopeProfiles().AppendEmpty()
			sp.SetSchemaUrl(semconv.SchemaURL)
			scope := sp.Scope()
			scope.SetName(agentName)
			scope.SetVersion(agentVersion)
		}

		for _, kind := range []profileKind{profileKindHeapInuseSpace, profileKindHeapInuseObjects} {
			prof := sp.Profiles().AppendEmpty()

			st := prof.SampleType()
			if kind == profileKindHeapInuseSpace {
				st.SetTypeStrindex(stringSet.Add("inuse_space"))
				st.SetUnitStrindex(stringSet.Add("bytes"))
			} else {
				st.SetTypeStrindex(stringSet.Add("inuse_objects"))
				st.SetUnitStrindex(stringSet.Add("count"))
			}

			for _, entry := range processEntries {
				sample := prof.Samples().AppendEmpty()
				if kind == profileKindHeapInuseSpace {
					sample.Values().Append(entry.Space)
				} else {
					sample.Values().Append(entry.Objects)
				}
				sample.TimestampsUnixNano().Append(uint64(collectionEndTime.UnixNano()))

				stackIdx := appendFramesAsStack(entry.Frames, dic, attrMgr,
					stringSet, funcSet, mappingSet, locationSet, stackSet)
				sample.SetStackIndex(stackIdx)
				if extraSampleAttrProd != nil && entry.ExtraMeta != nil {
					extra := extraSampleAttrProd.ExtraSampleAttrs(attrMgr, entry.ExtraMeta)
					sample.AttributeIndices().Append(extra...)
				}
			}

			// In-use profiles are instantaneous gauges, not event counts over the
			// collection window. Timestamp the snapshot at collection end with zero
			// duration so storage/query layers can apply snapshot aggregation.
			prof.SetDurationNano(0)
			prof.SetTime(pcommon.Timestamp(collectionEndTime.UnixNano()))
		}
	}
}

func matchingInuseResource(candidates []pprofile.ResourceProfiles,
	meta liveheap.ProcessMeta, hasMeta bool,
) (pprofile.ResourceProfiles, bool) {
	var matched pprofile.ResourceProfiles
	numMatched := 0
	for _, candidate := range candidates {
		if hasMeta && !resourceMatchesInuseMeta(candidate.Resource().Attributes(), meta) {
			continue
		}
		matched = candidate
		numMatched++
	}
	return matched, numMatched == 1
}

func resourceMatchesInuseMeta(attrs pcommon.Map, meta liveheap.ProcessMeta) bool {
	return resourceStringAttributeMatches(attrs,
		string(semconv.ProcessExecutablePathKey), meta.ExecutablePath) &&
		resourceStringAttributeMatches(attrs,
			string(semconv.ContainerIDKey), meta.ContainerID)
}

func resourceStringAttributeMatches(attrs pcommon.Map, key string, want libpf.String) bool {
	if want == libpf.NullString {
		return true
	}
	got, present := attrs.Get(key)
	return present && got.Str() == want.String()
}
