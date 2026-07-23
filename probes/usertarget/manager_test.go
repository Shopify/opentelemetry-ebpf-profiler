// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usertarget

import (
	"debug/elf"
	"errors"
	"os"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type testCloser struct {
	closed *atomic.Uint64
	err    error
}

type testMetricFinalizer struct {
	closed *atomic.Uint64
	final  []metrics.Metric
}

func (f *testMetricFinalizer) Close() error {
	return f.CloseWithMetrics(nil)
}

func (f *testMetricFinalizer) CloseWithMetrics(final []metrics.Metric) error {
	f.closed.Add(1)
	f.final = append([]metrics.Metric(nil), final...)
	return nil
}

func (c *testCloser) Close() error {
	c.closed.Add(1)
	return c.err
}

type testLink struct {
	link.Link
	closed *atomic.Uint64
	err    error
}

func (l *testLink) Close() error {
	if l.closed != nil {
		l.closed.Add(1)
	}
	return l.err
}

func targetEvent(pid libpf.PID, identity tracer.ProcessIdentity,
	mappings ...process.RawMapping,
) tracer.ProcessEvent {
	return tracer.ProcessEvent{
		PID:      pid,
		Identity: identity,
		Meta: process.ProcessMeta{
			Name:       libpf.Intern("server\n"),
			Executable: libpf.Intern("/opt/bin/server"),
		},
		Mappings: mappings,
	}
}

func executableMapping(device, inode uint64) process.RawMapping {
	return process.RawMapping{
		Vaddr:  0x1000,
		Length: 0x1000,
		Flags:  elf.PF_R | elf.PF_X,
		Device: device,
		Inode:  inode,
		Path:   "/opt/bin/server",
	}
}

func TestManagerReconcilesMappingAndProcessGenerations(t *testing.T) {
	var closed atomic.Uint64
	var attachCalls atomic.Uint64
	var resets atomic.Uint64
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}, Return: &ebpf.Program{}},
		Options{ResetProcess: func(libpf.PID) error {
			resets.Add(1)
			return nil
		}})
	require.NoError(t, err)
	manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
		_ Programs, available uint32, _ map[uint64]struct{}, _ func() bool,
	) ([]newAttachment, error) {
		attachCalls.Add(1)
		require.GreaterOrEqual(t, available, uint32(2))
		return []newAttachment{{
			offset: 0x123,
			set: attachmentSet{links: []link.Link{
				&testLink{closed: &closed},
				&testLink{closed: &closed},
			}},
		}}, nil
	}

	pid := libpf.PID(42)
	firstIdentity := tracer.ProcessIdentity{StartTime: 1, AddressSpace: 1}
	mapping := executableMapping(1, 2)
	manager.ProcessSynchronized(targetEvent(pid, firstIdentity, mapping))
	require.Equal(t, uint64(1), attachCalls.Load())
	require.Equal(t, uint64(2), manager.Snapshot().ActiveLinks)
	require.Equal(t, uint64(1), manager.Snapshot().ActiveProcesses)

	// An unchanged synchronization retains existing links.
	manager.ProcessSynchronized(targetEvent(pid, firstIdentity, mapping))
	require.Equal(t, uint64(1), attachCalls.Load())
	require.Zero(t, closed.Load())

	// An explicit exec event invalidates state even if /proc identity fields
	// happen to remain unchanged for a same-image re-exec.
	execEvent := targetEvent(pid, firstIdentity, mapping)
	execEvent.ImageChanged = true
	manager.ProcessSynchronized(execEvent)
	require.Equal(t, uint64(2), attachCalls.Load())
	require.Equal(t, uint64(2), closed.Load())
	require.Equal(t, uint64(1), resets.Load())

	// A replacement identity also closes old links and reattaches.
	secondIdentity := tracer.ProcessIdentity{StartTime: 1, AddressSpace: 2}
	manager.ProcessSynchronized(targetEvent(pid, secondIdentity, mapping))
	require.Equal(t, uint64(3), attachCalls.Load())
	require.Equal(t, uint64(4), closed.Load())
	require.Equal(t, uint64(2), resets.Load())
	require.Equal(t, uint64(2), manager.Snapshot().ActiveLinks)

	manager.ProcessExited(pid)
	require.Equal(t, uint64(6), closed.Load())
	require.Equal(t, uint64(3), resets.Load())
	require.Zero(t, manager.Snapshot().ActiveLinks)
	require.Zero(t, manager.Snapshot().ActiveProcesses)

	// Exit delivery is idempotent for links and cleanup.
	manager.ProcessExited(pid)
	require.Equal(t, uint64(6), closed.Load())
	require.Equal(t, uint64(3), resets.Load())
}

func TestManagerRetriesOnlyOffsetsMissingAfterPartialAttachment(t *testing.T) {
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{})
	require.NoError(t, err)
	var calls uint64
	manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
		_ Programs, _ uint32, attached map[uint64]struct{}, _ func() bool,
	) ([]newAttachment, error) {
		calls++
		switch calls {
		case 1:
			require.Empty(t, attached)
			return []newAttachment{{
				offset: 1, set: attachmentSet{links: []link.Link{&testLink{}}},
			}}, &probeAttachError{err: errors.New("transient attach failure")}
		case 2:
			require.Equal(t, map[uint64]struct{}{1: {}}, attached)
			return []newAttachment{{
				offset: 2, set: attachmentSet{links: []link.Link{&testLink{}}},
			}}, nil
		default:
			t.Fatalf("unexpected attachment attempt %d", calls)
			return nil, nil
		}
	}

	event := targetEvent(1, tracer.ProcessIdentity{StartTime: 1}, executableMapping(1, 1))
	manager.ProcessSynchronized(event)
	require.Equal(t, uint64(1), manager.Snapshot().ActiveLinks)
	require.Equal(t, uint64(1), manager.Snapshot().AttachFailures)
	manager.ProcessSynchronized(event)
	require.Equal(t, uint64(2), manager.Snapshot().ActiveLinks)
	manager.ProcessSynchronized(event)
	require.Equal(t, uint64(2), calls)
}

func TestManagerRetriesOffsetsAfterPartialLinkLimit(t *testing.T) {
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{})
	require.NoError(t, err)
	var calls uint64
	manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
		_ Programs, _ uint32, attached map[uint64]struct{}, _ func() bool,
	) ([]newAttachment, error) {
		calls++
		if calls == 1 {
			require.Empty(t, attached)
			return []newAttachment{{
				offset: 1, set: attachmentSet{links: []link.Link{&testLink{}}},
			}}, errLinkLimit
		}
		require.Equal(t, map[uint64]struct{}{1: {}}, attached)
		return []newAttachment{{
			offset: 2, set: attachmentSet{links: []link.Link{&testLink{}}},
		}}, nil
	}

	event := targetEvent(1, tracer.ProcessIdentity{StartTime: 1}, executableMapping(1, 1))
	manager.ProcessSynchronized(event)
	require.Equal(t, uint64(1), manager.Snapshot().LinkLimitHits)
	manager.ProcessSynchronized(event)
	manager.ProcessSynchronized(event)
	require.Equal(t, uint64(2), calls)
	require.Equal(t, uint64(2), manager.Snapshot().ActiveLinks)
}

func TestManagerSaturationSkipsResolutionAndBoundsProcessState(t *testing.T) {
	target := validTarget()
	target.MaxLinks = 1
	manager, err := New(target, Programs{Entry: &ebpf.Program{}}, Options{})
	require.NoError(t, err)
	var attachCalls atomic.Uint64
	manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
		_ Programs, _ uint32, _ map[uint64]struct{}, _ func() bool,
	) ([]newAttachment, error) {
		attachCalls.Add(1)
		return []newAttachment{{
			offset: 1, set: attachmentSet{links: []link.Link{&testLink{}}},
		}}, nil
	}

	identity := tracer.ProcessIdentity{StartTime: 1}
	for pid := libpf.PID(1); pid <= 100; pid++ {
		manager.ProcessSynchronized(targetEvent(pid, identity, executableMapping(1, uint64(pid))))
	}
	require.Equal(t, uint64(1), attachCalls.Load())
	require.Equal(t, uint64(1), manager.Snapshot().ActiveProcesses)
	require.Equal(t, uint64(1), manager.Snapshot().ActiveLinks)
	require.Equal(t, uint64(99), manager.Snapshot().LinkLimitHits)

	manager.ProcessExited(1)
	manager.ProcessSynchronized(targetEvent(2, identity, executableMapping(1, 2)))
	require.Equal(t, uint64(2), attachCalls.Load())
	require.Equal(t, uint64(1), manager.Snapshot().ActiveProcesses)
}

func TestManagerInvalidationCancelsInflightAttachment(t *testing.T) {
	var closed atomic.Uint64
	var resets atomic.Uint64
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{
		ResetProcess: func(libpf.PID) error {
			resets.Add(1)
			return nil
		},
	})
	require.NoError(t, err)
	started := make(chan struct{})
	release := make(chan struct{})
	manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
		_ Programs, _ uint32, _ map[uint64]struct{}, _ func() bool,
	) ([]newAttachment, error) {
		close(started)
		<-release
		return []newAttachment{{
			offset: 1,
			set: attachmentSet{links: []link.Link{
				&testLink{closed: &closed},
			}},
		}}, nil
	}

	pid := libpf.PID(42)
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.ProcessSynchronized(targetEvent(pid,
			tracer.ProcessIdentity{StartTime: 1}, executableMapping(1, 1)))
	}()
	<-started
	manager.ProcessInvalidated(pid)
	close(release)
	<-done

	stats := manager.Snapshot()
	require.Equal(t, uint64(1), closed.Load())
	require.Equal(t, uint64(1), resets.Load())
	require.Equal(t, uint64(1), stats.LinksAttached)
	require.Equal(t, uint64(1), stats.LinksDetached)
	require.Zero(t, stats.ActiveLinks)
	require.Zero(t, stats.ActiveProcesses)
}

func TestManagerClassifiesAttachRollbackCleanupFailure(t *testing.T) {
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{})
	require.NoError(t, err)
	manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
		_ Programs, _ uint32, _ map[uint64]struct{}, _ func() bool,
	) ([]newAttachment, error) {
		return nil, errors.Join(
			&probeAttachError{err: errors.New("entry attach failed")},
			&probeCleanupError{err: errors.New("return rollback failed")},
		)
	}

	manager.ProcessSynchronized(targetEvent(1,
		tracer.ProcessIdentity{StartTime: 1}, executableMapping(1, 1)))
	stats := manager.Snapshot()
	require.Equal(t, uint64(1), stats.AttachFailures)
	require.Equal(t, uint64(1), stats.CleanupFailures)
	require.Zero(t, stats.ResolutionFailures)
	require.Zero(t, stats.ActiveProcesses)
}

func TestManagerReportsCleanupFailures(t *testing.T) {
	cleanupErr := errors.New("cleanup failed")
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{
		ResetProcess: func(libpf.PID) error { return cleanupErr },
	})
	require.NoError(t, err)
	manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
		_ Programs, _ uint32, _ map[uint64]struct{}, _ func() bool,
	) ([]newAttachment, error) {
		return []newAttachment{{
			offset: 1,
			set: attachmentSet{links: []link.Link{
				&testLink{err: cleanupErr},
			}},
		}}, nil
	}

	pid := libpf.PID(42)
	manager.ProcessSynchronized(targetEvent(pid,
		tracer.ProcessIdentity{StartTime: 1}, executableMapping(1, 1)))
	manager.ProcessExited(pid)
	require.Equal(t, uint64(2), manager.Snapshot().CleanupFailures)
	require.Equal(t, uint64(1), manager.Snapshot().LinksDetached)
	require.Zero(t, manager.Snapshot().ActiveLinks)
}

func TestManagerRemovesUnmappedObjectAndEnforcesSelectors(t *testing.T) {
	var closed atomic.Uint64
	var resets atomic.Uint64
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{
		ResetProcess: func(libpf.PID) error {
			resets.Add(1)
			return nil
		},
	})
	require.NoError(t, err)
	manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
		_ Programs, _ uint32, _ map[uint64]struct{}, _ func() bool,
	) ([]newAttachment, error) {
		return []newAttachment{{
			offset: 1,
			set:    attachmentSet{links: []link.Link{&testLink{closed: &closed}}},
		}}, nil
	}

	identity := tracer.ProcessIdentity{StartTime: 1}
	manager.ProcessSynchronized(targetEvent(1, identity, executableMapping(1, 1)))
	require.Equal(t, uint64(1), manager.Snapshot().ActiveLinks)

	manager.ProcessSynchronized(targetEvent(1, identity))
	require.Equal(t, uint64(1), closed.Load())
	require.Equal(t, uint64(1), resets.Load())
	require.Zero(t, manager.Snapshot().ActiveLinks)
	require.Zero(t, manager.Snapshot().ActiveProcesses)

	nonMatching := targetEvent(1, identity, executableMapping(1, 1))
	nonMatching.Meta.Name = libpf.Intern("other")
	manager.ProcessSynchronized(nonMatching)
	require.Zero(t, manager.Snapshot().ActiveProcesses)
}

func TestProcessIdentityCurrentRejectsStaleSnapshot(t *testing.T) {
	pid := libpf.PID(os.Getpid())
	identity, err := tracer.ReadProcessIdentity(pid)
	require.NoError(t, err)
	event := tracer.ProcessEvent{PID: pid, Identity: identity}
	require.True(t, processIdentityCurrent(event))
	event.Identity.StartTime++
	require.False(t, processIdentityCurrent(event))
}

func TestManagerStartRejectsNilContext(t *testing.T) {
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{})
	require.NoError(t, err)
	_, err = manager.Start(nil)
	require.ErrorContains(t, err, "context is nil")
}

func TestManagerCloseCleansSubscriptionsLinksAndProcessState(t *testing.T) {
	var subscriptionCloses atomic.Uint64
	var metricCloses atomic.Uint64
	var linkCloses atomic.Uint64
	var resets atomic.Uint64
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{
		ResetProcess: func(libpf.PID) error {
			resets.Add(1)
			return nil
		},
	})
	require.NoError(t, err)
	manager.subscription = &testCloser{closed: &subscriptionCloses}
	metricFinalizer := &testMetricFinalizer{closed: &metricCloses}
	manager.metricSubscription = metricFinalizer
	pid := libpf.PID(42)
	identity := tracer.ProcessIdentity{StartTime: 1}
	manager.processes[pid] = identity
	manager.counters.activeProcesses.Store(1)
	manager.attachments[attachmentKey{
		attachmentObjectKey: attachmentObjectKey{pid: pid, identity: identity}, offset: 1,
	}] = attachmentSet{links: []link.Link{&testLink{closed: &linkCloses}}}
	manager.counters.activeLinks.Store(1)

	require.NoError(t, manager.Close())
	require.NoError(t, manager.Close())
	require.Equal(t, uint64(1), subscriptionCloses.Load())
	require.Equal(t, uint64(1), metricCloses.Load())
	require.Equal(t, uint64(1), linkCloses.Load())
	require.Equal(t, uint64(1), resets.Load())
	require.Contains(t, metricFinalizer.final, metrics.Metric{
		ID: metrics.IDUserspaceProbeLinksDetached, Value: 1,
	})
	require.Zero(t, manager.Snapshot().ActiveProcesses)
	require.Zero(t, manager.Snapshot().ActiveLinks)
	_, err = manager.Start(&tracer.ProbeContext{})
	require.ErrorContains(t, err, "closed")
}

func TestManagerCollectMetricsReportsCounterDeltasAndGauges(t *testing.T) {
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{})
	require.NoError(t, err)
	manager.counters.linksAttached.Add(4)
	manager.counters.activeLinks.Add(3)

	first := manager.collectMetrics()
	require.Contains(t, first, metrics.Metric{
		ID: metrics.IDUserspaceProbeLinksAttached, Value: 4,
	})
	require.Contains(t, first, metrics.Metric{
		ID: metrics.IDUserspaceProbeActiveLinks, Value: 3,
	})
	second := manager.collectMetrics()
	require.Contains(t, second, metrics.Metric{
		ID: metrics.IDUserspaceProbeLinksAttached, Value: 0,
	})
	require.Contains(t, second, metrics.Metric{
		ID: metrics.IDUserspaceProbeActiveLinks, Value: 3,
	})
}

func TestManagerClassifiesLinkLimitAndObjectMismatch(t *testing.T) {
	tests := []struct {
		name             string
		err              error
		wantLimitHits    uint64
		wantAttachErrors uint64
		wantResolution   uint64
	}{
		{name: "link limit", err: errLinkLimit, wantLimitHits: 1},
		{name: "object mismatch", err: errObjectMismatch},
		{name: "resolution", err: errors.New("resolution failed"), wantResolution: 1},
		{name: "joined attach and limit", err: errors.Join(
			&probeAttachError{err: errors.New("attach failed")}, errLinkLimit),
			wantLimitHits: 1, wantAttachErrors: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{})
			require.NoError(t, err)
			manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
				_ Programs, _ uint32, _ map[uint64]struct{}, _ func() bool,
			) ([]newAttachment, error) {
				return nil, test.err
			}
			manager.ProcessSynchronized(targetEvent(1,
				tracer.ProcessIdentity{StartTime: 1}, executableMapping(1, 1)))
			stats := manager.Snapshot()
			require.Equal(t, test.wantLimitHits, stats.LinkLimitHits)
			require.Equal(t, test.wantAttachErrors, stats.AttachFailures)
			require.Equal(t, test.wantResolution, stats.ResolutionFailures)
		})
	}
}

func TestManagerClassifiesFailures(t *testing.T) {
	manager, err := New(validTarget(), Programs{Entry: &ebpf.Program{}}, Options{})
	require.NoError(t, err)
	failure := errors.New("attach failed")
	manager.attachObject = func(_ tracer.ProcessEvent, _ process.RawMapping, _ Target,
		_ Programs, _ uint32, _ map[uint64]struct{}, _ func() bool,
	) ([]newAttachment, error) {
		return nil, &probeAttachError{err: failure}
	}
	manager.ProcessSynchronized(targetEvent(1,
		tracer.ProcessIdentity{StartTime: 1}, executableMapping(1, 1)))
	require.Equal(t, uint64(1), manager.Snapshot().AttachFailures)
	require.Zero(t, manager.Snapshot().ResolutionFailures)
}
