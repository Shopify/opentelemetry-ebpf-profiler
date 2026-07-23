// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager

import (
	"debug/elf"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	freelru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type recordingProcessObserver struct {
	mu     sync.Mutex
	events []ProcessEvent
	exits  []libpf.PID
}

func (o *recordingProcessObserver) ProcessSynchronized(event ProcessEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
}

func (o *recordingProcessObserver) ProcessExited(pid libpf.PID) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.exits = append(o.exits, pid)
}

func (o *recordingProcessObserver) snapshot() ([]ProcessEvent, []libpf.PID) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]ProcessEvent(nil), o.events...), append([]libpf.PID(nil), o.exits...)
}

func TestSubscribeProcessObserverPublishesSnapshotAndUnsubscribes(t *testing.T) {
	pid := libpf.PID(42)
	mapping := process.RawMapping{Path: "/bin/server", Inode: 7}
	pm := &ProcessManager{
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {
				meta:             process.ProcessMeta{Name: libpf.Intern("server")},
				identity:         ProcessIdentity{StartTime: 1},
				observerMappings: []process.RawMapping{mapping},
			},
		},
	}
	observer := &recordingProcessObserver{}
	subscription, err := pm.SubscribeProcessObserver(observer)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		events, _ := observer.snapshot()
		return len(events) == 1
	}, time.Second, time.Millisecond)
	events, _ := observer.snapshot()
	require.Equal(t, pid, events[0].PID)
	require.Equal(t, mapping, events[0].Mappings[0])

	// The observer owns a cloned slice rather than ProcessManager's backing array.
	events[0].Mappings[0].Inode = 99
	require.Equal(t, uint64(7), pm.pidToProcessInfo[pid].observerMappings[0].Inode)

	pm.notifyProcessExited(pid)
	require.Eventually(t, func() bool {
		_, exits := observer.snapshot()
		return len(exits) == 1
	}, time.Second, time.Millisecond)
	require.NoError(t, subscription.Close())
	require.NoError(t, subscription.Close())
	pm.notifyProcessExited(pid)
	_, exits := observer.snapshot()
	require.Equal(t, []libpf.PID{pid}, exits)
}

type blockingProcessObserver struct {
	started   chan struct{}
	unblock   chan struct{}
	once      sync.Once
	exited    chan libpf.PID
	syncCalls atomic.Uint64
}

func (o *blockingProcessObserver) ProcessSynchronized(ProcessEvent) {
	o.syncCalls.Add(1)
	o.once.Do(func() { close(o.started) })
	<-o.unblock
}

func (o *blockingProcessObserver) ProcessExited(pid libpf.PID) {
	o.exited <- pid
}

type fastInvalidationObserver struct {
	started     chan struct{}
	unblock     chan struct{}
	invalidated chan libpf.PID
}

func (o *fastInvalidationObserver) ProcessSynchronized(ProcessEvent) {
	close(o.started)
	<-o.unblock
}

func (o *fastInvalidationObserver) ProcessExited(libpf.PID) {}

func (o *fastInvalidationObserver) ProcessInvalidated(pid libpf.PID) {
	o.invalidated <- pid
}

func TestProcessInvalidationBypassesSlowSynchronization(t *testing.T) {
	observer := &fastInvalidationObserver{
		started:     make(chan struct{}),
		unblock:     make(chan struct{}),
		invalidated: make(chan libpf.PID, 1),
	}
	entry := newProcessObserverEntry(observer, nil)
	pid := libpf.PID(42)
	entry.enqueue(processObserverNotification{event: ProcessEvent{PID: pid}})
	<-observer.started
	entry.enqueue(processObserverNotification{event: ProcessEvent{PID: pid}, exited: true})
	select {
	case invalidated := <-observer.invalidated:
		require.Equal(t, pid, invalidated)
	case <-time.After(time.Second):
		t.Fatal("invalidation was blocked behind process synchronization")
	}
	close(observer.unblock)
	entry.close()
}

type orderedInvalidationObserver struct {
	invalidationStarted chan struct{}
	releaseInvalidation chan struct{}
	synchronized        chan struct{}
}

func (o *orderedInvalidationObserver) ProcessSynchronized(ProcessEvent) {
	close(o.synchronized)
}

func (o *orderedInvalidationObserver) ProcessExited(libpf.PID) {}

func (o *orderedInvalidationObserver) ProcessInvalidated(libpf.PID) {
	close(o.invalidationStarted)
	<-o.releaseInvalidation
}

func TestReplacementSynchronizationWaitsForFastInvalidation(t *testing.T) {
	observer := &orderedInvalidationObserver{
		invalidationStarted: make(chan struct{}),
		releaseInvalidation: make(chan struct{}),
		synchronized:        make(chan struct{}),
	}
	entry := newProcessObserverEntry(observer, nil)
	entry.enqueue(processObserverNotification{event: ProcessEvent{
		PID: 42, ImageChanged: true,
	}})
	<-observer.invalidationStarted
	select {
	case <-observer.synchronized:
		t.Fatal("replacement synchronization ran before invalidation completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(observer.releaseInvalidation)
	select {
	case <-observer.synchronized:
	case <-time.After(time.Second):
		t.Fatal("replacement synchronization did not run after invalidation")
	}
	entry.close()
}

func TestProcessObserverDeliveryDoesNotBlockAndCoalescesByPID(t *testing.T) {
	pm := &ProcessManager{}
	observer := &blockingProcessObserver{
		started: make(chan struct{}),
		unblock: make(chan struct{}),
		exited:  make(chan libpf.PID, 1),
	}
	subscription, err := pm.SubscribeProcessObserver(observer)
	require.NoError(t, err)

	pid := libpf.PID(42)
	pm.notifyProcessSynchronized(ProcessEvent{PID: pid})
	require.Eventually(t, func() bool {
		select {
		case <-observer.started:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)

	// These notifications must not wait for the blocked callback. The exit
	// supersedes the pending synchronization for the same PID.
	pm.notifyProcessSynchronized(ProcessEvent{PID: pid, Identity: ProcessIdentity{StartTime: 2}})
	pm.notifyProcessExited(pid)
	close(observer.unblock)
	select {
	case exited := <-observer.exited:
		require.Equal(t, pid, exited)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for coalesced exit")
	}
	require.NoError(t, subscription.Close())
	require.Equal(t, uint64(1), observer.syncCalls.Load())
}

type orderedBlockingObserver struct {
	started   chan struct{}
	unblock   chan struct{}
	once      sync.Once
	delivered chan ProcessEvent
}

func (o *orderedBlockingObserver) ProcessSynchronized(event ProcessEvent) {
	blocked := false
	o.once.Do(func() {
		blocked = true
		close(o.started)
	})
	if blocked {
		<-o.unblock
	}
	o.delivered <- event
}

func (*orderedBlockingObserver) ProcessExited(libpf.PID) {}

func TestProcessObserverCoalescingPreservesImageInvalidation(t *testing.T) {
	pm := &ProcessManager{}
	observer := &orderedBlockingObserver{
		started: make(chan struct{}), unblock: make(chan struct{}),
		delivered: make(chan ProcessEvent, 2),
	}
	subscription, err := pm.SubscribeProcessObserver(observer)
	require.NoError(t, err)
	pm.notifyProcessSynchronized(ProcessEvent{PID: 1})
	<-observer.started

	identity := ProcessIdentity{StartTime: 1}
	pm.notifyProcessSynchronized(ProcessEvent{PID: 42, Identity: identity, ImageChanged: true})
	pm.notifyProcessSynchronized(ProcessEvent{PID: 42, Identity: identity})
	close(observer.unblock)

	first := <-observer.delivered
	second := <-observer.delivered
	require.Equal(t, libpf.PID(1), first.PID)
	require.Equal(t, libpf.PID(42), second.PID)
	require.True(t, second.ImageChanged)
	require.NoError(t, subscription.Close())
}

func TestSubscribeProcessObserverExcludesExitingPIDs(t *testing.T) {
	pid := libpf.PID(42)
	pm := &ProcessManager{
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {observerMappings: []process.RawMapping{{Path: "/bin/server"}}},
		},
		exitEvents: map[libpf.PID]times.KTime{pid: 1},
	}
	observer := &recordingProcessObserver{}
	subscription, err := pm.SubscribeProcessObserver(observer)
	require.NoError(t, err)
	require.NoError(t, subscription.Close())
	events, _ := observer.snapshot()
	require.Empty(t, events)
}

func TestSubscribeProcessObserverSkipsSnapshotInvalidatedByExec(t *testing.T) {
	pid := libpf.PID(42)
	pm := &ProcessManager{
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {
				identity:         ProcessIdentity{StartTime: 1},
				observerMappings: []process.RawMapping{{Path: "/bin/server", Inode: 7}},
			},
		},
	}
	pm.MarkProcessExec(pid)
	observer := &recordingProcessObserver{}
	subscription, err := pm.SubscribeProcessObserver(observer)
	require.NoError(t, err)
	require.NoError(t, subscription.Close())
	events, _ := observer.snapshot()
	require.Empty(t, events)
}

func TestSubscribeProcessObserverRejectsNil(t *testing.T) {
	pm := &ProcessManager{}
	_, err := pm.SubscribeProcessObserver(nil)
	require.ErrorContains(t, err, "nil")
}

func TestSynchronizeProcessPublishesExecutableRawMappings(t *testing.T) {
	pid := libpf.PID(os.Getpid())
	elfCache, err := freelru.New[util.OnDiskFileIdentifier, elfInfo](16,
		util.OnDiskFileIdentifier.Hash32)
	require.NoError(t, err)
	pm := &ProcessManager{
		ebpf:             &testEbpfHandler{},
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: make(map[libpf.PID]*processInfo),
		exitEvents:       make(map[libpf.PID]times.KTime),
		elfInfoCache:     elfCache,
	}
	observer := &recordingProcessObserver{}
	_, err = pm.SubscribeProcessObserver(observer)
	require.NoError(t, err)

	wanted := process.RawMapping{
		Vaddr: 0x1000, Length: 0x1000, Flags: elf.PF_R | elf.PF_X,
		Device: 1, Inode: 2, Path: "/container/bin/server",
	}
	inspectionTID := pid + 1
	pm.SynchronizeProcess(&testProcess{pid: pid, tid: inspectionTID, mappings: []process.RawMapping{
		wanted,
		{Vaddr: 0x3000, Length: 0x1000, Flags: elf.PF_R | elf.PF_W,
			Device: 1, Inode: 2, Path: "/container/bin/server"},
	}})

	require.Eventually(t, func() bool {
		events, _ := observer.snapshot()
		return len(events) == 1
	}, time.Second, time.Millisecond)
	events, _ := observer.snapshot()
	require.Equal(t, []process.RawMapping{wanted}, events[0].Mappings)
	require.Equal(t, inspectionTID, events[0].TID)
	require.True(t, events[0].Identity.Valid())

	// The explicit exec generation detects same-inode, same-address-space exec
	// even when /proc identity fields happen to remain unchanged.
	pm.MarkProcessExec(pid)
	pm.SynchronizeProcess(&testProcess{pid: pid, tid: inspectionTID,
		mappings: []process.RawMapping{wanted}})
	require.Eventually(t, func() bool {
		events, _ := observer.snapshot()
		return len(events) == 2
	}, time.Second, time.Millisecond)
	events, _ = observer.snapshot()
	require.True(t, events[1].ImageChanged)
}

func TestSynchronizationIdentityRaceInvalidatesPublishedState(t *testing.T) {
	pid := libpf.PID(42)
	handler := &testEbpfHandler{}
	observer := &recordingProcessObserver{}
	entry := newProcessObserverEntry(observer, nil)
	defer entry.close()
	pm := &ProcessManager{
		ebpf: handler,
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {
				execGeneration:   3,
				observerTID:      43,
				observerMappings: []process.RawMapping{{Path: "/bin/old", Inode: 7}},
			},
		},
		processObservers: map[uint64]*processObserverEntry{1: entry},
	}

	pm.invalidateSynchronizationRace(pid, 3)
	info := pm.pidToProcessInfo[pid]
	require.Equal(t, uint64(4), info.execGeneration)
	require.Zero(t, info.observerTID)
	require.Empty(t, info.observerMappings)
	require.Equal(t, []libpf.PID{pid}, handler.deletedPidInformation)
	require.Equal(t, []libpf.PID{pid}, handler.removedReportedPIDs)
	require.Eventually(t, func() bool {
		_, exits := observer.snapshot()
		return len(exits) == 1
	}, time.Second, time.Millisecond)
}

func TestReadProcessIdentityIsStableAndValid(t *testing.T) {
	pid := libpf.PID(os.Getpid())
	first, err := ReadProcessIdentity(pid)
	require.NoError(t, err)
	second, err := ReadProcessIdentity(pid)
	require.NoError(t, err)
	require.True(t, first.Valid())
	require.Equal(t, first, second)
}
