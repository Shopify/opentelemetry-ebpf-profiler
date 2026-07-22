// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"errors"
	"io"
	"slices"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// ProcessIdentity identifies one process address-space generation. StartTime
// separates PID reuse while AddressSpace changes across exec, including a
// same-path re-exec of the same executable inode.
type ProcessIdentity struct {
	ExecutableDevice uint64
	ExecutableInode  uint64
	StartTime        uint64
	AddressSpace     uint64
}

// Valid reports whether the process identity was read successfully.
func (id ProcessIdentity) Valid() bool {
	return id.StartTime != 0
}

// ProcessEvent is an immutable snapshot published after ProcessManager has
// synchronized a process. Mappings contains executable file-backed mappings
// and owns its path strings; observers may retain the event after the callback.
type ProcessEvent struct {
	PID          libpf.PID
	TID          libpf.PID
	Identity     ProcessIdentity
	Meta         process.ProcessMeta
	Mappings     []process.RawMapping
	ImageChanged bool
}

// ProcessObserver receives serialized process mapping and lifecycle updates.
// Delivery is asynchronous and coalesced by PID so observer latency cannot
// block the PID event processor. A newer synchronization supersedes an older
// pending one; ProcessExited supersedes all pending state for that PID.
// Implementations must treat events as read-only. ProcessExited may be
// delivered more than once and must be idempotent.
//
// An observer may additionally implement ProcessInvalidated(libpf.PID). That
// method is delivered on a separate worker and may run concurrently with
// ProcessSynchronized so stale slow work can be cancelled promptly. It must be
// idempotent and safe for concurrent use.
type ProcessObserver interface {
	ProcessSynchronized(ProcessEvent)
	ProcessExited(libpf.PID)
}

type processInvalidationObserver interface {
	ProcessInvalidated(libpf.PID)
}

type processObserverNotification struct {
	event        ProcessEvent
	exited       bool
	invalidation <-chan struct{}
}

type processObserverEntry struct {
	observer    ProcessObserver
	invalidator processInvalidationObserver

	mu                  sync.Mutex
	pending             map[libpf.PID]processObserverNotification
	invalidations       map[libpf.PID]struct{}
	invalidationSignals map[libpf.PID]chan struct{}
	closed              bool
	wake                chan struct{}
	invalidate          chan struct{}
	done                chan struct{}
	wg                  sync.WaitGroup
}

func newProcessObserverEntry(observer ProcessObserver, snapshots []ProcessEvent) *processObserverEntry {
	entry := &processObserverEntry{
		observer: observer,
		pending:  make(map[libpf.PID]processObserverNotification, len(snapshots)),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	if invalidator, ok := observer.(processInvalidationObserver); ok {
		entry.invalidator = invalidator
		entry.invalidations = make(map[libpf.PID]struct{})
		entry.invalidationSignals = make(map[libpf.PID]chan struct{})
		entry.invalidate = make(chan struct{}, 1)
	}
	for _, event := range snapshots {
		entry.pending[event.PID] = processObserverNotification{event: event}
	}
	entry.wg.Add(1)
	go entry.run()
	if entry.invalidator != nil {
		entry.wg.Add(1)
		go entry.runInvalidations()
	}
	if len(snapshots) > 0 {
		entry.signal()
	}
	return entry
}

func (entry *processObserverEntry) signal() {
	select {
	case entry.wake <- struct{}{}:
	default:
	}
}

func (entry *processObserverEntry) signalInvalidation() {
	if entry.invalidator == nil {
		return
	}
	select {
	case entry.invalidate <- struct{}{}:
	default:
	}
}

func (entry *processObserverEntry) enqueue(notification processObserverNotification) {
	entry.mu.Lock()
	if entry.closed {
		entry.mu.Unlock()
		return
	}
	pid := notification.event.PID
	previous, pending := entry.pending[pid]
	if !notification.exited {
		notification.event.Mappings = slices.Clone(notification.event.Mappings)
		// Coalescing must never erase an exec/exit invalidation. A later
		// synchronized snapshot carries the newest mappings while retaining the
		// requirement for observers to reset process-scoped state.
		if pending && (previous.exited || previous.event.ImageChanged) {
			notification.event.ImageChanged = true
		}
	}
	invalidated := entry.invalidator != nil &&
		(notification.exited || notification.event.ImageChanged)
	if invalidated {
		if pending && previous.invalidation != nil {
			notification.invalidation = previous.invalidation
		} else if signal := entry.invalidationSignals[pid]; signal != nil {
			notification.invalidation = signal
		} else {
			signal := make(chan struct{})
			entry.invalidationSignals[pid] = signal
			entry.invalidations[pid] = struct{}{}
			notification.invalidation = signal
		}
	}
	entry.pending[pid] = notification
	entry.mu.Unlock()
	entry.signal()
	if invalidated {
		entry.signalInvalidation()
	}
}

func (entry *processObserverEntry) takePending() (processObserverNotification, bool) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.closed {
		return processObserverNotification{}, false
	}
	// Remove only the notification about to be delivered. Leaving other PIDs
	// in pending allows an exec/exit arriving behind a slow callback to replace
	// their older snapshots before those snapshots become in-flight.
	for pid, notification := range entry.pending {
		delete(entry.pending, pid)
		return notification, true
	}
	return processObserverNotification{}, false
}

func (entry *processObserverEntry) takeInvalidation() (libpf.PID, chan struct{}, bool) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.closed {
		return 0, nil, false
	}
	for pid := range entry.invalidations {
		delete(entry.invalidations, pid)
		return pid, entry.invalidationSignals[pid], true
	}
	return 0, nil, false
}

func (entry *processObserverEntry) waitForInvalidation(notification processObserverNotification) bool {
	if notification.invalidation == nil {
		return true
	}
	select {
	case <-notification.invalidation:
		return true
	case <-entry.done:
		return false
	}
}

func (entry *processObserverEntry) isClosed() bool {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.closed
}

func (entry *processObserverEntry) run() {
	defer entry.wg.Done()
	for {
		select {
		case <-entry.done:
			return
		case <-entry.wake:
			for {
				notification, ok := entry.takePending()
				if !ok {
					break
				}
				if entry.isClosed() {
					return
				}
				entry.deliver(notification)
			}
		}
	}
}

func (entry *processObserverEntry) runInvalidations() {
	defer entry.wg.Done()
	for {
		select {
		case <-entry.done:
			return
		case <-entry.invalidate:
			for {
				pid, signal, ok := entry.takeInvalidation()
				if !ok {
					break
				}
				entry.deliverInvalidation(pid)
				entry.mu.Lock()
				if entry.invalidationSignals[pid] == signal {
					delete(entry.invalidationSignals, pid)
				}
				entry.mu.Unlock()
				close(signal)
			}
		}
	}
}

func (entry *processObserverEntry) deliverInvalidation(pid libpf.PID) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Errorf("Process invalidation observer %T panicked: %v", entry.observer, recovered)
		}
	}()
	entry.invalidator.ProcessInvalidated(pid)
}

func (entry *processObserverEntry) deliver(notification processObserverNotification) {
	if !entry.waitForInvalidation(notification) {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Errorf("Process observer %T panicked: %v", entry.observer, recovered)
		}
	}()
	if notification.exited {
		entry.observer.ProcessExited(notification.event.PID)
		return
	}
	entry.observer.ProcessSynchronized(notification.event)
}

func (entry *processObserverEntry) close() {
	entry.mu.Lock()
	if !entry.closed {
		entry.closed = true
		clear(entry.pending)
		clear(entry.invalidations)
		clear(entry.invalidationSignals)
		close(entry.done)
	}
	entry.mu.Unlock()
	entry.wg.Wait()
}

type observerSubscription struct {
	pm   *ProcessManager
	id   uint64
	once sync.Once
}

func (s *observerSubscription) Close() error {
	if s == nil || s.pm == nil {
		return nil
	}
	s.once.Do(func() {
		s.pm.observerMu.Lock()
		entry := s.pm.processObservers[s.id]
		delete(s.pm.processObservers, s.id)
		s.pm.observerMu.Unlock()
		if entry != nil {
			entry.close()
		}
	})
	return nil
}

var _ io.Closer = (*observerSubscription)(nil)

// SubscribeProcessObserver registers observer and asynchronously publishes
// snapshots for processes already known to ProcessManager. Registration and
// notifications are serialized, so a subscriber never observes an older
// initial snapshot after a newer process update.
func (pm *ProcessManager) SubscribeProcessObserver(observer ProcessObserver) (io.Closer, error) {
	if observer == nil {
		return nil, errors.New("process observer is nil")
	}

	pm.observerMu.Lock()
	defer pm.observerMu.Unlock()

	pm.mu.RLock()
	snapshots := make([]ProcessEvent, 0, len(pm.pidToProcessInfo))
	for pid, info := range pm.pidToProcessInfo {
		if len(info.observerMappings) == 0 {
			continue
		}
		if _, exiting := pm.exitEvents[pid]; exiting {
			continue
		}
		snapshots = append(snapshots, ProcessEvent{
			PID:      pid,
			TID:      info.observerTID,
			Identity: info.identity,
			Meta:     info.meta,
			Mappings: slices.Clone(info.observerMappings),
		})
	}
	pm.mu.RUnlock()

	pm.nextObserverID++
	id := pm.nextObserverID
	if pm.processObservers == nil {
		pm.processObservers = make(map[uint64]*processObserverEntry)
	}
	pm.processObservers[id] = newProcessObserverEntry(observer, snapshots)
	return &observerSubscription{pm: pm, id: id}, nil
}

func (pm *ProcessManager) notifyProcessSynchronized(event ProcessEvent) {
	pm.observerMu.Lock()
	defer pm.observerMu.Unlock()
	for _, entry := range pm.processObservers {
		entry.enqueue(processObserverNotification{event: event})
	}
}

func (pm *ProcessManager) notifyProcessExited(pid libpf.PID) {
	pm.observerMu.Lock()
	defer pm.observerMu.Unlock()
	for _, entry := range pm.processObservers {
		entry.enqueue(processObserverNotification{
			event:  ProcessEvent{PID: pid},
			exited: true,
		})
	}
}
