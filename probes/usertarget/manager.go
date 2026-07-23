// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usertarget // import "go.opentelemetry.io/ebpf-profiler/probes/usertarget"

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

var (
	errObjectMismatch    = errors.New("mapped object does not match target")
	errLinkLimit         = errors.New("userspace target link limit reached")
	errReconcileCanceled = errors.New("userspace target reconciliation cancelled")
)

type probeAttachError struct {
	err error
}

func (e *probeAttachError) Error() string { return e.err.Error() }
func (e *probeAttachError) Unwrap() error { return e.err }

type probeCleanupError struct {
	err error
}

func (e *probeCleanupError) Error() string { return e.err.Error() }
func (e *probeCleanupError) Unwrap() error { return e.err }

// Programs are attached at every resolved target point. Return is attached
// before Entry so activation cannot create state with no completion path.
type Programs struct {
	Entry  *ebpf.Program
	Return *ebpf.Program
}

// Options configures process lifecycle handling for a target manager.
type Options struct {
	// ResetProcess clears probe-private state for an exited, execed, or reused
	// PID. It must be idempotent.
	ResetProcess func(libpf.PID) error
}

// Stats is a cumulative target-manager snapshot.
type Stats struct {
	ResolutionFailures uint64
	AttachFailures     uint64
	LinksAttached      uint64
	LinksDetached      uint64
	LinkLimitHits      uint64
	CleanupFailures    uint64
	ActiveProcesses    uint64
	ActiveLinks        uint64
}

type objectKey struct {
	device uint64
	inode  uint64
}

type attachmentObjectKey struct {
	pid      libpf.PID
	identity tracer.ProcessIdentity
	object   objectKey
}

type attachmentKey struct {
	attachmentObjectKey
	offset uint64
}

type attachmentSet struct {
	links  []link.Link
	source string
}

type newAttachment struct {
	offset uint64
	set    attachmentSet
}

type managerCounters struct {
	resolutionFailures atomic.Uint64
	attachFailures     atomic.Uint64
	linksAttached      atomic.Uint64
	linksDetached      atomic.Uint64
	linkLimitHits      atomic.Uint64
	cleanupFailures    atomic.Uint64
	activeProcesses    atomic.Uint64
	activeLinks        atomic.Uint64
}

type objectAttachFunc func(tracer.ProcessEvent, process.RawMapping, Target,
	Programs, uint32, map[uint64]struct{}, func() bool) ([]newAttachment, error)

// Manager reconciles bounded PID-scoped uprobe links against process mapping
// snapshots. Manager is safe for observer callbacks and concurrent Close.
type Manager struct {
	mu sync.Mutex

	target   Target
	programs Programs
	options  Options

	attachments        map[attachmentKey]attachmentSet
	completeObjects    map[attachmentObjectKey]struct{}
	processes          map[libpf.PID]tracer.ProcessIdentity
	inflight           map[libpf.PID]uint64
	nextReconcileToken uint64
	subscription       io.Closer
	metricSubscription io.Closer
	closed             bool
	started            bool

	attachObject  objectAttachFunc
	counters      managerCounters
	collectMu     sync.Mutex
	lastCollected Stats
}

// New validates a runtime target descriptor and creates an unattached manager.
func New(target Target, programs Programs, options Options) (*Manager, error) {
	validated, err := target.validated()
	if err != nil {
		return nil, err
	}
	if programs.Entry == nil && programs.Return == nil {
		return nil, errors.New("userspace target has no eBPF program")
	}
	return &Manager{
		target:          validated,
		programs:        programs,
		options:         options,
		attachments:     make(map[attachmentKey]attachmentSet),
		completeObjects: make(map[attachmentObjectKey]struct{}),
		processes:       make(map[libpf.PID]tracer.ProcessIdentity),
		inflight:        make(map[libpf.PID]uint64),
		attachObject:    attachResolvedObject,
	}, nil
}

// Start subscribes to process updates and returns a dynamic link handle. It is
// valid when no matching process currently exists; future mapping events create
// the concrete uprobe links. Start may be called at most once. A concurrent
// Close causes Start to roll back both subscriptions.
func (m *Manager) Start(ctx *tracer.ProbeContext) (link.Link, error) {
	if ctx == nil {
		return nil, errors.New("userspace target probe context is nil")
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("userspace target manager is closed")
	}
	if m.started {
		m.mu.Unlock()
		return nil, errors.New("userspace target manager is already started")
	}
	m.started = true
	m.mu.Unlock()

	metricSubscription, err := ctx.RegisterMetricsCollector(m.collectMetrics)
	if err != nil {
		m.mu.Lock()
		m.started = false
		m.mu.Unlock()
		return nil, err
	}
	subscription, err := ctx.ObserveProcesses(m)
	if err != nil {
		_ = metricSubscription.Close()
		m.mu.Lock()
		m.started = false
		m.mu.Unlock()
		return nil, err
	}
	m.mu.Lock()
	if m.closed {
		m.started = false
		m.mu.Unlock()
		_ = subscription.Close()
		_ = metricSubscription.Close()
		return nil, errors.New("userspace target manager closed while starting")
	}
	m.subscription = subscription
	m.metricSubscription = metricSubscription
	m.mu.Unlock()
	return &managedLink{manager: m}, nil
}

func processMetaMatches(meta process.ProcessMeta, selector ProcessSelector) bool {
	if selector.ExecutableName != "" &&
		strings.TrimSpace(meta.Name.String()) != selector.ExecutableName {
		return false
	}
	if selector.ExecutablePath != "" &&
		meta.Executable.String() != selector.ExecutablePath {
		return false
	}
	return true
}

func processMatches(event tracer.ProcessEvent, selector ProcessSelector) bool {
	return processMetaMatches(event.Meta, selector)
}

func mappingMatches(mapping process.RawMapping, selector ObjectSelector) bool {
	if !mapping.IsExecutable() || !mapping.IsFileBacked() {
		return false
	}
	if selector.Basename != "" && path.Base(mapping.Path) != selector.Basename {
		return false
	}
	if selector.Path != "" && mapping.Path != selector.Path {
		return false
	}
	return true
}

func processIdentityCurrent(event tracer.ProcessEvent) bool {
	if !event.Identity.Valid() {
		return false
	}
	current, err := tracer.ReadProcessIdentity(event.PID)
	return err == nil && current == event.Identity
}

func requiredLinks(programs Programs) uint32 {
	var count uint32
	if programs.Return != nil {
		count++
	}
	if programs.Entry != nil {
		count++
	}
	return count
}

func (m *Manager) resetProcess(pid libpf.PID) {
	if m.options.ResetProcess == nil {
		return
	}
	if err := m.options.ResetProcess(pid); err != nil {
		m.counters.cleanupFailures.Add(1)
		log.Errorf("Failed to reset userspace probe target %q for PID %d: %v",
			m.target.Name, pid, err)
	}
}

func closeAttachment(set attachmentSet) (closed uint64, err error) {
	var errs []error
	for index := len(set.links) - 1; index >= 0; index-- {
		if closeErr := set.links[index].Close(); closeErr != nil {
			errs = append(errs, closeErr)
		}
		// close(2) errors do not make the descriptor safe to retry; ownership
		// ends after Close is invoked, while the error remains observable.
		closed++
	}
	return closed, errors.Join(errs...)
}

func subtract(counter *atomic.Uint64, value uint64) {
	if value > 0 {
		counter.Add(^uint64(value - 1))
	}
}

func (m *Manager) removeProcessAttachments(pid libpf.PID) {
	for key, set := range m.attachments {
		if key.pid != pid {
			continue
		}
		closed, err := closeAttachment(set)
		m.counters.linksDetached.Add(closed)
		subtract(&m.counters.activeLinks, closed)
		if err != nil {
			m.counters.cleanupFailures.Add(1)
			log.Errorf("Failed to detach userspace probe target %q from PID %d: %v",
				m.target.Name, pid, err)
		}
		delete(m.attachments, key)
	}
	for key := range m.completeObjects {
		if key.pid == pid {
			delete(m.completeObjects, key)
		}
	}
	if _, exists := m.processes[pid]; exists {
		delete(m.processes, pid)
		subtract(&m.counters.activeProcesses, 1)
	}
}

func (m *Manager) hasProcessAttachments(pid libpf.PID) bool {
	for key := range m.attachments {
		if key.pid == pid {
			return true
		}
	}
	return false
}

func (m *Manager) invalidateProcessLocked(pid libpf.PID) {
	delete(m.inflight, pid)
	_, tracked := m.processes[pid]
	if !tracked && !m.hasProcessAttachments(pid) {
		return
	}
	m.removeProcessAttachments(pid)
	m.resetProcess(pid)
}

// ProcessInvalidated cancels stale resolution on an observer-owned fast
// invalidation worker. It may run concurrently with ProcessSynchronized.
func (m *Manager) ProcessInvalidated(pid libpf.PID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		delete(m.inflight, pid)
		return
	}
	m.invalidateProcessLocked(pid)
}

// ProcessExited implements tracer.ProcessObserver.
func (m *Manager) ProcessExited(pid libpf.PID) {
	m.ProcessInvalidated(pid)
}

func (m *Manager) reconciliationCurrent(pid libpf.PID, token uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && m.inflight[pid] == token
}

func (m *Manager) recordFailure(event tracer.ProcessEvent, mapping process.RawMapping, err error) {
	if err == nil {
		return
	}
	cancelled := errors.Is(err, errReconcileCanceled)
	if errors.Is(err, errLinkLimit) {
		m.counters.linkLimitHits.Add(1)
	}
	var attachErr *probeAttachError
	hasAttachError := errors.As(err, &attachErr)
	if hasAttachError {
		m.counters.attachFailures.Add(1)
	}
	var cleanupErr *probeCleanupError
	if errors.As(err, &cleanupErr) {
		m.counters.cleanupFailures.Add(1)
		if cancelled {
			log.Errorf("Failed to clean up cancelled userspace probe target %q for PID %d: %v",
				m.target.Name, event.PID, cleanupErr)
		}
	}
	if !cancelled && !errors.Is(err, errObjectMismatch) && !errors.Is(err, errLinkLimit) &&
		!hasAttachError && cleanupErr == nil {
		m.counters.resolutionFailures.Add(1)
	}
	if !cancelled && !errors.Is(err, errObjectMismatch) {
		log.Debugf("Failed to attach userspace probe target %q for PID %d mapping %q: %v",
			m.target.Name, event.PID, mapping.Path, err)
	}
}

func (m *Manager) closeUncommitted(pid libpf.PID, attached []newAttachment) {
	if len(attached) == 0 {
		return
	}
	for _, item := range attached {
		count := uint64(len(item.set.links))
		m.counters.linksAttached.Add(count)
		closed, err := closeAttachment(item.set)
		m.counters.linksDetached.Add(closed)
		if err != nil {
			m.counters.cleanupFailures.Add(1)
			log.Errorf("Failed to roll back stale userspace probe target %q for PID %d: %v",
				m.target.Name, pid, err)
		}
	}
	// Entry links may have fired between attachment and cancellation.
	if m.programs.Entry != nil {
		m.resetProcess(pid)
	}
}

func (m *Manager) finishProcessLocked(event tracer.ProcessEvent) {
	hasAttachments := m.hasProcessAttachments(event.PID)
	_, tracked := m.processes[event.PID]
	if hasAttachments && !tracked {
		m.processes[event.PID] = event.Identity
		m.counters.activeProcesses.Add(1)
	} else if !hasAttachments && tracked {
		delete(m.processes, event.PID)
		subtract(&m.counters.activeProcesses, 1)
		m.resetProcess(event.PID)
	}
}

// ProcessSynchronized implements tracer.ProcessObserver.
func (m *Manager) ProcessSynchronized(event tracer.ProcessEvent) {
	objects := make(map[objectKey]process.RawMapping)
	if processMatches(event, m.target.Process) {
		for _, mapping := range event.Mappings {
			if !mappingMatches(mapping, m.target.Object) {
				continue
			}
			key := objectKey{device: mapping.Device, inode: mapping.Inode}
			if _, exists := objects[key]; !exists {
				objects[key] = mapping
			}
		}
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if !processMatches(event, m.target.Process) {
		m.invalidateProcessLocked(event.PID)
		m.mu.Unlock()
		return
	}
	if previous, exists := m.processes[event.PID]; exists &&
		(previous != event.Identity || event.ImageChanged) {
		m.invalidateProcessLocked(event.PID)
	}
	m.nextReconcileToken++
	token := m.nextReconcileToken
	m.inflight[event.PID] = token

	// Remove links whose mapped inode disappeared or stopped matching.
	for key, set := range m.attachments {
		if key.pid != event.PID || key.identity != event.Identity {
			continue
		}
		if _, exists := objects[key.object]; exists {
			continue
		}
		closed, err := closeAttachment(set)
		m.counters.linksDetached.Add(closed)
		subtract(&m.counters.activeLinks, closed)
		if err != nil {
			m.counters.cleanupFailures.Add(1)
			log.Errorf("Failed to detach unmapped userspace probe target %q from PID %d: %v",
				m.target.Name, event.PID, err)
		}
		delete(m.completeObjects, key.attachmentObjectKey)
		delete(m.attachments, key)
	}

	for object, mapping := range objects {
		objectAttachment := attachmentObjectKey{
			pid: event.PID, identity: event.Identity, object: object,
		}
		if _, complete := m.completeObjects[objectAttachment]; complete {
			continue
		}
		attachedOffsets := make(map[uint64]struct{})
		for key := range m.attachments {
			if key.attachmentObjectKey == objectAttachment {
				attachedOffsets[key.offset] = struct{}{}
			}
		}

		active := m.counters.activeLinks.Load()
		available := uint32(0)
		if active < uint64(m.target.MaxLinks) {
			available = m.target.MaxLinks - uint32(active)
		}
		// Do not perform procfs opens or ELF parsing after saturation. Process
		// ownership is derived from concrete links below, so unattached matching
		// PIDs cannot grow manager state beyond the link limit.
		if available < requiredLinks(m.programs) {
			m.counters.linkLimitHits.Add(1)
			break
		}

		m.mu.Unlock()
		stillCurrent := func() bool { return m.reconciliationCurrent(event.PID, token) }
		attached, err := m.attachObject(event, mapping, m.target, m.programs,
			available, attachedOffsets, stillCurrent)
		m.mu.Lock()
		if m.closed || m.inflight[event.PID] != token || errors.Is(err, errReconcileCanceled) {
			m.closeUncommitted(event.PID, attached)
			m.recordFailure(event, mapping, err)
			if m.inflight[event.PID] == token {
				delete(m.inflight, event.PID)
			}
			m.mu.Unlock()
			return
		}
		for _, item := range attached {
			key := attachmentKey{attachmentObjectKey: objectAttachment, offset: item.offset}
			m.attachments[key] = item.set
			count := uint64(len(item.set.links))
			m.counters.linksAttached.Add(count)
			m.counters.activeLinks.Add(count)
		}
		m.recordFailure(event, mapping, err)
		if err == nil {
			m.completeObjects[objectAttachment] = struct{}{}
		}
	}

	if m.inflight[event.PID] == token {
		delete(m.inflight, event.PID)
		m.finishProcessLocked(event)
	}
	m.mu.Unlock()
}

func attachResolvedObject(event tracer.ProcessEvent, mapping process.RawMapping, target Target,
	programs Programs, available uint32, attachedOffsets map[uint64]struct{},
	stillCurrent func() bool,
) ([]newAttachment, error) {
	if !stillCurrent() || !processIdentityCurrent(event) {
		return nil, errReconcileCanceled
	}
	var attached []newAttachment
	var attachErrors []error
	err := withResolvedMapping(event, mapping, target,
		func(executable *link.Executable, points []resolvedPoint, _ string) error {
			linksPerPoint := requiredLinks(programs)
			for _, point := range points {
				if !stillCurrent() || !processIdentityCurrent(event) {
					attachErrors = append(attachErrors, errReconcileCanceled)
					break
				}
				if _, exists := attachedOffsets[point.fileOffset]; exists {
					continue
				}
				if available < linksPerPoint {
					attachErrors = append(attachErrors, errLinkLimit)
					break
				}
				options := &link.UprobeOptions{Address: point.fileOffset, PID: int(event.PID)}
				set := attachmentSet{source: point.source}
				if programs.Return != nil {
					returnLink, err := executable.Uretprobe("", programs.Return, options)
					if err != nil {
						attachErrors = append(attachErrors, &probeAttachError{err: fmt.Errorf("attach return at %#x (%s): %w",
							point.fileOffset, point.source, err)})
						continue
					}
					set.links = append(set.links, returnLink)
				}
				if programs.Entry != nil {
					if !stillCurrent() || !processIdentityCurrent(event) {
						_, cleanupErr := closeAttachment(set)
						attachErrors = append(attachErrors, errReconcileCanceled)
						if cleanupErr != nil {
							attachErrors = append(attachErrors, &probeCleanupError{
								err: fmt.Errorf("rollback cancelled return probe: %w", cleanupErr),
							})
						}
						break
					}
					entryLink, err := executable.Uprobe("", programs.Entry, options)
					if err != nil {
						_, cleanupErr := closeAttachment(set)
						attachErr := &probeAttachError{err: fmt.Errorf("attach entry at %#x (%s): %w",
							point.fileOffset, point.source, err)}
						if cleanupErr != nil {
							attachErrors = append(attachErrors, errors.Join(attachErr,
								&probeCleanupError{err: fmt.Errorf("rollback return probe: %w", cleanupErr)}))
						} else {
							attachErrors = append(attachErrors, attachErr)
						}
						continue
					}
					set.links = append(set.links, entryLink)
				}
				available -= linksPerPoint
				attached = append(attached, newAttachment{offset: point.fileOffset, set: set})
				if !stillCurrent() || !processIdentityCurrent(event) {
					attachErrors = append(attachErrors, errReconcileCanceled)
					break
				}
			}
			return nil
		})
	if err != nil {
		attachErrors = append(attachErrors, err)
	}
	return attached, errors.Join(attachErrors...)
}

// Snapshot returns cumulative lifecycle counters and current gauges.
func (m *Manager) Snapshot() Stats {
	return Stats{
		ResolutionFailures: m.counters.resolutionFailures.Load(),
		AttachFailures:     m.counters.attachFailures.Load(),
		LinksAttached:      m.counters.linksAttached.Load(),
		LinksDetached:      m.counters.linksDetached.Load(),
		LinkLimitHits:      m.counters.linkLimitHits.Load(),
		CleanupFailures:    m.counters.cleanupFailures.Load(),
		ActiveProcesses:    m.counters.activeProcesses.Load(),
		ActiveLinks:        m.counters.activeLinks.Load(),
	}
}

func metricDelta(current, previous uint64) metrics.MetricValue {
	return metrics.MetricValue(current - previous)
}

func (m *Manager) collectMetrics() []metrics.Metric {
	m.collectMu.Lock()
	defer m.collectMu.Unlock()
	current := m.Snapshot()
	previous := m.lastCollected
	m.lastCollected = current
	return []metrics.Metric{
		{ID: metrics.IDUserspaceProbeResolutionFailures,
			Value: metricDelta(current.ResolutionFailures, previous.ResolutionFailures)},
		{ID: metrics.IDUserspaceProbeAttachFailures,
			Value: metricDelta(current.AttachFailures, previous.AttachFailures)},
		{ID: metrics.IDUserspaceProbeLinksAttached,
			Value: metricDelta(current.LinksAttached, previous.LinksAttached)},
		{ID: metrics.IDUserspaceProbeLinksDetached,
			Value: metricDelta(current.LinksDetached, previous.LinksDetached)},
		{ID: metrics.IDUserspaceProbeLinkLimitHits,
			Value: metricDelta(current.LinkLimitHits, previous.LinkLimitHits)},
		{ID: metrics.IDUserspaceProbeCleanupFailures,
			Value: metricDelta(current.CleanupFailures, previous.CleanupFailures)},
		{ID: metrics.IDUserspaceProbeActiveProcesses,
			Value: metrics.MetricValue(current.ActiveProcesses)},
		{ID: metrics.IDUserspaceProbeActiveLinks,
			Value: metrics.MetricValue(current.ActiveLinks)},
	}
}

// Close unsubscribes from process events, detaches every concrete link, and
// invokes process cleanup once per currently matched PID.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	// Publish closure in the same critical section that captures subscriptions.
	// A concurrent Start either stores its subscriptions before this point (and
	// they are captured here), or observes closed and closes its local handles.
	m.closed = true
	subscription := m.subscription
	metricSubscription := m.metricSubscription
	m.subscription = nil
	m.metricSubscription = nil
	m.mu.Unlock()

	// Subscription close serializes with in-flight callbacks. Do this without
	// m.mu to avoid lock inversion with ProcessManager's observer mutex.
	var errs []error
	if subscription != nil {
		if err := subscription.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	m.mu.Lock()
	for pid := range m.processes {
		m.removeProcessAttachments(pid)
		m.resetProcess(pid)
	}
	m.mu.Unlock()

	// Keep metrics registered through final detach/reset accounting, then retain
	// the last counter deltas even if no periodic collection runs before close.
	if metricSubscription != nil {
		var err error
		if finalizer, ok := metricSubscription.(finalMetricSubscription); ok {
			err = finalizer.CloseWithMetrics(m.collectMetrics())
		} else {
			err = metricSubscription.Close()
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type finalMetricSubscription interface {
	CloseWithMetrics([]metrics.Metric) error
}

type managedLink struct {
	link.Link
	manager *Manager
}

func (l *managedLink) Close() error {
	return l.manager.Close()
}

func (l *managedLink) Detach() error {
	return l.manager.Close()
}

func (l *managedLink) Update(*ebpf.Program) error {
	return link.ErrNotSupported
}

func (l *managedLink) Pin(string) error {
	return link.ErrNotSupported
}

func (l *managedLink) Unpin() error {
	return link.ErrNotSupported
}

func (l *managedLink) Info() (*link.Info, error) {
	return nil, link.ErrNotSupported
}
