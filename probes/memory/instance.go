// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package memory // import "go.opentelemetry.io/ebpf-profiler/probes/memory"

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// Instance owns the live process-scoped memory hook links for one PID.
type Instance struct {
	pid libpf.PID

	// SynchronizeProcess and process-exit cleanup can race. mu serializes link
	// reconciliation and teardown without requiring ProcessManager.mu.
	mu sync.Mutex

	applicabilityEvaluated bool
	eligible               bool
	attached               map[AttachmentKey]AttachedHook

	// injectionAttempted makes destructive mutation at most once per process.
	// A failed injection is never retried automatically.
	injectionAttempted bool
	injectionResult    InjectionResult
	injectionErr       error
}

type desiredEntry struct {
	vaddr  uint64
	length uint64
	hook   resolvedHook
}

// NewInstance creates an empty process-local memory probe instance.
func NewInstance(pid libpf.PID) *Instance {
	return &Instance{pid: pid, attached: make(map[AttachmentKey]AttachedHook)}
}

// NumAttached returns the number of live links.
func (inst *Instance) NumAttached() int {
	if inst == nil {
		return 0
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return len(inst.attached)
}

// HasEvent reports whether at least one hook for event is attached.
func (inst *Instance) HasEvent(event EventKind) bool {
	if inst == nil {
		return false
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	for key := range inst.attached {
		if key.Event == event {
			return true
		}
	}
	return false
}

// Applicability reports whether this process has been evaluated against the
// configured process-executable selectors and whether it matched.
func (inst *Instance) Applicability() (evaluated, eligible bool) {
	if inst == nil {
		return false, false
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return inst.applicabilityEvaluated, inst.eligible
}

func (inst *Instance) setApplicability(eligible bool) {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	inst.applicabilityEvaluated = true
	inst.eligible = eligible
}

func (inst *Instance) beginInjection() bool {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.injectionAttempted {
		return false
	}
	inst.injectionAttempted = true
	return true
}

func (inst *Instance) completeInjection(result InjectionResult, err error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	inst.injectionResult = result
	inst.injectionErr = err
}

// Reconcile discovers the hooks currently exposed by pid's executable mappings,
// attaches newly desired links, and detaches links whose mappings disappeared.
func (m *Manager) Reconcile(
	pid libpf.PID,
	pr process.Process,
	inst *Instance,
) (*Instance, error) {
	if inst == nil {
		inst = NewInstance(pid)
	}

	eligible, err := m.matchesProcess(pr)
	if err != nil {
		return inst, err
	}
	inst.setApplicability(eligible)
	if !eligible {
		return inst, inst.Detach()
	}

	desired := make(map[AttachmentKey]desiredEntry)
	failedFiles := make(map[util.OnDiskFileIdentifier]struct{})
	var scanErrs []error
	_, iterErr := pr.IterateMappings(func(mapping process.RawMapping) bool {
		if !mapping.IsExecutable() || mapping.IsAnonymous() {
			return true
		}
		fileID := mapping.GetOnDiskFileIdentifier()
		hooks, err := m.scanMapping(pr, &mapping)
		if err != nil {
			// Preserve existing links for a file we could not inspect. A
			// transient map_files/read failure is not evidence that its hooks
			// disappeared.
			failedFiles[fileID] = struct{}{}
			scanErrs = append(scanErrs, fmt.Errorf("scan mapping %#x-%#x: %w",
				mapping.Vaddr, mapping.Vaddr+mapping.Length, err))
			return true
		}
		for _, hook := range hooks {
			key := AttachmentKey{
				PID: pid, FileID: fileID, Event: hook.Event,
				HookID: hook.HookID, Offset: hook.Location,
			}
			desired[key] = desiredEntry{
				vaddr: mapping.Vaddr, length: mapping.Length, hook: hook,
			}
		}
		return true
	})
	if iterErr != nil && !errors.Is(iterErr, process.ErrCallbackStopped) {
		// A partial mapping view must never detach existing links.
		scanErrs = append(scanErrs, fmt.Errorf("iterate mappings: %w", iterErr))
		return inst, errors.Join(scanErrs...)
	}

	allocationHookDiscovered := false
	for key := range desired {
		if key.Event == EventAllocation {
			allocationHookDiscovered = true
			break
		}
	}

	inst.mu.Lock()
	var detachErrs []error
	numDetached := 0
	for key, attached := range inst.attached {
		if _, keep := desired[key]; keep {
			continue
		}
		if _, scanFailed := failedFiles[key.FileID]; scanFailed {
			continue
		}
		if err := closeLinks(attached.Links); err != nil {
			detachErrs = append(detachErrs, fmt.Errorf("detach %v: %w", key, err))
		}
		delete(inst.attached, key)
		numDetached++
	}

	var attachErrs []error
	numAttached := 0
	for key, entry := range desired {
		if _, exists := inst.attached[key]; exists {
			continue
		}
		mapping := &process.RawMapping{Vaddr: entry.vaddr, Length: entry.length}
		links, err := m.attach(pid, mapping, entry.hook)
		if err != nil {
			attachErrs = append(attachErrs, fmt.Errorf("attach %v: %w", key, err))
			continue
		}
		inst.attached[key] = AttachedHook{Key: key, Links: links}
		numAttached++
	}

	hasAllocation := false
	for key := range inst.attached {
		if key.Event == EventAllocation {
			hasAllocation = true
			break
		}
	}
	liveAttachments := len(inst.attached)
	inst.mu.Unlock()

	if numAttached > 0 || numDetached > 0 {
		log.Debugf("memory probes pid=%d live=%d (+%d,-%d)",
			pid, liveAttachments, numAttached, numDetached)
	}

	var injectionErr error
	if m.injector != nil && !allocationHookDiscovered && !hasAllocation && inst.beginInjection() {
		// This permanently mutates the target. It is reachable only through an
		// explicitly selected experimental mode and is never retried implicitly.
		result, err := m.injector.Inject(pid)
		inst.completeInjection(result, err)
		if err != nil {
			injectionErr = fmt.Errorf("experimental allocator injection pid=%d: %w", pid, err)
		} else {
			log.Warnf("EXPERIMENTAL allocator injection mutated pid=%d: %s", pid, result)
		}
	}

	allErrs := append(append(scanErrs, detachErrs...), attachErrs...)
	allErrs = append(allErrs, injectionErr)
	return inst, errors.Join(allErrs...)
}

// Detach closes every live attachment for this PID.
func (inst *Instance) Detach() error {
	if inst == nil {
		return nil
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()

	var errs []error
	for key, attached := range inst.attached {
		if err := closeLinks(attached.Links); err != nil {
			errs = append(errs, fmt.Errorf("close %v: %w", key, err))
		}
		delete(inst.attached, key)
	}
	return errors.Join(errs...)
}

func closeLinks(links []link.Link) error {
	var errs []error
	for _, attached := range links {
		if attached != nil {
			errs = append(errs, attached.Close())
		}
	}
	return errors.Join(errs...)
}
