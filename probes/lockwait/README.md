# Runtime lock-wait latency probes

`lockwait` combines the process-aware `usertarget` attachment manager with a
bounded entry/return latency state machine. The profiler contains no database-
or lock-library-specific symbol table: process selectors, object selectors,
symbol aliases or build-ID offsets, labels, and return-value ABI policy arrive
in the runtime descriptor.

## Semantics

- Duration begins at target entry and ends at the matching return on the same
  thread. It therefore includes spinning, sleeping, and scheduler delay inside
  the target.
- An empty `SuccessfulReturnValues` list accepts any return and is appropriate
  for `void` targets. A non-empty list emits only exact ABI return values (for
  example, `0` and Linux `EOWNERDEAD` for a robust pthread acquisition).
  `ReturnValueMode` selects full 64-bit, signed 32-bit, or unsigned 32-bit
  normalization of the architecture return register.
- `min_duration` and `sample_rate` are applied at return. Sampling reduces
  unwinding and export work, but **does not reduce uprobe traps or entry state
  updates**.
- In-flight state is a bounded hash map keyed by `pid_tgid`. Exec, process exit,
  PID reuse, and target invalidation remove matching state. A nested entry on
  one thread replaces the previous timestamp and is counted as an overwrite.
- Symbol aliases may be supplied as fallbacks, but at most one distinct offset
  may resolve in each mapped object. Use separate instances only for distinct,
  non-nesting points; probing a wrapper and its implementation together would
  double-count their overlapping wait.
- Descriptor labels are the low-cardinality `lock.kind`, `lock.mode`, and
  `lock.operation`. Lock addresses are neither captured nor exported.

This state machine is for synchronous same-thread acquisition functions. It
must not be reused to infer held time, cross-thread release, reader ownership,
recursive depth, or condition-variable release/reacquisition.

## Initial Yugabyte descriptor

The first intended deployment target is the contention-only C++ function
`base::SpinLock::SlowLock()`:

```go
lockwait.Definition{
    Target: usertarget.Target{
        Name:             "yb-base-spinlock-slow-lock",
        Process:          usertarget.ProcessSelector{ExecutableName: "yb-server"},
        Object:           usertarget.ObjectSelector{Basename: "yb-server"},
        SymbolCandidates: []string{"_ZN4base8SpinLock8SlowLockEv"},
    },
    Labels: lockwait.Labels{
        Kind: "spinlock", Mode: "exclusive", Operation: "lock",
    },
    ABI: lockwait.ABI{}, // void return: accept every return value
}
```

Deployments should additionally pin a validated executable path and/or build ID
where workload identity matters. Validate each deployed ELF before enabling it:

```sh
readelf -n /path/to/yb-server | grep 'Build ID'
readelf -Ws /path/to/yb-server | grep '_ZN4base8SpinLock8SlowLockEv'
```

If the symbol table is unavailable, use a build-ID-scoped `Offsets` point whose
executable file offset was derived from that exact artifact. Probing `SlowLock`
observes only contended acquisitions; probing public `pthread_mutex_lock` entry
points remains a deployment decision and is disabled by default because eBPF
sampling cannot reduce their trap frequency.

## Deployment and rollback

Enable descriptors gradually and watch `agent.userspace_probe.*` together with
`agent.lock_wait.*`; update failures should remain zero and active state should
stay well below `max_entries`. To roll back, remove the descriptor and restart
(or otherwise close the enabled probe through the embedding application). Probe
close detaches its PID-scoped links, clears private state, and preserves final
counter deltas. No persistent state or data migration is involved.
