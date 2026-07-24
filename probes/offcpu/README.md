# Off-CPU time probe

`offcpu` measures **how long** each stack was off CPU. Like the built-in
`off_cpu` profile, each emitted event is weighted by elapsed nanoseconds rather
than count one. It follows the classic `offcputime` model (Gregg, *BPF
Performance Tools*, Ch06): the departure time of every thread is recorded as it is
switched out, and when the thread is switched back in the elapsed nanoseconds
are attributed to the stack that blocked. Samples carry the measured duration
(`off_cpu_time` / nanoseconds), so aggregation by stack yields total wait
time — the flame graph answers "where does wall-clock time go while blocked".

## Hook points

- `tracepoint/sched/sched_switch` runs in the outgoing thread's context and
  records only a timestamp keyed by `pid_tgid`. It runs on every context
  switch, so it does nothing else.
- `kprobe/finish_task_switch` runs in the incoming thread's context right
  after the scheduler restored its registers. At this point the kernel stack
  is still the blocking path (`…→schedule→finish_task_switch`) and the user
  state is unchanged since the thread went off CPU, so the unwind through the
  shared kprobe unwinder chain observes exactly the stack that was waiting.
  Optimized symbol variants (`finish_task_switch.isra.0`) are resolved by
  prefix from kallsyms, mirroring the built-in off-CPU hook. The program that
  calls `collect_trace` must be a kprobe: tail calls into the kprobe unwinder
  program array require matching program types, which is why the measurement
  side cannot be a tracepoint.

## Semantics

- Duration covers **all** off-CPU time: blocking on I/O, locks, timers, and
  also runqueue wait after involuntary preemption. Every sample carries a
  **`thread.state` label** with the thread's state at switch-out so the two
  populations separate cleanly: `interruptible`/`uninterruptible`/`parked`/
  `idle`/… mean the thread blocked voluntarily, while `running` (entered the
  scheduler while still runnable, e.g. `cond_resched`/yield) and `preempted`
  (descheduled involuntarily) mean the thread was denied CPU by saturation.
  Filter `thread.state` out of `{running, preempted}` for pure blocking
  analysis, or onto them to quantify CPU pressure.
- The `prev_state` layout is validated by parsing the sched_switch
  **tracepoint format file** (`/sys/kernel/tracing/events/sched/sched_switch/format`,
  debugfs fallback) before direct context access is enabled. Regular tracepoint
  contexts require direct field access (`bpf_probe_read_kernel` may fail on
  them), so the supported 64-bit x86_64/aarch64 layout must report offset 32,
  size 8. A mismatch logs and continues without the label; durations are
  unaffected. Values use the post-4.14 `task_state_index` encoding;
  unrecognized encodings collapse to `other` to bound label cardinality.
- `min_duration` and `sample_rate` are applied at **switch-in**, after the
  duration is known. Each retained duration is exact. At `sample_rate=1`, all
  qualifying waits are retained; lower rates can drop qualifying waits and are
  not inverse-probability scaled. Unlike built-in entry sampling, duration
  filtering never rejects a wait before knowing its length. `min_duration` is
  the primary volume control. The safe default is 1ms; explicitly setting 0s
  requests exhaustive capture and may overwhelm busy hosts.
- The switch-out map is a **global LRU hash** (`max_entries`, default 64Ki):
  the pending set is every sleeping thread in the system, and a thread that
  exits while off CPU leaks its entry (its final switch-out happens after
  every exit tracepoint, so there is no deterministic cleanup hook). LRU
  recycles leaked and coldest entries under pressure; the threads evicted
  first are those sleeping longest. Unlike the built-in `sched_times` map it
  is not per-CPU, so a thread that blocks on one CPU and wakes on another is
  still measured.
- Idle (pid 0) is never tracked. Kernel threads are measured and produce
  kernel-only stacks.

## Comparison with the built-in off-CPU profiling

| | built-in (`off-cpu-threshold`) | this probe |
|---|---|---|
| sample value | exact selected interval duration (ns) | exact selected interval duration (ns) |
| decision point | random sample at switch-out | duration filter, then sample at switch-in |
| long waits | missed with probability 1-p | all retained at sample_rate=1 after min_duration |
| CPU migration | lost (per-CPU LRU map) | measured (global LRU map) |
| duration filter | none | `min_duration` |
| drop accounting | none | per-path metrics |
| thread state | not captured | `thread.state` sample label |
| activation | static flag at startup | dynamic `custom_probes` entry |

## Configuration

Enabled as a custom probe named `off_cpu_time`:

```yaml
custom_probes:
  off_cpu_time:
    min_duration: 1ms   # emit only waits at least this long (default 1ms)
    sample_rate: 0.25   # sample qualifying wakeups (default 1.0)
    max_entries: 65536  # pending switch-out states (default 64Ki)
```

The sample type is fixed (`off_cpu_time`, nanoseconds) rather than
descriptor-supplied so downstream duration classification cannot drift.

## Overhead

The switch-out program adds one hash update to every context switch and the
switch-in program one lookup+delete; this is the unavoidable cost of exact
durations (identical to `offcputime`). Unwinds are bounded by
`min_duration`/`sample_rate`. On busy hosts prefer raising `min_duration`
over lowering `sample_rate`: it suppresses the huge population of micro-waits
while keeping every meaningful stall.

## Metrics

`agent.off_cpu_time.switch_outs`, `.switch_ins`, `.switch_ins.unmatched`,
`.filtered`, `.emitted`, `.state.update_failures`, and
`.metrics.read_failures` account for every event and drop path.
