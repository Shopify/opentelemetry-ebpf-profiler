# Per-stack hardware counters

## Overview

Tier 2 per-stack counters add hardware work estimates to the existing software
CPU-clock stack samples without adding hardware-PMU sampling interrupts. Enable
the mode with either configuration form:

- CLI: `--enable-per-sample-counters`
- collector configuration: `enable_per_sample_counters: true`

For every selected CPU, userspace opens readable, non-sampling
`PERF_TYPE_HARDWARE` events for `PERF_COUNT_HW_CPU_CYCLES` and
`PERF_COUNT_HW_INSTRUCTIONS`. Their file descriptors are installed in two
`BPF_MAP_TYPE_PERF_EVENT_ARRAY` maps indexed by CPU. The software CPU-clock BPF
entry program reads both counters and carries the deltas on its normal `Trace`
record. The deltas are payload on the software-clock origin; they are not new
interrupt sources and do not receive fabricated BPF origin IDs.

The result is statistical attribution: work performed on a CPU between two
software-clock interrupts is attributed to the stack sampled at the latter
interrupt. It is useful for per-stack cycles, instructions, and approximate IPC,
but it is not exact task accounting.

## Configuration and v1 constraints

Version 1 requires software CPU-clock sampling to be enabled and rejects either
hardware sampling trigger at the same time:

- `enable_sw_cpu_clock` must be `true`;
- `enable_hw_cpu_cycles` must be `false`; and
- `enable_hw_instructions` must be `false`.

This prevents trigger-mode sample counts from being confused or double-counted
with delta-mode values. Branch sampling remains a cycles-trigger feature and is
therefore also outside this mode. A possible v2 can read deltas from the cycles
trigger, but it needs explicit semantics for the trigger counter itself and its
first/last interval before relaxing this exclusivity.

PMU availability is deliberately not a startup requirement. If any cycles or
instructions event cannot be opened, enabled, or installed for any selected
CPU, the profiler rolls back the complete readable-counter set, logs one warning,
and continues plain software CPU-clock profiling. This supports nodes without
PMU passthrough, including ab5-style environments.

## Delta and multiplex scaling semantics

The BPF program stores the previous `{value, enabled, running}` reading in a
per-CPU map. For each counter it computes:

```text
raw_delta     = value_now   - value_previous
enabled_delta = enabled_now - enabled_previous
running_delta = running_now - running_previous
scaled_delta  = floor(raw_delta * enabled_delta / running_delta)
```

`enabled_delta / running_delta` compensates for perf multiplexing. A first
reading, a failed read, a reset/non-monotonic reading, or `running_delta == 0`
produces no delta. The current successful reading becomes the next baseline.
The common multiplication path is exact. Before multiplying, BPF checks for
`u64` overflow; its exceptional fallback divides first, saturates an overflowing
integral result, and omits an unsafe fractional multiplication instead of
wrapping. Normal sampling intervals are many orders of magnitude below that
fallback.

## Wire and reporter representation

`Trace` carries two additional `u64` fields:

- `cycles_delta`
- `instructions_delta`

Userspace preserves them through `support.Trace`, `libpf.EbpfTrace`, and the
symbolized `libpf.Trace`. They remain attached to the software-clock event while
the reporter derives two export-only profile types through `TypeMetadata`.

The pinned `profiles/v1development` v0.4.0 model gives a `Profile` one singular
`SampleType`; it cannot represent pprof-style correlated cycle and instruction
value types on one profile sample. The reporter therefore emits sibling
profiles in one OTLP `Profiles` message:

1. the software-clock profile, unchanged;
2. a cycles profile with sample type/unit `cycles`/`cycles`; and
3. an instructions profile with sample type/unit
   `instructions`/`instructions`.

Counter siblings retain period type/unit `cpu`/`nanoseconds`, because the stack
observation cadence is the software CPU-clock trigger. Their deltas are summed
per sample identity over the reporting window and emitted in aggregate shape.
Stacks whose summed delta is zero are omitted from that sibling.

All siblings share the one `ProfilesDictionary`. The generator interns each
location sequence globally and the corresponding samples use the exact same
`stack_index`. This invariant is required for the processor to coalesce the
siblings without comparing symbolized frame text.

An upstream protocol improvement would allow correlated multi-value samples:
one stack identity and timestamp carrying multiple named values, as pprof does.
That would remove the sibling workaround while preserving the correlation.

## Profile-type names

Trigger mode and delta mode intentionally describe different quantities.
Hardware cycles *trigger mode* still counts interrupts and has:

```text
process_cpu:on_cpu-samples:count:cpu:cycles
```

Software-clock samples in this mode remain:

```text
process_cpu:on_cpu-samples:count:cpu:nanoseconds
```

The delta siblings use honest OTLP value types rather than disguising actual
hardware counts as `samples:count`:

```text
cycles:cycles with period cpu:nanoseconds
instructions:instructions with period cpu:nanoseconds
```

The current processor's fallback names for these previously unknown pairs are
therefore exactly:

```text
unknown:cycles:cycles:cpu:nanoseconds
unknown:instructions:instructions:cpu:nanoseconds
```

Processor ingestion must recognize the two pairs as process CPU profiles,
producing the stable downstream names:

```text
process_cpu:cycles:cycles:cpu:nanoseconds
process_cpu:instructions:instructions:cpu:nanoseconds
```

It must then coalesce software-clock, cycles, and instructions siblings from the
same resource/window and shared `stack_index` into one ClickHouse stack row with
a values map. Missing zero-delta sibling samples mean zero for that stack;
absence of the counter profiles for an entire payload means the profiler
degraded to software-clock-only mode.

## Expected overhead

When disabled, the RODATA gate lets the verifier eliminate the counter-read
branch; there are no perf helper calls in the sampling path. The small perf-event
array and per-CPU baseline maps remain loaded.

When enabled, each software-clock interrupt adds two
`bpf_perf_event_read_value()` calls, two per-CPU state updates, delta/scaling
arithmetic, and 16 bytes in each trace header. There are no additional sampling
interrupts. Userspace holds two extra perf file descriptors per selected CPU and
emits up to two additional profiles per resource per reporting window. Reporter
stack/location dictionary storage is shared rather than duplicated.
