# Per-stack hardware counters

## Overview

Per-stack counters add hardware work estimates to the existing software
CPU-clock stack samples without adding hardware-PMU sampling interrupts. Enable
the base mode with either configuration form:

- CLI: `--enable-per-sample-counters`
- collector configuration: `enable_per_sample_counters: true`

The base mode reads cycles and instructions. Additional prototype counters are
additive and opt-in:

- CLI: `--per-sample-extra-counters=topdown`
- collector configuration: `per_sample_extra_counters: topdown`

Multiple extras can be comma-separated, for example
`--per-sample-extra-counters=branch-misses,topdown`.

The extra-counter list defaults to empty, so existing
`--enable-per-sample-counters` behavior remains cycles and instructions only.
Unknown names are rejected. Extras require the base mode, but each extra set
fails independently after startup validation.

For every selected CPU, userspace opens readable, non-sampling perf events and
installs their file descriptors in `BPF_MAP_TYPE_PERF_EVENT_ARRAY` maps indexed
by CPU. The software CPU-clock BPF entry program reads the available counters
and carries their deltas on its normal `Trace` record. The deltas are payload on
the software-clock origin; they are not new interrupt sources and do not
receive fabricated BPF origin IDs.

The result is statistical attribution: work performed on a CPU between two
software-clock interrupts is attributed to the stack sampled at the latter
interrupt. It is useful for per-stack hardware ratios, but it is not exact task
accounting.

## Configuration and constraints

This mode requires software CPU-clock sampling and rejects either hardware
sampling trigger at the same time:

- `enable_sw_cpu_clock` must be `true`;
- `enable_hw_cpu_cycles` must be `false`; and
- `enable_hw_instructions` must be `false`.

This prevents trigger-mode sample counts from being confused or double-counted
with delta-mode values. `--enable-branch-sampling` remains a cycles-trigger
feature for collecting LBR/BRS branch records and is therefore outside this
mode. The `branch-misses` extra is different: it is a readable counting event
and does not collect branch records.

PMU availability is deliberately not a startup requirement. Cycles and
instructions are installed as one base transaction. Branch misses and Top-Down
are separate transactions, so failure of either extra leaves all previously
working counter sets in place. A setup failure logs one warning and profiling
continues. BPF reads are enabled only after all selected-CPU file descriptors
for that set have been installed.

A failed BPF helper read invalidates that counter's baseline so a later success
does not bridge the missing interval into an unrelated stack. An optional
counter set that becomes BPF-unreadable is disabled on the affected CPU, and a
periodic status check emits one clear warning while other counters continue.

## Events

### Base counters

The base mode opens independent `PERF_TYPE_HARDWARE` events for:

- `PERF_COUNT_HW_CPU_CYCLES`
- `PERF_COUNT_HW_INSTRUCTIONS`

### Branch misses

The `branch-misses` extra opens
`PERF_TYPE_HARDWARE/PERF_COUNT_HW_BRANCH_MISSES`. It is one additional readable
event and one additional sibling profile. Unsupported or constrained PMUs fail
soft without removing cycles or instructions.

### Intel Top-Down prototype

The `topdown` extra resolves CPU-model-specific aliases from the CPU PMU sysfs
surface instead of hard-coding raw encodings:

- `slots` (group leader)
- `topdown-retiring`
- `topdown-bad-spec`
- `topdown-fe-bound`
- `topdown-be-bound`

Each alias is parsed with the matching `/sys/bus/event_source/devices/cpu/type`
and `format/*` definitions. On Intel CPUs with architectural Top-Down support,
SLOTS is fixed counter 3 and the four category events are PERF_METRICS pseudo
events. The kernel requires SLOTS to lead the group and each category member to
use `PERF_FORMAT_GROUP`; the prototype follows those constraints and installs
every member FD in its own BPF perf-event-array map.

The kernel converts each PERF_METRICS fraction into an accumulated category
count using SLOTS. The profiler exports the four category deltas as raw slots;
the SLOTS leader is read for group accounting and failure detection but is not
exported as another sibling. Ratios must be computed after aggregation, for
example:

```text
total = sum(topdown_retiring) + sum(topdown_bad_spec) +
        sum(topdown_fe_bound) + sum(topdown_be_bound)
retiring_ratio = sum(topdown_retiring) / total
```

The same total applies to bad speculation, frontend bound, and backend bound.
Computing a ratio per sample and then averaging it would be incorrect.

There is an important experimental caveat: kernels may allow userspace group
reads while rejecting `bpf_perf_event_read_value()` on PERF_METRICS group
members. BPF also reads the five file descriptors sequentially rather than as
one atomic userspace group read, so successful values may have a small amount
of intra-sample skew. The first helper failure disables only Top-Down on the
affected CPU and produces one warning; branch misses and cycles/instructions
continue. An absent Top-Down sibling for the whole payload therefore means the
prototype was unavailable, not that every category measured zero.

If PERF_METRICS members are not BPF-readable, a possible follow-up is a
CPU-model-specific four-general-purpose-event approximation: collect retired
slots, frontend starvation, speculative waste, and total slots, then derive
backend bound as the residual. That fallback consumes four scarce programmable
counters and is intentionally documented in code rather than silently used by
this prototype.

Hybrid systems that expose only `cpu_core`/`cpu_atom` PMUs rather than the
`cpu` sysfs PMU currently fail soft. Live PMU and hybrid-PMU selection are
separate validation/follow-up work.

## Delta and multiplex scaling semantics

The BPF program stores the previous `{value, enabled, running}` reading in a
per-CPU map. For each readable counter it computes:

```text
raw_delta     = value_now   - value_previous
enabled_delta = enabled_now - enabled_previous
running_delta = running_now - running_previous
scaled_delta  = floor(raw_delta * enabled_delta / running_delta)
```

`enabled_delta / running_delta` compensates for perf multiplexing. A first
reading, a failed read, a reset/non-monotonic reading, or `running_delta == 0`
produces no delta. A successful reading becomes the next baseline. The common
multiplication path is exact. Before multiplying, BPF checks for `u64` overflow;
its exceptional fallback divides first, saturates an overflowing integral
result, and omits an unsafe fractional multiplication instead of wrapping.

Independently scheduled cycles, instructions, and branch misses can run during
different multiplexing windows, so ratios such as IPC or branch-miss rate are
estimates. The Top-Down events are opened as one constrained group to preserve
the category/slots relationship if the kernel permits BPF member reads.

## Wire and reporter representation

`Trace` carries seven hardware-counter `u64` fields:

- `cycles_delta`
- `instructions_delta`
- `branch_misses_delta`
- `topdown_retiring_delta`
- `topdown_bad_spec_delta`
- `topdown_fe_bound_delta`
- `topdown_be_bound_delta`

Userspace preserves them through `support.Trace`, `libpf.EbpfTrace`, and the
symbolized `libpf.Trace`. They remain attached to the software-clock event while
the reporter derives export-only profile types through `TypeMetadata`.

The pinned `profiles/v1development` v0.4.0 model gives a `Profile` one singular
`SampleType`; it cannot represent pprof-style correlated values on one profile
sample. The reporter therefore emits sibling profiles in one OTLP `Profiles`
message. Counter siblings retain period type/unit `cpu`/`nanoseconds`, because
the stack observation cadence is the software CPU-clock trigger. Deltas are
summed per sample identity over the reporting window and emitted in aggregate
shape. Stacks whose summed delta is zero are omitted from that sibling.

All siblings share one `ProfilesDictionary`. The generator interns each
location sequence globally and corresponding samples use the exact same
`stack_index`. This invariant lets a processor coalesce siblings without
comparing symbolized frame text.

## Profile-type names

Software-clock samples remain:

```text
process_cpu:on_cpu-samples:count:cpu:nanoseconds
```

The sibling sample type/unit pairs are:

```text
cycles:cycles
instructions:instructions
branch_misses:branch_misses
topdown_retiring:slots
topdown_bad_spec:slots
topdown_fe_bound:slots
topdown_be_bound:slots
```

Every sibling has period `cpu:nanoseconds`. Before processor classification,
OTLP fallback names use the `unknown:` prefix, for example:

```text
unknown:branch_misses:branch_misses:cpu:nanoseconds
unknown:topdown_retiring:slots:cpu:nanoseconds
```

A processor that supports these siblings should classify them as process CPU
profiles and produce stable names such as:

```text
process_cpu:branch_misses:branch_misses:cpu:nanoseconds
process_cpu:topdown_retiring:slots:cpu:nanoseconds
process_cpu:topdown_bad_spec:slots:cpu:nanoseconds
process_cpu:topdown_fe_bound:slots:cpu:nanoseconds
process_cpu:topdown_be_bound:slots:cpu:nanoseconds
```

It can then coalesce software-clock and counter siblings from the same
resource/window by shared `stack_index`. Missing zero-delta sibling samples mean
zero for that stack; absence of an optional counter profile for an entire
payload can mean fail-soft degradation.

## Expected overhead and row cost

When the base mode is disabled, the RODATA gate lets the verifier eliminate the
counter-read branch. Perf-event-array, availability, health, and per-CPU
baseline maps remain loaded. The fixed wire ABI adds 56 bytes to every `Trace`
header for the seven exported `u64` delta fields, even when optional counters
are not requested.

With only the base mode enabled, each software-clock interrupt adds two
`bpf_perf_event_read_value()` calls and userspace holds two extra perf FDs per
selected CPU. Branch misses adds one helper call and one FD. Top-Down adds five
helper calls and five FDs, for a maximum of eight counter reads and eight FDs
per selected CPU when every option is enabled. There are no additional sampling
interrupts.

Each enabled counter type can add up to **+1x sibling sample rows** relative to
the software-clock rows for the same reporting window:

- base cycles and instructions: up to `+2x` rows;
- branch misses: up to `+1x` more;
- Top-Down: up to `+4x` more.

With all extras enabled, the payload can therefore contain the clock profile
plus seven counter profiles, and ingestion can expand to as much as `+7x`
sibling rows before coalescing. Zero-delta stacks reduce that upper bound.
Reporter stack/location dictionary storage is shared rather than duplicated.
