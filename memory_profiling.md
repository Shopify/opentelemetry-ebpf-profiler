# Memory Profiling Prototype

## Scope

Memory profiling is the first typed custom probe. It separates:

1. **event semantics** — allocation is `(pointer, size, unbiased byte weight)` and deallocation is `(pointer)`;
2. **source adapters** — producer-weighted USDT, producer-weighted function entry, or paired allocator entry/return probes;
3. **attachment** — process-scoped links resolved from executable mappings; and
4. **reporting** — `alloc_space` / `alloc_objects`, with live profiles remaining a separate opt-in.

`probes/probeconfig.Config` is consumed directly by `tracer.Config`. Prophiler and the
standalone agent construct this config themselves; running an OpenTelemetry Collector is
not required. Collector YAML is only an additional configuration frontend.

## Hook adapters

### Producer-weighted allocation

A sampled producer can expose all allocation data at one hook point:

```c
allocation(void *pointer, uint64_t size, uint64_t weight);
```

`weight` is the unbiased estimate of represented allocation bytes. The defaults consume
`ddheap:alloc` and `ddheap:free`, but the provider and probe names are configurable. A raw
function-entry uprobe can explicitly select `abi: weighted_allocation` in YAML.

Producer-side sampling is the preferred production path. Only sampled events trap into the
kernel, so a lightweight allocator/runtime integration or `LD_PRELOAD` sampler can perform
hot-path sampling in userspace and fire a USDT for selected allocations.

### Direct allocator instrumentation

A raw allocation uprobe defaults to the `malloc` adapter:

```c
void *malloc(size_t size);
```

One logical hook atomically owns two PID-scoped links:

1. an entry uprobe reads `size`, makes a byte-proportional sampling decision, and stores
   sampled `{size, weight}` state by PID/TID;
2. a return uprobe reads the returned pointer, consumes pending state, and emits the typed
   allocation event.

For allocations smaller than `sampling_interval_bytes`, sampling probability is
`size / interval` and sampled byte weight is `interval`. Larger allocations are always
sampled with their actual size. `alloc_objects` is derived as `weight / size`.

**Overhead warning:** sampling occurs after the entry breakpoint. Direct allocator uprobes
therefore trap on every matching `malloc` entry and return; live mode also traps on every
`free`. Sampling reduces unwind/export work but not breakpoint frequency. This adapter is
intended for short, explicitly enabled diagnostic sessions
until producer-side sampling is available.

The first prototype supports malloc-like `(size) -> pointer` functions and `free(pointer)`.
`calloc`, `realloc`, `posix_memalign`, C++ `new/delete`, nested allocator calls, and custom
argument layouts require explicit follow-up adapters rather than implicit ABI guessing.

## Configuration

The typed configuration can be supplied by Prophiler, the standalone daemon, or collector
YAML. This example enables both alternatives so different processes can expose different
hooks:

```yaml
probes:
  memory:
    enabled: true
    live: false
    sampling_interval_bytes: 524288
    max_entries_per_pid: 10000
    process_executables: [ruby*, tarantool]
    allocation_hooks:
      - type: usdt
        provider: ddheap
        name: alloc
      - type: uprobe
        executable: libc.so.6
        symbol: malloc
      - type: uprobe
        abi: weighted_allocation
        executable: libcustom_sampler*.so
        symbol: record_sampled_allocation
    deallocation_hooks:
      - type: usdt
        provider: ddheap
        name: free
      - type: uprobe
        executable: libc.so.6
        symbol: free
```

The daemon/Prophiler flag forms are:

```text
--heap-profiling
--heap-sampling-interval-bytes=524288
--heap-process-executable=ruby*
--heap-allocation-hook=usdt:ddheap:alloc
--heap-allocation-hook=uprobe:libc.so.6:malloc
--live-heap-profiling
--heap-deallocation-hook=uprobe:libc.so.6:free
--live-heap-max-entries-per-pid=10000
```

Compact allocation hook defaults are event-aware:

- `usdt:<provider>:<name>` → `weighted_allocation`;
- `uprobe:<executable-pattern>:<symbol>` → paired `malloc` entry/return;
- any deallocation hook → `free(pointer)` entry.

Direct allocator hooks require at least one `process_executables` selector, preventing an
accidental host-wide attachment to every process mapping libc. A literal `*` remains an
explicit operator opt-in to host-wide attachment.

A non-empty hook list replaces the default for that event. Patterns containing `/` match
the full mapping path; other patterns match its basename. Linux paths containing `:` are
supported by splitting a uprobe specification at its final colon.

## Attachment lifecycle

- Attach per process (`UprobeOptions.PID`) rather than globally per binary.
- Resolve files through `/proc/<pid>/map_files/<start>-<end>` so target mount namespaces
  and deleted/replaced files work.
- Discover USDT notes and `.symtab`/`.dynsym` symbols, converting ELF virtual addresses to
  file offsets before attachment.
- Cache parsed ELF metadata by on-disk file identity. Raw-only configurations reject
  unrelated mapping paths before parsing ELF files.
- Reconcile on every `SynchronizeProcess` and periodically retry PIDs missing a required
  event, so late `dlopen` libraries are discovered.
- Treat multiple hooks for one event as runtime alternatives: one attached allocation hook
  is sufficient; live mode additionally requires one deallocation hook.
- Attach both sides of a malloc adapter atomically, return side first. If either fails, close
  the partial link set and retry later.
- Preserve existing links through transient mapping-read failures, and close all links on
  process exit or profiler shutdown.
- Do not use attach cookies: perf-event BPF-link cookies require Linux 5.15, while the
  profiler supports Linux 5.10.

## eBPF footprint

- All memory-only maps and programs are skipped when memory profiling is disabled.
- Producer-weighted mode does not load direct-allocator pending-state or sampling maps.
- Direct allocator mode uses an LRU pending-call map containing sampled calls only and a
  one-entry sampling configuration map.
- Allocation-only mode minimizes verifier-required live-heap maps to one entry and never
  populates them.
- Free programs and deallocation links are loaded only for live mode.

## Reporting decisions

Allocation events fan out as sibling OTLP profiles:

- `alloc_space / bytes` uses the unbiased byte weight;
- `alloc_objects / count` uses `weight / allocation_size`.

Live heap remains a separate opt-in and is not production-ready until object weighting,
metadata, PID-reuse cleanup, and backend repeated-snapshot aggregation semantics are fixed.

Kernel `mmap`/`brk`/`munmap` instrumentation may later provide a distinct low-overhead
virtual-memory-growth profile. It cannot replace allocator profiling because most small
allocations and frees are satisfied entirely inside userspace arenas.

## Next producer and probe work

A lightweight `LD_PRELOAD` producer can interpose allocator functions, make the same
byte-proportional sampling decision in userspace, track sampled pointers for live mode, and
fire the configurable weighted USDT ABI. That removes per-call breakpoint overhead while
keeping the profiler-side event contract runtime-neutral.

After the memory prototype, extend the same typed configuration and process/mapping
lifecycle to bpftrace-like network and disk latency probes, including stateful entry/return
correlation where required.
