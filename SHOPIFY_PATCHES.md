# Shopify Carried Patches (`shopify/omnibus-2026-11`)

- **Upstream base**: `open-telemetry/opentelemetry-ebpf-profiler@d6c326c2bba5c2f8bd0e0ffa1265abe12dd11c55`
- **Previous production pin**: `Shopify/opentelemetry-ebpf-profiler@3d8d33c9340baa2cf2a68bb603598551c48232e0` (32 commits above upstream `2c951531`)
- **Dropped from previous fork carry**: Native TLS thread context (`#60`/`#62`) — superseded by upstream `#1869` + `#2004`; redundant arm64 `bpf_user_pt_regs_t` typedefs — superseded by upstream `#1877`.

## Carried Layers

### 1. LuaJIT Interpreter Unwinder & Symbolizer
- **Why**: Upstream closed the full Parca LuaJIT unwinder PR (`open-telemetry/opentelemetry-ebpf-profiler#1236`) and has only merged the offset extractor (`#1648`) and JIT mapping sync skeleton (`#1929`). Shopify profiles OpenResty/nginx and statically-linked LuaJIT hosts (Tarantool) in production.
- **Commits**:
  1. `luajit: add full LuaJIT interpreter unwinder and symbolizer` — eBPF unwinder (`support/ebpf/luajit_tracer.ebpf.c`), bytecode/proto/trace symbolizer (`interpreter/luajit/`), register/state plumbing (`types.h`, `tracemgmt.h`, `native_stack_trace.h`), and LuaJIT error codes (`tools/errors-codegen/errors.json`). Adapted to upstream `#1910` (`-Wsign-conversion`/`-Wshorten-64-to-32`), `#1929` (`regionKey`, `LUAJIT_JIT_MARKER`), and `#2124` (`SEC("multi/unwind_luajit")`).
  2. `luajit: support statically-linked hosts, jit_base extraction, and cframe handback` — configurable `Config.Executables`, `lj_vm_asm_begin` `.symtab` anchoring, independent `g2jitbase` extraction from `lj_vm_exit_handler` (for Tarantool's `mem_L` layout), interval-derived interpreter cframe unwind (`cframe_size_interp`/`interp_fp`), x86 JIT cframe (`interp + 16`), and end-of-stack native handback for interpreter frames.
  3. `luajit,coredump,testutils: add coredump -luajit-executables flag and integration test harness` — `tools/coredump` `-luajit-executables` flag and `luajit_procs` lookup, `testutils/helpers.go`, `tools/dis2go.py`, and LuaJIT integration test fixtures.

### 2. Ruby Shopify Specifics (pshopify 4.0.6 + Ruby 4.1.x + ZJIT)
- **Why**: Upstream Ruby support currently caps at `< 4.1.0` and does not recognize Shopify's transitional `4.0.5-pshopify3` build (revision `21a2595676`, which carries both 4.0.6 `master_box`/`rb_thread_sched` shifts) or Ruby 4.1.x + ZJIT.
- **Commit**: `ruby: detect pshopify 4.0.6 layout and add Ruby 4.1.x + ZJIT unwinding` — `ruby_description` revision detection (`d5946e5a`), Ruby 4.1.x VM layout (per-ractor GC objspace, 5-bit `IMEMO_MASK_41`, TypedData global symbol directory, derived `base_label`, reordered `classext`), and ZJIT unwinding via `rb_zjit_entry` (`10aa8105`, `9ea07f72`, `b54f66ae`). Adapted to upstream `#1983` (`bool is_ruby_41`).

### 3. PMU `perf_event` Direct Collect Trampoline
- **Why**: Prophiler's PMU probe attaches hardware/software `perf_event_open` counters directly with `PERF_EVENT_IOC_SET_BPF` and reports `ctx->sample_period` as the sample value without an intermediate BPF program (`ext_probe_value`). Upstream's `perf_event__external` is a tail-call target reading from `ext_probe_value`.
- **Commit**: `probes: add perf_event direct collect trampoline for external PMU probes` — `sample_period`/`addr` + static assertions in `support/ebpf/kernel.h`, `SEC("perf_event/direct") int perf_event__direct` in `support/ebpf/generic_probe.ebpf.c`, `ProbeContext.RegisterPerfEventCollectTrampoline`, and unit/integration tests adapted to `#1915`/`#2054`/`#2118`.

### 4. Live-Heap Profiling (Upstream `#1747`) + Snapshot Metadata Fix
- **Why**: Upstream live-heap profiling (`open-telemetry/opentelemetry-ebpf-profiler#1747` @ `3ac7cd77`) is still open in draft while all its prerequisites (`#1915`, `#2014`, `#2015`, `#2054`, `#2118`, `#2119`) have landed on `upstream/main`.
- **Commits**:
  1. `probes/heap: add live (in-use) heap profiling (rebased upstream #1747)` — `uprobe_heap_free` using upstream `#2014` SDT arg decoding (`usdt_args.h`), probe-owned live-heap correlation maps, `Tracker`, `TraceHandlerHooks` via `OriginEntry` (`#2054`), and `ProbeContext.ProcessMeta` (`#2015`).
  2. `reporter: preserve ExtraSampleAttrProd metadata on snapshot rows` — upstreamable fix ensuring `baseReporter.mergeSnapshots` calls `ExtraSampleAttrProd.CollectExtraSampleMeta` with full process metadata so `inuse_space`/`inuse_objects` snapshot rows retain Prophiler's Kubernetes attributes (`k8s.pod.name`, `k8s.namespace.name`, `k8s.container.name`, `process.linux.cgroup`).

### 5. Thread Context OTEP 4947 `"tls_v1"` Compatibility (Upstream PR Candidate)
- **Why**: Upstream `process/processcontext/threadlabels.go` still checks only the pre-merge `threadlocal.schema_version = "tlsdesc_v1_dev"`, whereas merged OTEP 4947 and Shopify's publishers (`observe-instrument#1141`, `observe-profiling`, `profiles-processor#1443`) publish `"tls_v1"`.
- **Commit**: `processcontext: accept OTEP 4947 threadlocal.schema_version "tls_v1"` — accepts both `"tls_v1"` and `"tlsdesc_v1_dev"` in `readThreadContextInfo` with unit test coverage (Go-only; upstream PR candidate).

### 6. Generated Artifacts
- **Commit**: `build: regenerate support types, error headers, and eBPF blobs` — regenerated in Linux/Docker (`otel/opentelemetry-ebpf-profiler-dev`) via `make generate` and `make -C support/ebpf amd64 arm64`. Never hand-edit `support/types.go`, `support/ebpf/errors.h`, or `support/ebpf/tracer.ebpf.{amd64,arm64}`.
