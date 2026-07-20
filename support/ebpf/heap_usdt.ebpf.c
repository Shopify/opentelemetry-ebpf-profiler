// SPDX-License-Identifier: Apache-2.0
//
// Process-scoped entry handlers for memory profiling.
//
// Hook points are configured by probes/memory on the Go side. The defaults
// consume ddheap:alloc and ddheap:free USDT notes. Adapters support both a
// producer-weighted entry ABI and standard malloc/free function ABIs:
//
//   allocation(void *user, uint64_t size, uint64_t weight)
//   malloc(size) -> user; deallocation(void *ptr)
//
// Links are PID-scoped and reconciled against process mappings so late-loaded
// libraries are discovered. See memory.Manager/memory.Instance.
//
// Hook identity stays in userspace; dedicated eBPF entry programs distinguish
// allocation and deallocation without requiring attach-cookie support.
//
// v1 reads arguments and return values directly from architecture-specific
// pt_regs fields, matching the fixed producer and allocator ABIs above.
// Honouring arbitrary per-argument location descriptors from an SDT note is
// follow-up work.

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// ─────────────────────────────────────────────────────────────────────────
// heap_live_pids: set of PIDs that have a deallocation hook attached.
// Only these PIDs get entries in heap_alloc_live. Written by userspace
// during memory-probe reconcile; read by uprobe_heap_alloc.
// ─────────────────────────────────────────────────────────────────────────
struct heap_live_pids_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);  // pid
  __type(value, u8); // dummy
} heap_live_pids SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// heap_pid_alloc_count: per-PID count of entries currently in
// heap_alloc_live. Used to enforce per-process caps.
// ─────────────────────────────────────────────────────────────────────────
struct heap_pid_alloc_count_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024); // same as heap_live_pids
  __type(key, u32);          // pid
  __type(value, u32);        // current count
} heap_pid_alloc_count SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// heap_pid_alloc_limit: single-entry array holding one global cap value,
// applied uniformly against every PID's live count in heap_pid_alloc_count
// (i.e. "the limit that is applied per PID", not a per-PID map of limits).
// Written by userspace at startup. If 0, per-PID limiting is disabled.
// ─────────────────────────────────────────────────────────────────────────
struct heap_pid_alloc_limit_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);   // always 0
  __type(value, u32); // the limit
} heap_pid_alloc_limit SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// heap_alloc_live: correlation map for live-heap tracking.
//
// Key:   (pid, ptr): uniquely identifies a sampled allocation.
// Value: weight:     the unbiased weight passed by the sampler.
//
// Written by uprobe_heap_alloc (only for PIDs in heap_live_pids),
// read+deleted by uprobe_heap_free.
// Entries for dead PIDs are batch-deleted from userspace on process exit.
// ─────────────────────────────────────────────────────────────────────────
typedef struct {
  u32 pid;
  u32 _pad;
  u64 ptr;
} HeapAllocKey;

typedef struct {
  u64 weight;
} HeapAllocVal;

struct heap_alloc_live_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, HeapAllocKey);
  __type(value, HeapAllocVal);
} heap_alloc_live SEC(".maps");

// Sampled malloc-like calls need their size preserved from function entry
// until the corresponding return probe exposes the allocation pointer. LRU
// eviction bounds state left behind by thread exit, longjmp, or unmatched
// returns. The map contains sampled calls only, not every allocator call.
typedef struct {
  u64 size;
  u64 weight;
} HeapPendingAlloc;

struct heap_pending_allocs_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, u64); // pid_tgid
  __type(value, HeapPendingAlloc);
} heap_pending_allocs SEC(".maps");

// Average allocation volume represented by a directly instrumented malloc
// sample. Written once by userspace. Producer-weighted USDT events bypass it.
struct heap_sampling_interval_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u32);
} heap_sampling_interval SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// Entry/return argument helpers
// ─────────────────────────────────────────────────────────────────────────

static EBPF_INLINE u64 usdt_arg0(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->di;
#elif defined(__aarch64__)
  return ctx->regs[0];
#else
  #error "Unsupported architecture"
#endif
}

static EBPF_INLINE u64 usdt_arg1(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->si;
#elif defined(__aarch64__)
  return ctx->regs[1];
#else
  #error "Unsupported architecture"
#endif
}

static EBPF_INLINE u64 usdt_arg2(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->dx;
#elif defined(__aarch64__)
  return ctx->regs[2];
#else
  #error "Unsupported architecture"
#endif
}

static EBPF_INLINE u64 function_return_value(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->ax;
#elif defined(__aarch64__)
  return ctx->regs[0];
#else
  #error "Unsupported architecture"
#endif
}

// ─────────────────────────────────────────────────────────────────────────
// Typed allocation event emission shared by producer-weighted USDT hooks and
// the sampled malloc entry/return adapter.
//
//   arg0 = user-visible allocation pointer
//   arg1 = allocation size in bytes
//   arg2 = weight (unbiased size estimator = nsamples * interval)
// ─────────────────────────────────────────────────────────────────────────
static EBPF_INLINE int emit_heap_alloc(struct pt_regs *ctx, u64 user, u64 size, u64 weight)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid;

  DEBUG_PRINT("heap_usdt: alloc pid=%llu ptr=%llx", pid_tgid >> 32, user);
  DEBUG_PRINT("heap_usdt: alloc size=%llu weight=%llu", size, weight);

  // We can't use collect_trace() directly: it calls get_pristine_per_cpu_record()
  // internally, which would zero out the ptr/size fields we set below, and its
  // final step is a tail_call() into the unwinder chain that does not return
  // control to us; there is no point after that call where we could still set
  // trace->ptr/trace->size before send_trace() fires at the end of the chain.
  // So we inline collect_trace()'s setup here instead, and set our extra
  // fields on the trace immediately after:
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace  = &record->trace;
  trace->origin = TRACE_HEAP_ALLOC;
  trace->pid    = pid;
  trace->tid    = tid;
  trace->ktime  = bpf_ktime_get_ns();
  trace->value  = weight;
  trace->size   = size;
  trace->ptr    = 0;
  if (bpf_get_current_comm(&(trace->comm), sizeof(trace->comm)) < 0) {
    increment_metric(metricID_ErrBPFCurrentComm);
  }

  // Deliberately not calling push_kernel_frames() here: this is a uprobe, so
  // the process is executing user-space code at the point of the trap, not
  // genuinely running in the kernel. bpf_get_stack()'s kernel-mode stack at
  // this point would just be the uprobe/int3 trap-handling machinery itself,
  // not anything the profiled application was doing; capturing it would
  // mislabel that internal noise as application kernel frames. Contrast with
  // collect_trace()'s callers (kprobes, perf_event overflow), which do fire
  // while the task is genuinely executing in the kernel.

  if (!pid_information_exists(pid)) {
    u64 pid_tgid_val = (u64)pid << 32 | tid;
    if (report_pid(ctx, pid_tgid_val, RATELIMIT_ACTION_DEFAULT)) {
      increment_metric(metricID_NumProcNew);
    }
    return 0;
  }

  // Only record in the live-heap correlation map once we know this trace
  // will actually reach userspace (past the first-sighting report_pid
  // return above); otherwise the entry would never be seen by
  // Tracker.HandleAlloc and would leak in heap_alloc_live forever, since
  // the matching free could never find and remove it either.
  //
  // Only record if this PID has the free probe attached (i.e., is in
  // heap_live_pids). Without the free probe, entries would accumulate
  // forever and starve the map.
  //
  // live_tracked gates trace->ptr below. If the eBPF map insert fails (map
  // full or per-PID cap), we leave ptr zeroed so userspace won't add this
  // allocation to the live-heap Tracker, since the free probe won't be
  // able to find it either, it would never be removed.
  bool live_tracked = false;
  if (bpf_map_lookup_elem(&heap_live_pids, &pid)) {
    // Check per-PID limit before attempting the insert.
    u32 zero_key = 0;
    u32 *limit   = bpf_map_lookup_elem(&heap_pid_alloc_limit, &zero_key);
    u32 *count   = bpf_map_lookup_elem(&heap_pid_alloc_count, &pid);

    if (limit && *limit > 0 && count && *count >= *limit) {
      increment_metric(metricID_HeapPerPIDLimitHit);
    } else {
      HeapAllocKey key = {.pid = pid, .ptr = user};
      HeapAllocVal val = {.weight = weight};
      if (bpf_map_update_elem(&heap_alloc_live, &key, &val, BPF_NOEXIST) < 0) {
        // Could be map full or duplicate ptr (realloc without free; unusual).
        // Try overwrite for the duplicate case.
        if (bpf_map_update_elem(&heap_alloc_live, &key, &val, BPF_ANY) < 0) {
          increment_metric(metricID_HeapLiveMapFull);
        } else {
          // Overwrote an existing entry (duplicate ptr): the alloc is tracked
          // but the number of live entries is unchanged, so we must NOT bump
          // the per-PID count. The matching free deletes the single entry and
          // decrements once; incrementing here would leak the count upward and
          // eventually trip the per-PID limit.
          live_tracked = true;
        }
      } else {
        // Inserted a genuinely new entry; bump the per-PID count.
        live_tracked  = true;
        u32 new_count = count ? (*count + 1) : 1;
        bpf_map_update_elem(&heap_pid_alloc_count, &pid, &new_count, BPF_ANY);
      }
    }
  }
  trace->ptr = live_tracked ? user : 0;

  int unwinder           = PROG_UNWIND_STOP;
  bool has_usermode_regs = false;
  ErrorCode error        = get_usermode_regs(ctx, &record->state, &has_usermode_regs);
  if (error || !has_usermode_regs) {
    goto exit;
  }

  error = get_next_unwinder_after_native_frame(record, &unwinder);

exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("bpf_tail call failed for %d in memory allocation probe", unwinder);
  return -1;
}

// Producer-weighted allocations expose pointer, size, and weight together at
// one entry point. This is the low-overhead path when userspace samples before
// firing the probe (the default ddheap USDT contract).
SEC("uprobe/heap_alloc")
int uprobe_heap_alloc(struct pt_regs *ctx)
{
  return emit_heap_alloc(ctx, usdt_arg0(ctx), usdt_arg1(ctx), usdt_arg2(ctx));
}

// Byte-proportional Bernoulli sampling for direct malloc instrumentation. For
// allocations smaller than the interval, p=size/interval and a sampled call
// represents `interval` bytes. Larger calls are always sampled with weight=size.
// This is unbiased for alloc_space; userspace derives alloc_objects as
// weight/size. Sampling happens after the uprobe trap and therefore reduces
// unwind/export work, but not breakpoint costs on allocator entry and return.
static EBPF_INLINE bool sample_malloc(u64 size, HeapPendingAlloc *sample)
{
  u32 zero_key  = 0;
  u32 *interval = bpf_map_lookup_elem(&heap_sampling_interval, &zero_key);
  if (!interval || *interval == 0 || size == 0) {
    return false;
  }

  sample->size = size;
  if (size >= *interval) {
    sample->weight = size;
    return true;
  }

  // size and interval are bounded by u32, so this multiplication fits u64.
  u64 threshold = (size * (1ULL << 32)) / *interval;
  if ((u64)(u32)bpf_get_prandom_u32() >= threshold) {
    return false;
  }
  sample->weight = *interval;
  return true;
}

// malloc-like entry: arg0=size. Only sampled calls occupy pending state.
SEC("uprobe/malloc_enter")
int uprobe_malloc_enter(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();

  // A nested/unmatched call must drop stale state rather than pair the wrong
  // size with a later return. Exported malloc implementations are not expected
  // to recursively call themselves, but this makes failure a safe sample drop.
  bpf_map_delete_elem(&heap_pending_allocs, &pid_tgid);

  HeapPendingAlloc sample = {};
  if (sample_malloc(usdt_arg0(ctx), &sample)) {
    bpf_map_update_elem(&heap_pending_allocs, &pid_tgid, &sample, BPF_ANY);
  }
  return 0;
}

// malloc-like return: return register=pointer. The paired entry supplied size
// and an unbiased weight. Failed allocations are discarded.
SEC("uretprobe/malloc_return")
int uretprobe_malloc_return(struct pt_regs *ctx)
{
  u64 pid_tgid              = bpf_get_current_pid_tgid();
  HeapPendingAlloc *pending = bpf_map_lookup_elem(&heap_pending_allocs, &pid_tgid);
  if (!pending) {
    return 0;
  }

  // Copy before deleting: map-value pointers are invalid after deletion.
  u64 size   = pending->size;
  u64 weight = pending->weight;
  bpf_map_delete_elem(&heap_pending_allocs, &pid_tgid);

  u64 user = function_return_value(ctx);
  if (!user) {
    return 0;
  }
  return emit_heap_alloc(ctx, user, size, weight);
}

// ─────────────────────────────────────────────────────────────────────────
// heap:free(ptr)
//
//   arg0 = pointer being freed
//
// Fast path: if the pointer is not in our sampled-allocation map, return
// immediately without any work. Hot path on every free, must stay cheap.
// ─────────────────────────────────────────────────────────────────────────
SEC("uprobe/heap_free")
int uprobe_heap_free(struct pt_regs *ctx)
{
  u64 ptr = usdt_arg0(ctx);

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid;

  // Fast-path: was this pointer sampled? This should almost always be the
  // case for a pointer that was actually sampled by the userspace library,
  // unless we dropped it from live tracking ourselves (per-PID cap or map
  // full; see uprobe_heap_alloc), in which case there is nothing to find here.
  HeapAllocKey key  = {.pid = pid, .ptr = ptr};
  HeapAllocVal *val = bpf_map_lookup_elem(&heap_alloc_live, &key);
  if (!val) {
    // Not a sampled allocation; nothing to do.
    return 0;
  }

  u64 weight = val->weight;

  // Remove from the live map before emitting the event.
  bpf_map_delete_elem(&heap_alloc_live, &key);

  // Decrement the per-PID count.
  u32 *count = bpf_map_lookup_elem(&heap_pid_alloc_count, &pid);
  if (count && *count > 0) {
    u32 new_count = *count - 1;
    bpf_map_update_elem(&heap_pid_alloc_count, &pid, &new_count, BPF_ANY);
  }

  DEBUG_PRINT("heap_usdt: free pid=%u ptr=%llx weight=%llu", pid, ptr, weight);

  // Emit a minimal free event to userspace via the trace_events ringbuf.
  // No stack walk; we only need to identify which allocation was freed.
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace             = &record->trace;
  trace->origin            = TRACE_HEAP_FREE;
  trace->pid               = pid;
  trace->tid               = tid;
  trace->ktime             = bpf_ktime_get_ns();
  trace->value             = weight;
  trace->ptr               = ptr;
  trace->num_frames        = 0;
  trace->num_kernel_frames = 0;
  trace->frame_data_len    = 0;
  if (bpf_get_current_comm(&(trace->comm), sizeof(trace->comm)) < 0) {
    increment_metric(metricID_ErrBPFCurrentComm);
  }

  send_trace(ctx, trace);
  return 0;
}
