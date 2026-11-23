// SPDX-License-Identifier: Apache-2.0
//
// USDT (uprobe) handlers for heap profiling.
//
// Provider:  "otel_memory" — the current provider emitted by the reference
//            sampler implementation; expected to track the eventual
//            OTel-standard memory-profiling provider name once defined.
//
// Probes:    alloc(void *user, uint64_t size, uint64_t weighted_bytes)
//            free(void *ptr)
//
// These programs are attached PID-scoped from userspace by the `probes/heap`
// package once per (process, probe site) discovered via .note.stapsdt
// scanning, using SDT argument specifications decoded into usdt_specs.

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "usdt_args.h"

// origin_id_heap_alloc and origin_id_heap_free are set during load time by
// the heap probe's Load() method via the origin registry.
BPF_RODATA_VAR(u16, origin_id_heap_alloc, 0)
BPF_RODATA_VAR(u16, origin_id_heap_free, 0)

// ─────────────────────────────────────────────────────────────────────────
// heap_live_pids: set of PIDs that have the otel_memory:free probe attached.
// Only these PIDs get entries in heap_alloc_live. Written by userspace
// during USDT attach/detach; read by uprobe_heap_alloc.
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
  __uint(max_entries, 1024);
  __type(key, u32);   // pid
  __type(value, u32); // current count
} heap_pid_alloc_count SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// heap_pid_alloc_limit: single-entry array holding one global cap value,
// applied uniformly against every PID's live count in heap_pid_alloc_count.
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
// Value: weighted_bytes: the unbiased byte estimate passed by the sampler.
//
// Written by uprobe_heap_alloc (only for PIDs in heap_live_pids),
// read+deleted by uprobe_heap_free.
// Entries for dead PIDs are deleted from userspace on process exit.
// ─────────────────────────────────────────────────────────────────────────
typedef struct {
  u32 pid;
  u32 _pad;
  u64 ptr;
} HeapAllocKey;

typedef struct {
  u64 weighted_bytes;
} HeapAllocVal;

struct heap_alloc_live_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, HeapAllocKey);
  __type(value, HeapAllocVal);
} heap_alloc_live SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// heap:alloc(user, size, weighted_bytes)
//
//   arg0 = user-visible allocation pointer
//   arg1 = allocation size in bytes
//   arg2 = weighted_bytes (unbiased byte estimate; see ADR 00003)
// ─────────────────────────────────────────────────────────────────────────
SEC("uprobe/heap_alloc")
int uprobe_heap_alloc(struct pt_regs *ctx)
{
  u32 pid          = 0;
  u32 tid          = 0;
  u64 group_leader = 0;
  if (!get_pid_tgid_leader(&pid, &tid, &group_leader)) {
    return 0;
  }

  USDTSpec *spec = bpf_usdt_spec(ctx, pid);
  if (!spec) {
    return 0;
  }

  u64 user           = 0;
  u64 size           = 0;
  u64 weighted_bytes = 0;
  if (
    bpf_usdt_arg(ctx, spec, 0, &user) || bpf_usdt_arg(ctx, spec, 1, &size) ||
    bpf_usdt_arg(ctx, spec, 2, &weighted_bytes)) {
    return 0;
  }

  DEBUG_PRINT("heap_usdt: alloc pid=%u ptr=%lx", pid, user);
  DEBUG_PRINT("heap_usdt: alloc size=%lu weighted_bytes=%lu", size, weighted_bytes);

  PerCPURecord *record =
    prepare_trace(origin_id_heap_alloc, pid, tid, group_leader, bpf_ktime_get_boot_ns());
  if (!record) {
    return 0;
  }
  // Push context values for the weighted byte value, allocation pointer,
  // and raw size. They lead variable_data, ahead of the native frames
  // unwinding appends. They are filled in once live tracking below has
  // decided whether to report the pointer.
  u64 *values = push_context_values(&record->trace, 3);
  if (!values) {
    return 0;
  }

  // unwind_trace() also reports unknown PIDs, but live tracking below needs to
  // know up front whether this trace will reach userspace.
  if (!pid_information_exists(pid)) {
    u64 pid_tgid_val = (u64)pid << 32 | tid;
    if (report_pid(ctx, pid_tgid_val, RATELIMIT_ACTION_DEFAULT)) {
      increment_metric(metricID_NumProcNew);
    }
    return 0;
  }

  // Only record in the live-heap correlation map once we know this trace
  // will actually reach userspace (past the first-sighting report_pid
  // return above) and only if this PID has the free probe attached.
  //
  // live_tracked gates the pointer context value below. If the eBPF map insert
  // fails (map full or per-PID cap), we leave the pointer zeroed so userspace won't
  // add this allocation to the live-heap Tracker.
  bool live_tracked = false;
  if (bpf_map_lookup_elem(&heap_live_pids, &pid)) {
    u32 zero_key = 0;
    u32 *limit   = bpf_map_lookup_elem(&heap_pid_alloc_limit, &zero_key);
    u32 *count   = bpf_map_lookup_elem(&heap_pid_alloc_count, &pid);

    if (limit && *limit > 0 && count && *count >= *limit) {
      // Leave live_tracked false so userspace does not retain this allocation.
    } else {
      HeapAllocKey key = {.pid = pid, .ptr = user};
      HeapAllocVal val = {.weighted_bytes = weighted_bytes};
      if (bpf_map_update_elem(&heap_alloc_live, &key, &val, BPF_NOEXIST) < 0) {
        // Could be map full or duplicate ptr (realloc without free; unusual).
        // Try overwrite for the duplicate case without bumping the per-PID count.
        if (bpf_map_update_elem(&heap_alloc_live, &key, &val, BPF_ANY) == 0) {
          live_tracked = true;
        }
      } else {
        live_tracked  = true;
        u32 new_count = count ? (*count + 1) : 1;
        bpf_map_update_elem(&heap_pid_alloc_count, &pid, &new_count, BPF_ANY);
      }
    }
  }

  values[0] = weighted_bytes;
  values[1] = live_tracked ? user : 0;
  values[2] = size;

  // Deliberately not capturing kernel frames here: this is a uprobe, so
  // the process is executing user-space code at the point of the trap, not
  // genuinely running in the kernel.
  return unwind_trace(ctx, record, false);
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
  u32 pid          = 0;
  u32 tid          = 0;
  u64 group_leader = 0;
  if (!get_pid_tgid_leader(&pid, &tid, &group_leader)) {
    return 0;
  }

  USDTSpec *spec = bpf_usdt_spec(ctx, pid);
  if (!spec) {
    return 0;
  }

  u64 ptr = 0;
  if (bpf_usdt_arg(ctx, spec, 0, &ptr)) {
    return 0;
  }

  // Fast-path: was this pointer sampled?
  HeapAllocKey key  = {.pid = pid, .ptr = ptr};
  HeapAllocVal *val = bpf_map_lookup_elem(&heap_alloc_live, &key);
  if (!val) {
    return 0;
  }

  u64 weighted_bytes = val->weighted_bytes;

  // Remove from the live map before emitting the event.
  bpf_map_delete_elem(&heap_alloc_live, &key);

  // Decrement the per-PID count.
  u32 *count = bpf_map_lookup_elem(&heap_pid_alloc_count, &pid);
  if (count && *count > 0) {
    u32 new_count = *count - 1;
    bpf_map_update_elem(&heap_pid_alloc_count, &pid, &new_count, BPF_ANY);
  }

  DEBUG_PRINT("heap_usdt: free pid=%u ptr=%lx weighted_bytes=%lu", pid, ptr, weighted_bytes);

  // Emit a minimal free event to userspace via the trace_events ringbuf.
  // No stack walk; we only need to identify which allocation was freed.
  PerCPURecord *record =
    prepare_trace(origin_id_heap_free, pid, tid, group_leader, bpf_ktime_get_boot_ns());
  if (!record) {
    return 0;
  }
  Trace *trace = &record->trace;

  // Transport the sampled weight and freed pointer as context values.
  u64 *values = push_context_values(trace, 2);
  if (!values) {
    return 0;
  }
  values[0] = weighted_bytes;
  values[1] = ptr;

  send_trace(ctx, trace);
  return 0;
}
