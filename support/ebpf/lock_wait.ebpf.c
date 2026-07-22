#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

enum LockWaitReturnMode {
  LOCK_WAIT_RETURN_64,
  LOCK_WAIT_RETURN_SIGNED_32,
  LOCK_WAIT_RETURN_UNSIGNED_32,
};

typedef struct LockWaitMetrics {
  u64 entries;
  u64 returns;
  u64 unmatched_returns;
  u64 filtered;
  u64 emitted;
  u64 state_update_failures;
  u64 state_overwrites;
  s64 active_states;
} LockWaitMetrics;

// State is private to one runtime descriptor, so pid_tgid is sufficient to
// distinguish callers without requiring attach cookies.
struct lock_wait_starts_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);   // pid_tgid
  __type(value, u64); // entry timestamp in nanoseconds
  __uint(max_entries, 16384);
} lock_wait_starts SEC(".maps");

struct lock_wait_metrics_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, LockWaitMetrics);
  __uint(max_entries, 1);
} lock_wait_metrics SEC(".maps");

BPF_RODATA_VAR(u16, lock_wait_origin, 0)
BPF_RODATA_VAR(u64, lock_wait_min_ns, 0)
BPF_RODATA_VAR(u32, lock_wait_sample_threshold, 0xffffffff)
BPF_RODATA_VAR(u32, lock_wait_return_mode, 0)
BPF_RODATA_VAR(u32, lock_wait_success_count, 0)
BPF_RODATA_VAR(s64, lock_wait_success_0, 0)
BPF_RODATA_VAR(s64, lock_wait_success_1, 0)
BPF_RODATA_VAR(s64, lock_wait_success_2, 0)
BPF_RODATA_VAR(s64, lock_wait_success_3, 0)

static EBPF_INLINE LockWaitMetrics *lock_wait_get_metrics()
{
  u32 zero = 0;
  return bpf_map_lookup_elem(&lock_wait_metrics, &zero);
}

static EBPF_INLINE s64 lock_wait_return_value(struct pt_regs *ctx)
{
  u64 raw;
#if defined(__x86_64)
  raw = ctx->ax;
#elif defined(__aarch64__)
  raw = ctx->regs[0];
#else
  #error "Unsupported architecture"
#endif
  if (lock_wait_return_mode == LOCK_WAIT_RETURN_SIGNED_32) {
    return (s64)(s32)(u32)raw;
  }
  if (lock_wait_return_mode == LOCK_WAIT_RETURN_UNSIGNED_32) {
    return (s64)(u32)raw;
  }
  return (s64)raw;
}

static EBPF_INLINE bool lock_wait_return_succeeded(struct pt_regs *ctx)
{
  if (lock_wait_success_count == 0) {
    return true;
  }

  s64 result = lock_wait_return_value(ctx);
  if (lock_wait_success_count > 0 && result == lock_wait_success_0) {
    return true;
  }
  if (lock_wait_success_count > 1 && result == lock_wait_success_1) {
    return true;
  }
  if (lock_wait_success_count > 2 && result == lock_wait_success_2) {
    return true;
  }
  if (lock_wait_success_count > 3 && result == lock_wait_success_3) {
    return true;
  }
  return false;
}

SEC("kprobe/lock_wait_entry")
int lock_wait_entry(UNUSED struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xffffffff;
  if (pid == 0 || tid == 0) {
    return 0;
  }

  LockWaitMetrics *metrics = lock_wait_get_metrics();
  if (metrics) {
    metrics->entries++;
  }

  u64 timestamp = bpf_ktime_get_ns();
  if (bpf_map_update_elem(&lock_wait_starts, &pid_tgid, &timestamp, BPF_NOEXIST) != 0) {
    // Nested calls on one thread are exceptional. Pay the additional lookup
    // and replacement only on that path, preserving the newer timestamp.
    if (
      bpf_map_lookup_elem(&lock_wait_starts, &pid_tgid) != NULL &&
      bpf_map_update_elem(&lock_wait_starts, &pid_tgid, &timestamp, BPF_EXIST) == 0) {
      if (metrics) {
        metrics->state_overwrites++;
      }
      return 0;
    }
    if (metrics) {
      metrics->state_update_failures++;
    }
    return 0;
  }
  if (metrics) {
    metrics->active_states++;
  }
  return 0;
}

SEC("kretprobe/lock_wait_exit")
int lock_wait_exit(struct pt_regs *ctx)
{
  u64 timestamp            = bpf_ktime_get_ns();
  u64 pid_tgid             = bpf_get_current_pid_tgid();
  LockWaitMetrics *metrics = lock_wait_get_metrics();
  if (metrics) {
    metrics->returns++;
  }

  u64 *start = bpf_map_lookup_elem(&lock_wait_starts, &pid_tgid);
  if (!start) {
    if (metrics) {
      metrics->unmatched_returns++;
    }
    return 0;
  }

  u64 started = *start;
  if (bpf_map_delete_elem(&lock_wait_starts, &pid_tgid) == 0 && metrics) {
    metrics->active_states--;
  }

  if (
    timestamp < started || timestamp - started < lock_wait_min_ns ||
    !lock_wait_return_succeeded(ctx) ||
    (lock_wait_sample_threshold != 0xffffffff &&
     bpf_get_prandom_u32() > lock_wait_sample_threshold)) {
    if (metrics) {
      metrics->filtered++;
    }
    return 0;
  }

  if (metrics) {
    metrics->emitted++;
  }
  u64 pid = pid_tgid >> 32;
  u64 tid = pid_tgid & 0xffffffff;
  return collect_trace(ctx, lock_wait_origin, pid, tid, timestamp, timestamp - started);
}
