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

typedef struct LockWaitStart {
  u64 timestamp;
  EntryFrameState entry_frame;
} LockWaitStart;

// State is private to one runtime descriptor, so pid_tgid is sufficient to
// distinguish callers without requiring attach cookies. The entry frame
// snapshot lets selected returns report the measured function as the leaf
// frame with its true caller chain, which a uretprobe context cannot recover.
struct lock_wait_starts_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64); // pid_tgid
  __type(value, LockWaitStart);
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

  LockWaitStart start = {
    .timestamp = bpf_ktime_get_ns(),
  };
#if defined(__x86_64__)
  if (ctx->cs != __USER32_CS) {
    start.entry_frame.pc = ctx->ip;
    start.entry_frame.sp = ctx->sp;
    start.entry_frame.fp = ctx->bp;
    u64 return_address   = 0;
    // At function entry the return address is on the stack. It must be read
    // here: the return-probe trampoline consumes the slot before the exit
    // program runs. A failed read leaves ra 0 and selects caller-only stacks.
    if (bpf_probe_read_user(&return_address, sizeof(return_address), (void *)ctx->sp) == 0) {
      start.entry_frame.ra = return_address;
    }
  }
#elif defined(__aarch64__)
  if (!(ctx->pstate & PSR_MODE32_BIT)) {
    start.entry_frame.pc = normalize_pac_ptr(ctx->pc);
    start.entry_frame.sp = ctx->sp;
    start.entry_frame.fp = ctx->regs[29];
    start.entry_frame.ra = normalize_pac_ptr(ctx->regs[30]);
  }
#else
  #error "Unsupported architecture"
#endif
  if (bpf_map_update_elem(&lock_wait_starts, &pid_tgid, &start, BPF_NOEXIST) != 0) {
    // Nested calls on one thread are exceptional. Pay the additional lookup
    // and replacement only on that path, preserving the newer timestamp.
    if (
      bpf_map_lookup_elem(&lock_wait_starts, &pid_tgid) != NULL &&
      bpf_map_update_elem(&lock_wait_starts, &pid_tgid, &start, BPF_EXIST) == 0) {
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

  LockWaitStart *stored = bpf_map_lookup_elem(&lock_wait_starts, &pid_tgid);
  if (!stored) {
    if (metrics) {
      metrics->unmatched_returns++;
    }
    return 0;
  }

  // Copy the small snapshot before deleting the map entry.
  LockWaitStart start = *stored;
  if (bpf_map_delete_elem(&lock_wait_starts, &pid_tgid) == 0 && metrics) {
    metrics->active_states--;
  }

  if (
    timestamp < start.timestamp || timestamp - start.timestamp < lock_wait_min_ns ||
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
  return collect_trace_with_entry_frame(
    ctx,
    lock_wait_origin,
    pid,
    tid,
    timestamp,
    timestamp - start.timestamp,
    start.entry_frame.ra ? &start.entry_frame : NULL);
}
