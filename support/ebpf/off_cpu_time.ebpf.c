// Off-CPU time probe: measures how long each stack was off CPU.
//
// This follows the classic offcputime model (Gregg, BPF Performance Tools,
// Ch06 offcputime.bt): when a thread leaves the CPU its departure time is
// recorded, and when it is switched back in the elapsed nanoseconds are
// attributed to the stack that blocked. The switch-in unwind observes the
// blocking stack: the kernel stack still contains the path that entered the
// scheduler (…→schedule→finish_task_switch) and the user state is unchanged
// since the thread went off CPU.
//
// It intentionally differs from the built-in off-CPU support (off_cpu.ebpf.c)
// by following the exit-filtered latency-probe model used by the lock-wait
// and function-latency probes instead of entry-probability sampling:
//  - Every switch-out is timestamped, so long waits are never lost to an
//    entry-side coin flip. min_duration and sample_rate are applied to the
//    measured duration at switch-in, where the cost of a decision is paid
//    once per wakeup instead of once per context switch.
//  - The start map is a global LRU hash rather than per-CPU: a thread that
//    blocks on one CPU and resumes on another is still measured.
//  - Per-probe metrics account for every drop path.

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

typedef struct OffCpuTimeMetrics {
  u64 switch_outs;
  u64 switch_ins;
  u64 unmatched_switch_ins;
  u64 filtered;
  u64 emitted;
  u64 state_update_failures;
} OffCpuTimeMetrics;

// off_cpu_time_starts records when each thread left the CPU. The pending set
// is every sleeping thread in the system, and a thread that exits while off
// CPU leaves its entry behind with no deterministic cleanup hook (the final
// switch-out of a dying task happens after every exit tracepoint). It is
// therefore an LRU hash: leaked and coldest entries are recycled under
// pressure instead of failing new inserts. Unlike the built-in off-CPU
// profiling map this is not per-CPU, so migrated wakeups still match.
struct off_cpu_time_starts_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);           // pid_tgid
  __type(value, u64);         // switch-out timestamp in nanoseconds
  __uint(max_entries, 65536); // resized at load time from probe configuration
} off_cpu_time_starts SEC(".maps");

struct off_cpu_time_metrics_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, OffCpuTimeMetrics);
  __uint(max_entries, 1);
} off_cpu_time_metrics SEC(".maps");

// These values are set independently for each loaded probe instance.
BPF_RODATA_VAR(u16, off_cpu_time_origin, 0)
BPF_RODATA_VAR(u64, off_cpu_time_min_ns, 0)
BPF_RODATA_VAR(u32, off_cpu_time_sample_threshold, 0xffffffff)

static EBPF_INLINE OffCpuTimeMetrics *off_cpu_time_get_metrics()
{
  u32 zero = 0;
  return bpf_map_lookup_elem(&off_cpu_time_metrics, &zero);
}

// off_cpu_time_switch_out runs in the context of the thread that is leaving
// the CPU and records its departure time. It runs on every context switch on
// the system, so it must stay minimal: all filtering and the unwind happen at
// switch-in, once the off-CPU duration is known.
SEC("tracepoint/sched/sched_switch")
int off_cpu_time_switch_out(UNUSED void *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xffffffff;
  if (pid == 0 || tid == 0) {
    // Never track the idle task.
    return 0;
  }

  OffCpuTimeMetrics *metrics = off_cpu_time_get_metrics();
  if (metrics) {
    metrics->switch_outs++;
  }

  u64 timestamp = bpf_ktime_get_ns();
  // BPF_ANY: switch-out and switch-in strictly alternate per thread, so an
  // existing entry means the matching switch-in was missed (attach race or a
  // missed kprobe). The newer timestamp is the correct base either way.
  if (bpf_map_update_elem(&off_cpu_time_starts, &pid_tgid, &timestamp, BPF_ANY) != 0) {
    if (metrics) {
      metrics->state_update_failures++;
    }
  }
  return 0;
}

// off_cpu_time_switch_in runs in the context of the thread that was just
// scheduled back in, right after the scheduler restored its registers. The
// unwound trace is the stack that was off CPU. Filtering happens here, on the
// measured duration: a wait shorter than min_ns is dropped, and sampling is
// applied per wakeup rather than per switch-out so long waits are never lost.
SEC("kprobe/finish_task_switch")
int off_cpu_time_switch_in(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xffffffff;
  if (pid == 0 || tid == 0) {
    return 0;
  }

  OffCpuTimeMetrics *metrics = off_cpu_time_get_metrics();
  if (metrics) {
    metrics->switch_ins++;
  }

  u64 *start = bpf_map_lookup_elem(&off_cpu_time_starts, &pid_tgid);
  if (!start) {
    // First sighting of this thread, or its start was evicted.
    if (metrics) {
      metrics->unmatched_switch_ins++;
    }
    return 0;
  }
  u64 started = *start;
  bpf_map_delete_elem(&off_cpu_time_starts, &pid_tgid);

  u64 timestamp = bpf_ktime_get_ns();
  if (
    timestamp < started || timestamp - started < off_cpu_time_min_ns ||
    (off_cpu_time_sample_threshold != 0xffffffff &&
     bpf_get_prandom_u32() > off_cpu_time_sample_threshold)) {
    if (metrics) {
      metrics->filtered++;
    }
    return 0;
  }

  if (metrics) {
    metrics->emitted++;
  }
  DEBUG_PRINT("off-cpu time wakeup pid %d tid %d", pid, tid);
  return collect_trace(ctx, off_cpu_time_origin, pid, tid, timestamp, timestamp - started);
}
