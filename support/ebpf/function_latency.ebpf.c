#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// function_latency_starts correlates a function return with its entry on the
// same thread. It is an LRU hash because a task may migrate between CPUs while
// blocked inside the instrumented function.
struct function_latency_starts_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);   // pid_tgid
  __type(value, u64); // entry timestamp in nanoseconds
  __uint(max_entries, 16384);
} function_latency_starts SEC(".maps");

// These values are set independently for each loaded probe instance.
BPF_RODATA_VAR(u16, function_latency_origin, 0)
BPF_RODATA_VAR(u64, function_latency_min_ns, 0)
BPF_RODATA_VAR(u32, function_latency_sample_threshold, 0xffffffff)

SEC("kprobe/function_latency_entry")
int function_latency_entry(UNUSED struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xffffffff;

  if (pid == 0 || tid == 0 || function_latency_sample_threshold == 0) {
    return 0;
  }
  if (bpf_get_prandom_u32() > function_latency_sample_threshold) {
    return 0;
  }

  u64 timestamp = bpf_ktime_get_ns();
  bpf_map_update_elem(&function_latency_starts, &pid_tgid, &timestamp, BPF_ANY);
  return 0;
}

SEC("kretprobe/function_latency_exit")
int function_latency_exit(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 *start   = bpf_map_lookup_elem(&function_latency_starts, &pid_tgid);
  if (!start) {
    return 0;
  }

  u64 started = *start;
  bpf_map_delete_elem(&function_latency_starts, &pid_tgid);

  u64 timestamp = bpf_ktime_get_ns();
  if (timestamp < started) {
    return 0;
  }

  u64 latency = timestamp - started;
  if (latency < function_latency_min_ns) {
    return 0;
  }

  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid & 0xffffffff;
  return collect_trace(ctx, function_latency_origin, pid, tid, timestamp, latency);
}
