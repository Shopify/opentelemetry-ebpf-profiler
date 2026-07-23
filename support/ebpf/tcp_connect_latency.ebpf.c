#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

#define TCP_ESTABLISHED 1
#define TCP_CLOSE       7

typedef struct TCPConnectStart {
  u64 timestamp;
  u32 pid;
  u32 tid;
  u16 family;
  u8 comm[COMM_LEN];
} TCPConnectStart;

struct tcp_connect_starts_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, TCPConnectStart);
  __uint(max_entries, 16384);
} tcp_connect_starts SEC(".maps");

BPF_RODATA_VAR(u16, tcp_connect_origin, 0)
BPF_RODATA_VAR(u64, tcp_connect_min_ns, 0)
BPF_RODATA_VAR(u32, tcp_connect_sample_threshold, 0xffffffff)
BPF_RODATA_VAR(bool, tcp_connect_has_sk_err, false)
BPF_RODATA_VAR(u32, tcp_connect_sk_err_offset, 0)

static EBPF_INLINE u64 tcp_connect_first_argument(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->di;
#elif defined(__aarch64__)
  return ctx->regs[0];
#endif
}

static EBPF_INLINE void
tcp_connect_fill_start_trace(void *ctx, u64 socket_ptr, const TCPConnectStart *start)
{
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return;
  }
  Trace *trace           = &record->trace;
  trace->origin          = tcp_connect_origin;
  trace->pid             = start->pid;
  trace->tid             = start->tid;
  trace->ktime           = start->timestamp;
  trace->correlation_id  = socket_ptr;
  trace->async_operation = start->family;
  trace->event_kind      = TRACE_EVENT_ASYNC_START;
  trace->async_kind      = TRACE_ASYNC_TCP_CONNECT;
  trace->cpu_id          = bpf_get_smp_processor_id();
  __builtin_memcpy(trace->comm, start->comm, sizeof(trace->comm));
  push_kernel_frames(ctx, trace);
  send_trace(ctx, trace);
}

static EBPF_INLINE int tcp_connect_start(struct pt_regs *ctx, u16 family)
{
  if (
    tcp_connect_origin == 0 || tcp_connect_sample_threshold == 0 ||
    bpf_get_prandom_u32() > tcp_connect_sample_threshold) {
    return 0;
  }
  u64 socket_ptr = tcp_connect_first_argument(ctx);
  if (!socket_ptr) {
    return 0;
  }
  u64 pid_tgid          = bpf_get_current_pid_tgid();
  TCPConnectStart start = {
    .timestamp = bpf_ktime_get_ns(),
    .pid       = pid_tgid >> 32,
    .tid       = pid_tgid,
    .family    = family,
  };
  bpf_get_current_comm(start.comm, sizeof(start.comm));
  bpf_map_update_elem(&tcp_connect_starts, &socket_ptr, &start, BPF_ANY);

  // Keep a kernel fallback in case process mappings are not ready for the full
  // unwinder on the first connection from a process.
  tcp_connect_fill_start_trace(ctx, socket_ptr, &start);
  return collect_async_trace(
    ctx,
    tcp_connect_origin,
    start.pid,
    start.tid,
    start.timestamp,
    socket_ptr,
    0,
    family,
    TRACE_ASYNC_TCP_CONNECT,
    0);
}

SEC("kprobe/tcp_connect_v4_start")
int tcp_connect_v4_start(struct pt_regs *ctx)
{
  return tcp_connect_start(ctx, 4);
}

SEC("kprobe/tcp_connect_v6_start")
int tcp_connect_v6_start(struct pt_regs *ctx)
{
  return tcp_connect_start(ctx, 6);
}

SEC("raw_tracepoint/inet_sock_set_state")
int tcp_connect_state(struct bpf_raw_tracepoint_args *ctx)
{
  u32 new_state = ctx->args[2];
  if (new_state != TCP_ESTABLISHED && new_state != TCP_CLOSE) {
    return 0;
  }
  u64 socket_ptr         = ctx->args[0];
  TCPConnectStart *start = bpf_map_lookup_elem(&tcp_connect_starts, &socket_ptr);
  if (!start) {
    return 0;
  }

  u64 timestamp = bpf_ktime_get_ns();
  u64 latency   = timestamp >= start->timestamp ? timestamp - start->timestamp : 0;
  s64 result    = 0;
  if (new_state == TCP_CLOSE) {
    u32 socket_error = 0;
    if (tcp_connect_has_sk_err) {
      bpf_probe_read_kernel(
        &socket_error, sizeof(socket_error), (u8 *)socket_ptr + tcp_connect_sk_err_offset);
    }
    result = socket_error ? -(s32)socket_error : -1;
  }

  PerCPURecord *record = get_pristine_per_cpu_record();
  if (record) {
    Trace *trace            = &record->trace;
    trace->origin           = tcp_connect_origin;
    trace->pid              = start->pid;
    trace->tid              = start->tid;
    trace->ktime            = timestamp;
    trace->value            = latency;
    trace->correlation_id   = socket_ptr;
    trace->async_result     = result;
    trace->async_operation  = start->family;
    trace->event_kind       = TRACE_EVENT_ASYNC_COMPLETE;
    trace->async_kind       = TRACE_ASYNC_TCP_CONNECT;
    trace->async_attributes = latency < tcp_connect_min_ns ? TRACE_ASYNC_ATTR_FILTERED : 0;
    trace->cpu_id           = bpf_get_smp_processor_id();
    __builtin_memcpy(trace->comm, start->comm, sizeof(trace->comm));
    send_trace(ctx, trace);
  }
  bpf_map_delete_elem(&tcp_connect_starts, &socket_ptr);
  return 0;
}
