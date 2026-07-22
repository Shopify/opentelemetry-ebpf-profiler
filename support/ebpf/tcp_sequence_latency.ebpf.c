#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

#define TCP_SEQUENCE_CALL_BEGIN  1
#define TCP_SEQUENCE_CALL_RESULT 2
#define TCP_SEQUENCE_RANGE       3
#define TCP_SEQUENCE_RESET       4
#define TCP_TIME_WAIT            6
#define TCP_CLOSE                7

typedef struct TCPSequenceCall {
  u64 socket_ptr;
  u64 token;
  u64 timestamp;
  u64 requested;
  u32 start_sequence;
  u32 pid;
  u32 tid;
  u8 comm[COMM_LEN];
} TCPSequenceCall;

struct tcp_ack_send_calls_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, TCPSequenceCall);
  __uint(max_entries, 16384);
} tcp_ack_send_calls SEC(".maps");

struct tcp_ack_track_calls_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, u64);
  __uint(max_entries, 16384);
} tcp_ack_track_calls SEC(".maps");

struct tcp_ack_active_sockets_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, u8);
  __uint(max_entries, 16384);
} tcp_ack_active_sockets SEC(".maps");

struct tcp_receive_calls_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, TCPSequenceCall);
  __uint(max_entries, 16384);
} tcp_receive_calls SEC(".maps");

BPF_RODATA_VAR(u16, tcp_ack_origin, 0)
BPF_RODATA_VAR(u64, tcp_ack_min_ns, 0)
BPF_RODATA_VAR(u32, tcp_ack_sample_threshold, 0xffffffff)
BPF_RODATA_VAR(bool, tcp_ack_has_layout, false)
BPF_RODATA_VAR(u32, tcp_ack_write_seq_offset, 0)
BPF_RODATA_VAR(u32, tcp_ack_snd_una_offset, 0)

BPF_RODATA_VAR(u16, tcp_receive_origin, 0)
BPF_RODATA_VAR(u64, tcp_receive_min_ns, 0)
BPF_RODATA_VAR(u32, tcp_receive_sample_threshold, 0xffffffff)
BPF_RODATA_VAR(bool, tcp_receive_has_layout, false)
BPF_RODATA_VAR(u32, tcp_receive_copied_seq_offset, 0)
BPF_RODATA_VAR(u32, tcp_receive_skb_cb_offset, 0)
BPF_RODATA_VAR(u32, tcp_receive_skb_seq_offset, 0)
BPF_RODATA_VAR(u32, tcp_receive_skb_end_seq_offset, 0)

static EBPF_INLINE u64 tcp_sequence_first_argument(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->di;
#elif defined(__aarch64__)
  return ctx->regs[0];
#endif
}

static EBPF_INLINE u64 tcp_sequence_second_argument(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->si;
#elif defined(__aarch64__)
  return ctx->regs[1];
#endif
}

static EBPF_INLINE u64 tcp_sequence_third_argument(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->dx;
#elif defined(__aarch64__)
  return ctx->regs[2];
#endif
}

static EBPF_INLINE s64 tcp_sequence_return_value(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->ax;
#elif defined(__aarch64__)
  return ctx->regs[0];
#endif
}

static EBPF_INLINE u32 tcp_sequence_read_u32(u64 base, u32 offset)
{
  u32 value = 0;
  bpf_probe_read_kernel(&value, sizeof(value), (u8 *)base + offset);
  return value;
}

static EBPF_INLINE bool tcp_sequence_sample_socket(u64 socket_ptr, u32 threshold)
{
  // Multiplicative hashing avoids sampling bias from aligned slab pointers and
  // their common high address bits.
  u32 hash = (socket_ptr * 11400714819323198485ull) >> 32;
  return threshold != 0 && hash <= threshold;
}

static EBPF_INLINE void tcp_sequence_lifecycle_event(
  void *ctx,
  const TCPSequenceCall *call,
  u16 origin,
  u8 async_kind,
  u8 event_kind,
  u16 operation,
  s64 result,
  u32 sequence,
  u64 threshold)
{
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return;
  }
  Trace *trace           = &record->trace;
  trace->origin          = origin;
  trace->pid             = call->pid;
  trace->tid             = call->tid;
  trace->ktime           = bpf_ktime_get_ns();
  trace->correlation_id  = call->token;
  trace->async_user_data = call->socket_ptr;
  trace->async_threshold = threshold;
  trace->async_result    = result;
  trace->async_flags     = sequence;
  trace->async_operation = operation;
  trace->event_kind      = event_kind;
  trace->async_kind      = async_kind;
  __builtin_memcpy(trace->comm, call->comm, sizeof(trace->comm));
  send_trace(ctx, trace);
}

static EBPF_INLINE void tcp_sequence_start_fallback(
  void *ctx, const TCPSequenceCall *call, u16 origin, u8 async_kind, u64 threshold)
{
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return;
  }
  Trace *trace           = &record->trace;
  trace->origin          = origin;
  trace->pid             = call->pid;
  trace->tid             = call->tid;
  trace->ktime           = call->timestamp;
  trace->correlation_id  = call->token;
  trace->async_user_data = call->socket_ptr;
  trace->async_threshold = threshold;
  trace->event_kind      = TRACE_EVENT_ASYNC_START;
  trace->async_kind      = async_kind;
  __builtin_memcpy(trace->comm, call->comm, sizeof(trace->comm));
  push_kernel_frames(ctx, trace);
  send_trace(ctx, trace);
}

SEC("kprobe/tcp_ack_send_entry")
int tcp_ack_send_entry(struct pt_regs *ctx)
{
  if (tcp_ack_origin == 0 || !tcp_ack_has_layout) {
    return 0;
  }
  u64 socket_ptr = tcp_sequence_first_argument(ctx);
  if (!socket_ptr || !tcp_sequence_sample_socket(socket_ptr, tcp_ack_sample_threshold)) {
    return 0;
  }
  u64 pid_tgid         = bpf_get_current_pid_tgid();
  u64 timestamp        = bpf_ktime_get_ns();
  TCPSequenceCall call = {
    .socket_ptr     = socket_ptr,
    .token          = timestamp ^ pid_tgid ^ socket_ptr,
    .timestamp      = timestamp,
    .requested      = tcp_sequence_third_argument(ctx),
    .start_sequence = tcp_sequence_read_u32(socket_ptr, tcp_ack_write_seq_offset),
    .pid            = pid_tgid >> 32,
    .tid            = pid_tgid,
  };
  if (!call.token) {
    call.token = timestamp ? timestamp : 1;
  }
  u8 active = 1;
  bpf_map_update_elem(&tcp_ack_active_sockets, &socket_ptr, &active, BPF_ANY);
  bpf_get_current_comm(call.comm, sizeof(call.comm));
  if (bpf_map_update_elem(&tcp_ack_send_calls, &pid_tgid, &call, BPF_ANY)) {
    return 0;
  }
  tcp_sequence_lifecycle_event(
    ctx,
    &call,
    tcp_ack_origin,
    TRACE_ASYNC_TCP_ACK,
    TRACE_EVENT_ASYNC_REGISTER,
    TCP_SEQUENCE_CALL_BEGIN,
    call.requested,
    call.start_sequence,
    tcp_ack_min_ns);
  tcp_sequence_start_fallback(ctx, &call, tcp_ack_origin, TRACE_ASYNC_TCP_ACK, tcp_ack_min_ns);
  return collect_async_trace_with_threshold(
    ctx,
    tcp_ack_origin,
    call.pid,
    call.tid,
    call.timestamp,
    call.token,
    call.socket_ptr,
    tcp_ack_min_ns,
    0,
    TRACE_ASYNC_TCP_ACK,
    0);
}

SEC("kretprobe/tcp_ack_send_exit")
int tcp_ack_send_exit(struct pt_regs *ctx)
{
  u64 pid_tgid          = bpf_get_current_pid_tgid();
  TCPSequenceCall *call = bpf_map_lookup_elem(&tcp_ack_send_calls, &pid_tgid);
  if (!call) {
    return 0;
  }
  s64 result   = tcp_sequence_return_value(ctx);
  u32 sequence = call->start_sequence;
  if (result > 0) {
    u32 end_sequence = tcp_sequence_read_u32(call->socket_ptr, tcp_ack_write_seq_offset);
    sequence         = end_sequence - (u32)result;
  }
  tcp_sequence_lifecycle_event(
    ctx,
    call,
    tcp_ack_origin,
    TRACE_ASYNC_TCP_ACK,
    TRACE_EVENT_ASYNC_REGISTER,
    TCP_SEQUENCE_CALL_RESULT,
    result,
    sequence,
    tcp_ack_min_ns);
  bpf_map_delete_elem(&tcp_ack_send_calls, &pid_tgid);
  return 0;
}

SEC("kprobe/tcp_ack_track_entry")
int tcp_ack_track_entry(struct pt_regs *ctx)
{
  if (tcp_ack_origin == 0 || !tcp_ack_has_layout) {
    return 0;
  }
  u64 socket_ptr = tcp_sequence_first_argument(ctx);
  if (!socket_ptr || !tcp_sequence_sample_socket(socket_ptr, tcp_ack_sample_threshold)) {
    return 0;
  }
  if (!bpf_map_lookup_elem(&tcp_ack_active_sockets, &socket_ptr)) {
    return 0;
  }
  u64 pid_tgid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&tcp_ack_track_calls, &pid_tgid, &socket_ptr, BPF_ANY);
  return 0;
}

SEC("kretprobe/tcp_ack_track_exit")
int tcp_ack_track_exit(struct pt_regs *ctx)
{
  u64 pid_tgid    = bpf_get_current_pid_tgid();
  u64 *socket_ptr = bpf_map_lookup_elem(&tcp_ack_track_calls, &pid_tgid);
  if (!socket_ptr) {
    return 0;
  }

  PerCPURecord *record = get_pristine_per_cpu_record();
  if (record) {
    Trace *trace           = &record->trace;
    trace->origin          = tcp_ack_origin;
    trace->ktime           = bpf_ktime_get_ns();
    trace->correlation_id  = *socket_ptr;
    trace->async_user_data = tcp_sequence_read_u32(*socket_ptr, tcp_ack_snd_una_offset);
    trace->event_kind      = TRACE_EVENT_ASYNC_PROGRESS;
    trace->async_kind      = TRACE_ASYNC_TCP_ACK;
    send_trace(ctx, trace);
  }
  bpf_map_delete_elem(&tcp_ack_track_calls, &pid_tgid);
  return 0;
}

static EBPF_INLINE void
tcp_sequence_reset_event(struct bpf_raw_tracepoint_args *ctx, u16 origin, u8 async_kind)
{
  u32 new_state = ctx->args[2];
  if (origin == 0 || (new_state != TCP_TIME_WAIT && new_state != TCP_CLOSE)) {
    return;
  }
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return;
  }
  Trace *trace           = &record->trace;
  trace->origin          = origin;
  trace->ktime           = bpf_ktime_get_ns();
  trace->correlation_id  = ctx->args[0];
  trace->async_operation = TCP_SEQUENCE_RESET;
  trace->event_kind      = TRACE_EVENT_ASYNC_PROGRESS;
  trace->async_kind      = async_kind;
  send_trace(ctx, trace);
}

SEC("raw_tracepoint/tcp_ack_close")
int tcp_ack_close(struct bpf_raw_tracepoint_args *ctx)
{
  u32 new_state = ctx->args[2];
  if (new_state == TCP_TIME_WAIT || new_state == TCP_CLOSE) {
    u64 socket_ptr = ctx->args[0];
    bpf_map_delete_elem(&tcp_ack_active_sockets, &socket_ptr);
  }
  tcp_sequence_reset_event(ctx, tcp_ack_origin, TRACE_ASYNC_TCP_ACK);
  return 0;
}

SEC("raw_tracepoint/tcp_receive_close")
int tcp_receive_close(struct bpf_raw_tracepoint_args *ctx)
{
  tcp_sequence_reset_event(ctx, tcp_receive_origin, TRACE_ASYNC_TCP_RECEIVE);
  return 0;
}

SEC("kprobe/tcp_receive_data")
int tcp_receive_data(struct pt_regs *ctx)
{
  if (tcp_receive_origin == 0 || !tcp_receive_has_layout) {
    return 0;
  }
  u64 socket_ptr = tcp_sequence_first_argument(ctx);
  if (!socket_ptr || !tcp_sequence_sample_socket(socket_ptr, tcp_receive_sample_threshold)) {
    return 0;
  }
  u64 skb_ptr = tcp_sequence_second_argument(ctx);
  if (!skb_ptr) {
    return 0;
  }
  u32 sequence =
    tcp_sequence_read_u32(skb_ptr, tcp_receive_skb_cb_offset + tcp_receive_skb_seq_offset);
  u32 end_sequence =
    tcp_sequence_read_u32(skb_ptr, tcp_receive_skb_cb_offset + tcp_receive_skb_end_seq_offset);
  if (sequence == end_sequence) {
    return 0;
  }
  u32 copied_sequence = tcp_sequence_read_u32(socket_ptr, tcp_receive_copied_seq_offset);
  if ((s32)(end_sequence - copied_sequence) <= 0) {
    return 0;
  }

  PerCPURecord *record = get_pristine_per_cpu_record();
  if (record) {
    Trace *trace           = &record->trace;
    trace->origin          = tcp_receive_origin;
    trace->ktime           = bpf_ktime_get_ns();
    trace->correlation_id  = socket_ptr;
    trace->async_user_data = ((u64)sequence << 32) | end_sequence;
    trace->async_operation = TCP_SEQUENCE_RANGE;
    trace->event_kind      = TRACE_EVENT_ASYNC_REGISTER;
    trace->async_kind      = TRACE_ASYNC_TCP_RECEIVE;
    send_trace(ctx, trace);
  }
  return 0;
}

SEC("kprobe/tcp_receive_entry")
int tcp_receive_entry(struct pt_regs *ctx)
{
  if (tcp_receive_origin == 0 || !tcp_receive_has_layout) {
    return 0;
  }
  u64 socket_ptr = tcp_sequence_first_argument(ctx);
  if (!socket_ptr || !tcp_sequence_sample_socket(socket_ptr, tcp_receive_sample_threshold)) {
    return 0;
  }
  u64 pid_tgid         = bpf_get_current_pid_tgid();
  u64 timestamp        = bpf_ktime_get_ns();
  TCPSequenceCall call = {
    .socket_ptr     = socket_ptr,
    .token          = timestamp ^ pid_tgid ^ socket_ptr,
    .timestamp      = timestamp,
    .requested      = tcp_sequence_third_argument(ctx),
    .start_sequence = tcp_sequence_read_u32(socket_ptr, tcp_receive_copied_seq_offset),
    .pid            = pid_tgid >> 32,
    .tid            = pid_tgid,
  };
  if (!call.token) {
    call.token = timestamp ? timestamp : 1;
  }
  bpf_get_current_comm(call.comm, sizeof(call.comm));
  if (bpf_map_update_elem(&tcp_receive_calls, &pid_tgid, &call, BPF_ANY)) {
    return 0;
  }
  tcp_sequence_lifecycle_event(
    ctx,
    &call,
    tcp_receive_origin,
    TRACE_ASYNC_TCP_RECEIVE,
    TRACE_EVENT_ASYNC_REGISTER,
    TCP_SEQUENCE_CALL_BEGIN,
    call.requested,
    call.start_sequence,
    tcp_receive_min_ns);
  tcp_sequence_start_fallback(
    ctx, &call, tcp_receive_origin, TRACE_ASYNC_TCP_RECEIVE, tcp_receive_min_ns);
  return collect_async_trace_with_threshold(
    ctx,
    tcp_receive_origin,
    call.pid,
    call.tid,
    call.timestamp,
    call.token,
    call.socket_ptr,
    tcp_receive_min_ns,
    0,
    TRACE_ASYNC_TCP_RECEIVE,
    0);
}

SEC("kretprobe/tcp_receive_exit")
int tcp_receive_exit(struct pt_regs *ctx)
{
  u64 pid_tgid          = bpf_get_current_pid_tgid();
  TCPSequenceCall *call = bpf_map_lookup_elem(&tcp_receive_calls, &pid_tgid);
  if (!call) {
    return 0;
  }
  s64 result   = tcp_sequence_return_value(ctx);
  u32 sequence = call->start_sequence;
  if (result > 0) {
    u32 end_sequence = tcp_sequence_read_u32(call->socket_ptr, tcp_receive_copied_seq_offset);
    sequence         = end_sequence - (u32)result;
  }
  tcp_sequence_lifecycle_event(
    ctx,
    call,
    tcp_receive_origin,
    TRACE_ASYNC_TCP_RECEIVE,
    TRACE_EVENT_ASYNC_REGISTER,
    TCP_SEQUENCE_CALL_RESULT,
    result,
    sequence,
    tcp_receive_min_ns);
  bpf_map_delete_elem(&tcp_receive_calls, &pid_tgid);
  return 0;
}
