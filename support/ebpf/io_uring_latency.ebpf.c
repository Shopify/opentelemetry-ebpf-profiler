#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

typedef struct IOUringRequest {
  u64 timestamp;
  u64 correlation_id;
  u64 fallback_id;
  u64 request_ptr;
  u64 user_data;
  u32 pid;
  u32 tid;
  u16 operation;
  u8 attributes;
  u8 stack_emitted;
  u8 comm[COMM_LEN];
} IOUringRequest;

// In-flight operations are keyed by the correlation ID carried to userspace.
// This is req on modern kernels and a best-effort (ctx,user_data) key when the
// completion tracepoint does not expose req.
struct io_uring_requests_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, IOUringRequest);
  __uint(max_entries, 16384);
} io_uring_requests SEC(".maps");

// Resolve a best-effort (ring context,user_data) key to the correlation ID.
// This also handles modern auxiliary CQEs whose tracepoint has a NULL req.
struct io_uring_correlations_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, u64);
  __uint(max_entries, 16384);
} io_uring_correlations SEC(".maps");

// Resolve req to the correlation ID for full-stack capture at io_issue_sqe.
// Linux 5.10 submit tracepoints omit req, so those kernels intentionally use
// the tracepoint's initiating kernel stack without this enhancement.
struct io_uring_request_aliases_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, u64);
  __uint(max_entries, 16384);
} io_uring_request_aliases SEC(".maps");

BPF_RODATA_VAR(u16, io_uring_origin, 0)
BPF_RODATA_VAR(u64, io_uring_min_ns, 0)
BPF_RODATA_VAR(u32, io_uring_sample_threshold, 0xffffffff)

// Runtime offsets come from tracefs event format files. This avoids binding the
// programs to one cooked tracepoint layout.
BPF_RODATA_VAR(bool, io_uring_submit_has_req, false)
BPF_RODATA_VAR(u32, io_uring_submit_ctx_offset, 0)
BPF_RODATA_VAR(u32, io_uring_submit_req_offset, 0)
BPF_RODATA_VAR(u32, io_uring_submit_user_data_offset, 0)
BPF_RODATA_VAR(u32, io_uring_submit_opcode_offset, 0)
BPF_RODATA_VAR(u32, io_uring_submit_sq_thread_offset, 0)
BPF_RODATA_VAR(bool, io_uring_complete_has_req, false)
BPF_RODATA_VAR(bool, io_uring_complete_has_flags, false)
BPF_RODATA_VAR(u32, io_uring_complete_ctx_offset, 0)
BPF_RODATA_VAR(u32, io_uring_complete_req_offset, 0)
BPF_RODATA_VAR(u32, io_uring_complete_user_data_offset, 0)
BPF_RODATA_VAR(u32, io_uring_complete_result_offset, 0)
BPF_RODATA_VAR(u32, io_uring_complete_result_size, 0)
BPF_RODATA_VAR(u32, io_uring_complete_flags_offset, 0)

static EBPF_INLINE u64 io_uring_read_u64(void *ctx, u32 offset)
{
  u64 value = 0;
  bpf_probe_read_kernel(&value, sizeof(value), (u8 *)ctx + offset);
  return value;
}

static EBPF_INLINE u32 io_uring_read_u32(void *ctx, u32 offset)
{
  u32 value = 0;
  bpf_probe_read_kernel(&value, sizeof(value), (u8 *)ctx + offset);
  return value;
}

static EBPF_INLINE u8 io_uring_read_u8(void *ctx, u32 offset)
{
  u8 value = 0;
  bpf_probe_read_kernel(&value, sizeof(value), (u8 *)ctx + offset);
  return value;
}

static EBPF_INLINE u64 io_uring_first_argument(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->di;
#elif defined(__aarch64__)
  return ctx->regs[0];
#endif
}

static EBPF_INLINE u64 io_uring_fallback_correlation(u64 ring_ctx, u64 user_data)
{
  u64 correlation_id = ring_ctx ^ ((user_data << 17) | (user_data >> 47));
  return correlation_id ? correlation_id : 1;
}

static EBPF_INLINE void io_uring_fill_start_trace(void *ctx, const IOUringRequest *request)
{
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return;
  }

  Trace *trace            = &record->trace;
  trace->origin           = io_uring_origin;
  trace->pid              = request->pid;
  trace->tid              = request->tid;
  trace->ktime            = request->timestamp;
  trace->correlation_id   = request->correlation_id;
  trace->async_user_data  = request->user_data;
  trace->async_operation  = request->operation;
  trace->event_kind       = TRACE_EVENT_ASYNC_START;
  trace->async_kind       = TRACE_ASYNC_IO_URING;
  trace->async_attributes = request->attributes;
  trace->cpu_id           = bpf_get_smp_processor_id();
  __builtin_memcpy(trace->comm, request->comm, sizeof(trace->comm));

  // This tracepoint stack is a reliable kernel-only fallback. The io_issue_sqe
  // kprobe below emits the same correlation ID through the full unwinder and
  // replaces this entry in userspace when user registers are available.
  push_kernel_frames(ctx, trace);
  send_trace(ctx, trace);
}

SEC("tracepoint/io_uring/io_uring_submit_req")
int io_uring_submit(void *ctx)
{
  if (
    io_uring_origin == 0 || io_uring_sample_threshold == 0 ||
    bpf_get_prandom_u32() > io_uring_sample_threshold) {
    return 0;
  }

  u64 request_ptr =
    io_uring_submit_has_req ? io_uring_read_u64(ctx, io_uring_submit_req_offset) : 0;
  u64 pid_tgid       = bpf_get_current_pid_tgid();
  u64 user_data      = io_uring_read_u64(ctx, io_uring_submit_user_data_offset);
  u64 ring_ctx       = io_uring_read_u64(ctx, io_uring_submit_ctx_offset);
  u64 fallback_id    = io_uring_fallback_correlation(ring_ctx, user_data);
  u64 correlation_id = io_uring_complete_has_req && request_ptr ? request_ptr : fallback_id;

  IOUringRequest request = {
    .timestamp      = bpf_ktime_get_ns(),
    .correlation_id = correlation_id,
    .fallback_id    = fallback_id,
    .request_ptr    = request_ptr,
    .user_data      = user_data,
    .pid            = pid_tgid >> 32,
    .tid            = pid_tgid,
    .operation      = io_uring_read_u8(ctx, io_uring_submit_opcode_offset),
    .attributes =
      io_uring_read_u8(ctx, io_uring_submit_sq_thread_offset) ? TRACE_ASYNC_ATTR_SQ_POLL : 0,
  };
  bpf_get_current_comm(request.comm, sizeof(request.comm));

  bpf_map_update_elem(&io_uring_requests, &correlation_id, &request, BPF_ANY);
  bpf_map_update_elem(&io_uring_correlations, &fallback_id, &correlation_id, BPF_ANY);
  if (request_ptr) {
    bpf_map_update_elem(&io_uring_request_aliases, &request_ptr, &correlation_id, BPF_ANY);
  }
  io_uring_fill_start_trace(ctx, &request);
  return 0;
}

SEC("kprobe/io_uring_issue")
int io_uring_issue(struct pt_regs *ctx)
{
  u64 request_ptr     = io_uring_first_argument(ctx);
  u64 *correlation_id = bpf_map_lookup_elem(&io_uring_request_aliases, &request_ptr);
  if (!correlation_id) {
    return 0;
  }
  IOUringRequest *request = bpf_map_lookup_elem(&io_uring_requests, correlation_id);
  if (!request || request->stack_emitted) {
    return 0;
  }

  // A deferred io-wq worker cannot recover the submitter's user registers.
  // Keep the submission tracepoint fallback instead of misattributing a worker
  // stack to the initiating PID. SQPOLL is intentionally attributed to its SQ
  // thread and labeled as such.
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  if ((current_pid_tgid >> 32) != request->pid) {
    return 0;
  }
  request->stack_emitted = 1;

  return collect_async_trace(
    ctx,
    io_uring_origin,
    request->pid,
    request->tid,
    request->timestamp,
    request->correlation_id,
    request->user_data,
    request->operation,
    TRACE_ASYNC_IO_URING,
    request->attributes);
}

SEC("tracepoint/io_uring/io_uring_complete")
int io_uring_complete(void *ctx)
{
  u64 ring_ctx    = io_uring_read_u64(ctx, io_uring_complete_ctx_offset);
  u64 user_data   = io_uring_read_u64(ctx, io_uring_complete_user_data_offset);
  u64 fallback_id = io_uring_fallback_correlation(ring_ctx, user_data);
  u64 request_ptr =
    io_uring_complete_has_req ? io_uring_read_u64(ctx, io_uring_complete_req_offset) : 0;

  u64 correlation_id = 0;
  u64 *resolved      = request_ptr ? bpf_map_lookup_elem(&io_uring_request_aliases, &request_ptr)
                                   : bpf_map_lookup_elem(&io_uring_correlations, &fallback_id);
  if (resolved) {
    correlation_id = *resolved;
  }
  if (!correlation_id) {
    return 0;
  }

  IOUringRequest *request = bpf_map_lookup_elem(&io_uring_requests, &correlation_id);
  if (!request) {
    return 0;
  }
  u64 request_fallback_id = request->fallback_id;
  u64 request_request_ptr = request->request_ptr;

  u64 timestamp = bpf_ktime_get_ns();
  u32 cflags =
    io_uring_complete_has_flags ? io_uring_read_u32(ctx, io_uring_complete_flags_offset) : 0;
  bool more     = (cflags & (1U << 1)) != 0; // IORING_CQE_F_MORE
  u64 latency   = timestamp >= request->timestamp ? timestamp - request->timestamp : 0;
  bool filtered = latency < io_uring_min_ns;

  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    if (!more) {
      bpf_map_delete_elem(&io_uring_correlations, &request_fallback_id);
      if (request_request_ptr) {
        bpf_map_delete_elem(&io_uring_request_aliases, &request_request_ptr);
      }
      bpf_map_delete_elem(&io_uring_requests, &correlation_id);
    }
    return 0;
  }

  Trace *trace            = &record->trace;
  trace->origin           = io_uring_origin;
  trace->pid              = request->pid;
  trace->tid              = request->tid;
  trace->ktime            = timestamp;
  trace->value            = latency;
  trace->correlation_id   = request->correlation_id;
  trace->async_user_data  = request->user_data;
  trace->async_result     = io_uring_complete_result_size == 8
                              ? (s64)io_uring_read_u64(ctx, io_uring_complete_result_offset)
                              : (s32)io_uring_read_u32(ctx, io_uring_complete_result_offset);
  trace->async_flags      = cflags;
  trace->async_operation  = request->operation;
  trace->event_kind       = TRACE_EVENT_ASYNC_COMPLETE;
  trace->async_kind       = TRACE_ASYNC_IO_URING;
  trace->async_attributes = request->attributes | (more ? TRACE_ASYNC_ATTR_MORE : 0) |
                            (filtered ? TRACE_ASYNC_ATTR_FILTERED : 0);
  trace->cpu_id = bpf_get_smp_processor_id();
  __builtin_memcpy(trace->comm, request->comm, sizeof(trace->comm));

  send_trace(ctx, trace);
  if (!more) {
    bpf_map_delete_elem(&io_uring_correlations, &request_fallback_id);
    if (request_request_ptr) {
      bpf_map_delete_elem(&io_uring_request_aliases, &request_request_ptr);
    }
    bpf_map_delete_elem(&io_uring_requests, &correlation_id);
  }
  return 0;
}
