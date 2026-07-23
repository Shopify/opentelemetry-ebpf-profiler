#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

#define BLOCK_MODE_QUEUE   1
#define BLOCK_MODE_SERVICE 2
#define BLOCK_MODE_FULL    3
#define BLOCK_REQ_OP_MASK  0xff

typedef struct BlockBioStart {
  u64 timestamp;
  u32 pid;
  u32 tid;
  u16 operation;
  u8 comm[COMM_LEN];
} BlockBioStart;

typedef struct BlockRequest {
  u64 correlation_id;
  u64 submit_timestamp;
  u64 insert_timestamp;
  u64 issue_timestamp;
  u64 device;
  u32 remaining_bytes;
  u32 pid;
  u32 tid;
  u16 operation;
  u8 comm[COMM_LEN];
} BlockRequest;

struct block_io_bio_starts_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, BlockBioStart);
  __uint(max_entries, 4096);
} block_io_bio_starts SEC(".maps");

struct block_io_requests_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, BlockRequest);
  __uint(max_entries, 4096);
} block_io_requests SEC(".maps");

BPF_RODATA_VAR(u16, block_io_origin, 0)
BPF_RODATA_VAR(u8, block_io_mode, BLOCK_MODE_QUEUE)
BPF_RODATA_VAR(bool, block_io_old_rq_args, false)
BPF_RODATA_VAR(u64, block_io_min_ns, 0)
BPF_RODATA_VAR(u32, block_io_sample_threshold, 0xffffffff)

BPF_RODATA_VAR(bool, block_io_has_btf_layout, false)
BPF_RODATA_VAR(bool, block_io_has_direct_disk, false)
BPF_RODATA_VAR(u32, block_io_request_bio_offset, 0)
BPF_RODATA_VAR(u32, block_io_request_flags_offset, 0)
BPF_RODATA_VAR(u32, block_io_request_bytes_offset, 0)
BPF_RODATA_VAR(u32, block_io_request_queue_offset, 0)
BPF_RODATA_VAR(u32, block_io_request_disk_offset, 0)
BPF_RODATA_VAR(u32, block_io_queue_disk_offset, 0)
BPF_RODATA_VAR(u32, block_io_disk_major_offset, 0)
BPF_RODATA_VAR(u32, block_io_disk_minor_offset, 0)
BPF_RODATA_VAR(u32, block_io_bio_flags_offset, 0)

static EBPF_INLINE u64 block_first_argument(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->di;
#elif defined(__aarch64__)
  return ctx->regs[0];
#endif
}

static EBPF_INLINE u64 block_read_pointer(const void *base, u32 offset)
{
  u64 value = 0;
  bpf_probe_read_kernel(&value, sizeof(value), (const u8 *)base + offset);
  return value;
}

static EBPF_INLINE u32 block_read_u32(const void *base, u32 offset)
{
  u32 value = 0;
  bpf_probe_read_kernel(&value, sizeof(value), (const u8 *)base + offset);
  return value;
}

static EBPF_INLINE u64 block_request_from_raw(struct bpf_raw_tracepoint_args *ctx)
{
  return block_io_old_rq_args ? ctx->args[1] : ctx->args[0];
}

static EBPF_INLINE u16 block_request_operation(u64 request_ptr)
{
  if (!block_io_has_btf_layout) {
    return 0;
  }
  return block_read_u32((void *)request_ptr, block_io_request_flags_offset) & BLOCK_REQ_OP_MASK;
}

static EBPF_INLINE u64 block_request_device(u64 request_ptr)
{
  if (!block_io_has_btf_layout) {
    return 0;
  }

  u64 disk = 0;
  if (block_io_has_direct_disk) {
    disk = block_read_pointer((void *)request_ptr, block_io_request_disk_offset);
  } else {
    u64 queue = block_read_pointer((void *)request_ptr, block_io_request_queue_offset);
    if (queue) {
      disk = block_read_pointer((void *)queue, block_io_queue_disk_offset);
    }
  }
  if (!disk) {
    return 0;
  }
  u32 major = block_read_u32((void *)disk, block_io_disk_major_offset);
  u32 minor = block_read_u32((void *)disk, block_io_disk_minor_offset);
  return ((u64)major << 32) | minor;
}

static EBPF_INLINE void block_fill_start_trace(void *ctx, const BlockRequest *request)
{
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return;
  }

  Trace *trace           = &record->trace;
  trace->origin          = block_io_origin;
  trace->pid             = request->pid;
  trace->tid             = request->tid;
  trace->ktime           = request->submit_timestamp;
  trace->correlation_id  = request->correlation_id;
  trace->async_user_data = request->device;
  trace->async_operation = request->operation;
  trace->event_kind      = TRACE_EVENT_ASYNC_START;
  trace->async_kind      = TRACE_ASYNC_BLOCK;
  trace->cpu_id          = bpf_get_smp_processor_id();
  __builtin_memcpy(trace->comm, request->comm, sizeof(trace->comm));
  push_kernel_frames(ctx, trace);
  send_trace(ctx, trace);
}

static EBPF_INLINE void block_send_completion(
  void *ctx,
  const BlockRequest *request,
  u64 timestamp,
  u64 latency,
  s64 result,
  bool force_filtered)
{
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return;
  }

  Trace *trace           = &record->trace;
  trace->origin          = block_io_origin;
  trace->pid             = request->pid;
  trace->tid             = request->tid;
  trace->ktime           = timestamp;
  trace->value           = latency;
  trace->correlation_id  = request->correlation_id;
  trace->async_user_data = request->device;
  trace->async_result    = result;
  trace->async_operation = request->operation;
  trace->event_kind      = TRACE_EVENT_ASYNC_COMPLETE;
  trace->async_kind      = TRACE_ASYNC_BLOCK;
  trace->async_attributes =
    force_filtered || latency < block_io_min_ns ? TRACE_ASYNC_ATTR_FILTERED : 0;
  trace->cpu_id = bpf_get_smp_processor_id();
  __builtin_memcpy(trace->comm, request->comm, sizeof(trace->comm));
  send_trace(ctx, trace);
}

SEC("kprobe/block_io_submit_bio")
int block_io_submit_bio(struct pt_regs *ctx)
{
  if (
    block_io_origin == 0 || !block_io_has_btf_layout || block_io_sample_threshold == 0 ||
    bpf_get_prandom_u32() > block_io_sample_threshold) {
    return 0;
  }

  u64 bio_ptr = block_first_argument(ctx);
  if (!bio_ptr) {
    return 0;
  }
  u64 pid_tgid        = bpf_get_current_pid_tgid();
  BlockBioStart start = {
    .timestamp = bpf_ktime_get_ns(),
    .pid       = pid_tgid >> 32,
    .tid       = pid_tgid,
    .operation = block_read_u32((void *)bio_ptr, block_io_bio_flags_offset) & BLOCK_REQ_OP_MASK,
  };
  bpf_get_current_comm(start.comm, sizeof(start.comm));
  bpf_map_update_elem(&block_io_bio_starts, &bio_ptr, &start, BPF_ANY);

  return collect_async_trace(
    ctx,
    block_io_origin,
    start.pid,
    start.tid,
    start.timestamp,
    bio_ptr,
    0,
    start.operation,
    TRACE_ASYNC_BLOCK,
    0);
}

SEC("raw_tracepoint/block_rq_insert")
int block_io_insert(struct bpf_raw_tracepoint_args *ctx)
{
  u64 request_ptr = block_request_from_raw(ctx);
  if (!request_ptr || block_io_origin == 0) {
    return 0;
  }

  u64 bio_ptr              = block_io_has_btf_layout
                               ? block_read_pointer((void *)request_ptr, block_io_request_bio_offset)
                               : 0;
  BlockBioStart *bio_start = bio_ptr ? bpf_map_lookup_elem(&block_io_bio_starts, &bio_ptr) : NULL;
  if (
    !bio_start &&
    (block_io_sample_threshold == 0 || bpf_get_prandom_u32() > block_io_sample_threshold)) {
    return 0;
  }

  u64 timestamp        = bpf_ktime_get_ns();
  u64 pid_tgid         = bpf_get_current_pid_tgid();
  BlockRequest request = {
    .correlation_id   = bio_start ? bio_ptr : request_ptr,
    .submit_timestamp = bio_start ? bio_start->timestamp : timestamp,
    .insert_timestamp = timestamp,
    .device           = block_request_device(request_ptr),
    .pid              = bio_start ? bio_start->pid : pid_tgid >> 32,
    .tid              = bio_start ? bio_start->tid : (u32)pid_tgid,
    .operation        = bio_start ? bio_start->operation : block_request_operation(request_ptr),
  };
  if (bio_start) {
    __builtin_memcpy(request.comm, bio_start->comm, sizeof(request.comm));
  } else {
    bpf_get_current_comm(request.comm, sizeof(request.comm));
  }

  bpf_map_update_elem(&block_io_requests, &request_ptr, &request, BPF_ANY);
  // Always emit this kernel fallback. If submit_bio_noacct produced a full
  // user stack, the userspace correlator keeps that richer duplicate.
  block_fill_start_trace(ctx, &request);
  if (bio_start) {
    bpf_map_delete_elem(&block_io_bio_starts, &bio_ptr);
  }
  return 0;
}

SEC("raw_tracepoint/block_rq_issue")
int block_io_issue(struct bpf_raw_tracepoint_args *ctx)
{
  u64 request_ptr = block_request_from_raw(ctx);
  if (!request_ptr || block_io_origin == 0) {
    return 0;
  }

  bool no_queue_interval = false;
  u64 timestamp          = bpf_ktime_get_ns();
  BlockRequest *request  = bpf_map_lookup_elem(&block_io_requests, &request_ptr);
  if (!request) {
    u64 bio_ptr              = block_io_has_btf_layout
                                 ? block_read_pointer((void *)request_ptr, block_io_request_bio_offset)
                                 : 0;
    BlockBioStart *bio_start = bio_ptr ? bpf_map_lookup_elem(&block_io_bio_starts, &bio_ptr) : NULL;
    if (bio_start) {
      BlockRequest direct = {
        .correlation_id   = bio_ptr,
        .submit_timestamp = bio_start->timestamp,
        .insert_timestamp = timestamp,
        .device           = block_request_device(request_ptr),
        .pid              = bio_start->pid,
        .tid              = bio_start->tid,
        .operation        = bio_start->operation,
      };
      __builtin_memcpy(direct.comm, bio_start->comm, sizeof(direct.comm));
      bpf_map_update_elem(&block_io_requests, &request_ptr, &direct, BPF_ANY);
      block_fill_start_trace(ctx, &direct);
      bpf_map_delete_elem(&block_io_bio_starts, &bio_ptr);
      no_queue_interval = true;
    } else {
      // Without an insert or bio association only issue-to-completion service
      // latency remains well-defined.
      if (
        block_io_mode != BLOCK_MODE_SERVICE || block_io_sample_threshold == 0 ||
        bpf_get_prandom_u32() > block_io_sample_threshold) {
        return 0;
      }
      u64 pid_tgid          = bpf_get_current_pid_tgid();
      BlockRequest fallback = {
        .correlation_id   = request_ptr,
        .submit_timestamp = timestamp,
        .insert_timestamp = timestamp,
        .device           = block_request_device(request_ptr),
        .pid              = pid_tgid >> 32,
        .tid              = pid_tgid,
        .operation        = block_request_operation(request_ptr),
      };
      bpf_get_current_comm(fallback.comm, sizeof(fallback.comm));
      bpf_map_update_elem(&block_io_requests, &request_ptr, &fallback, BPF_ANY);
      block_fill_start_trace(ctx, &fallback);
    }
    request = bpf_map_lookup_elem(&block_io_requests, &request_ptr);
    if (!request) {
      return 0;
    }
  }

  if (!request->issue_timestamp) {
    request->issue_timestamp = timestamp;
    if (block_io_has_btf_layout) {
      request->remaining_bytes = block_read_u32((void *)request_ptr, block_io_request_bytes_offset);
    }
  }

  if (block_io_mode == BLOCK_MODE_QUEUE) {
    u64 latency =
      timestamp >= request->insert_timestamp ? timestamp - request->insert_timestamp : 0;
    block_send_completion(ctx, request, timestamp, latency, 0, no_queue_interval);
    bpf_map_delete_elem(&block_io_requests, &request_ptr);
  }
  return 0;
}

SEC("raw_tracepoint/block_rq_complete")
int block_io_complete(struct bpf_raw_tracepoint_args *ctx)
{
  u64 request_ptr       = ctx->args[0];
  BlockRequest *request = bpf_map_lookup_elem(&block_io_requests, &request_ptr);
  if (!request || block_io_mode == BLOCK_MODE_QUEUE) {
    return 0;
  }

  u32 completed_bytes = ctx->args[2];
  if (ctx->args[1] == 0 && request->remaining_bytes > completed_bytes && completed_bytes > 0) {
    request->remaining_bytes -= completed_bytes;
    return 0;
  }

  u64 timestamp = bpf_ktime_get_ns();
  u64 started   = block_io_mode == BLOCK_MODE_SERVICE && request->issue_timestamp
                    ? request->issue_timestamp
                    : request->submit_timestamp;
  u64 latency   = timestamp >= started ? timestamp - started : 0;
  block_send_completion(ctx, request, timestamp, latency, (s32)ctx->args[1], false);
  bpf_map_delete_elem(&block_io_requests, &request_ptr);
  return 0;
}
