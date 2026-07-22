#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// The block_io_start and block_rq_issue tracepoints share these leading fields.
// See /sys/kernel/tracing/events/block/<event>/format.
typedef struct BlockIOCtx {
  u64 common_fields;
  u32 dev;
  u32 padding;
  u64 sector;
  u32 nr_sector;
  u32 bytes;
  u8 rwbs[8];
} BlockIOCtx;

typedef struct BlockIOKey {
  u32 dev;
  u32 padding;
  u64 sector;
} BlockIOKey;

typedef struct BlockIOStart {
  u64 timestamp;
  u64 stack[PERF_MAX_STACK_DEPTH];
  u32 pid;
  u32 tid;
  u16 num_frames;
  u8 comm[COMM_LEN];
  u8 rwbs[8];
} BlockIOStart;

// A per-CPU scratch value avoids putting the large stack array on the BPF stack.
struct block_io_stacks_scratch_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, BlockIOStart);
  __uint(max_entries, 1);
} block_io_stacks_scratch SEC(".maps");

// In-flight block operations are keyed like bpftrace's biostacks tool: device
// plus sector. The value preserves the initialization stack until issue time.
struct block_io_stacks_inflight_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, BlockIOKey);
  __type(value, BlockIOStart);
  __uint(max_entries, 4096);
} block_io_stacks_inflight SEC(".maps");

BPF_RODATA_VAR(u16, block_io_stacks_origin, 0)
BPF_RODATA_VAR(u64, block_io_stacks_min_ns, 0)
BPF_RODATA_VAR(u32, block_io_stacks_sample_threshold, 0xffffffff)

static EBPF_INLINE u8 hex_digit(u8 value)
{
  return value < 10 ? '0' + value : 'a' + value - 10;
}

SEC("tracepoint/block/block_io_start")
int block_io_stacks_start(BlockIOCtx *ctx)
{
  if (
    block_io_stacks_sample_threshold == 0 ||
    bpf_get_prandom_u32() > block_io_stacks_sample_threshold) {
    return 0;
  }

  u32 zero            = 0;
  BlockIOStart *start = bpf_map_lookup_elem(&block_io_stacks_scratch, &zero);
  if (!start) {
    return 0;
  }

  u64 pid_tgid      = bpf_get_current_pid_tgid();
  start->pid        = pid_tgid >> 32;
  start->tid        = pid_tgid & 0xffffffff;
  start->timestamp  = bpf_ktime_get_ns();
  start->num_frames = 0;

  long stack_bytes =
    bpf_get_stack(ctx, start->stack, PERF_MAX_STACK_DEPTH * sizeof(start->stack[0]), 0);
  if (stack_bytes <= 0) {
    return 0;
  }
  start->num_frames = stack_bytes / sizeof(start->stack[0]);
  bpf_get_current_comm(start->comm, sizeof(start->comm));
  __builtin_memcpy(start->rwbs, ctx->rwbs, sizeof(start->rwbs));

  BlockIOKey key = {
    .dev    = ctx->dev,
    .sector = ctx->sector,
  };
  bpf_map_update_elem(&block_io_stacks_inflight, &key, start, BPF_ANY);
  return 0;
}

SEC("tracepoint/block/block_rq_issue")
int block_io_stacks_issue(BlockIOCtx *ctx)
{
  BlockIOKey key = {
    .dev    = ctx->dev,
    .sector = ctx->sector,
  };
  BlockIOStart *start = bpf_map_lookup_elem(&block_io_stacks_inflight, &key);
  if (!start) {
    return 0;
  }

  u64 timestamp = bpf_ktime_get_ns();
  if (timestamp < start->timestamp || timestamp - start->timestamp < block_io_stacks_min_ns) {
    bpf_map_delete_elem(&block_io_stacks_inflight, &key);
    return 0;
  }

  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    bpf_map_delete_elem(&block_io_stacks_inflight, &key);
    return 0;
  }

  Trace *trace  = &record->trace;
  trace->origin = block_io_stacks_origin;
  trace->pid    = start->pid;
  trace->tid    = start->tid;
  trace->ktime  = timestamp;
  trace->value  = timestamp - start->timestamp;
  trace->cpu_id = bpf_get_smp_processor_id();
  __builtin_memcpy(trace->comm, start->comm, sizeof(trace->comm));

  u16 num_frames = start->num_frames;
  if (num_frames > PERF_MAX_STACK_DEPTH) {
    num_frames = PERF_MAX_STACK_DEPTH;
  }
#pragma unroll
  for (int i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
    if (i < num_frames) {
      trace->frame_data[i] = start->stack[i];
    }
  }
  trace->num_kernel_frames = num_frames;
  trace->frame_data_len    = num_frames;

  CustomLabel *operation = &trace->custom_labels.labels[0];
  __builtin_memcpy(operation->key, "io.operation", sizeof("io.operation"));
  __builtin_memcpy(operation->val, start->rwbs, sizeof(start->rwbs));
  operation->val[sizeof(start->rwbs)] = 0;

  // Preserve dev_t as a fixed-width hexadecimal label without expensive
  // decimal conversion in the completion path.
  CustomLabel *device = &trace->custom_labels.labels[1];
  __builtin_memcpy(device->key, "io.device", sizeof("io.device"));
#pragma unroll
  for (int i = 0; i < sizeof(ctx->dev) * 2; i++) {
    u8 shift       = (sizeof(ctx->dev) * 2 - i - 1) * 4;
    device->val[i] = hex_digit((ctx->dev >> shift) & 0xf);
  }
  device->val[sizeof(ctx->dev) * 2] = 0;
  trace->custom_labels_type         = CUSTOM_LABELS_TYPE_GO;
  trace->custom_labels.len          = 2;

  send_trace(ctx, trace);
  bpf_map_delete_elem(&block_io_stacks_inflight, &key);
  return 0;
}
