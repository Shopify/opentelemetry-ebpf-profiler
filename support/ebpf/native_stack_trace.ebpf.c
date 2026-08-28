#include "bpfdefs.h"
#include "frametypes.h"
#include "tracemgmt.h"
#include "types.h"

// with_debug_output is set during load time.
BPF_RODATA_VAR(u32, with_debug_output, 0)

// filter_idle_frames is set during load time.
BPF_RODATA_VAR(bool, filter_idle_frames, false)

// filter_min_process_age_ns is set during load time.
BPF_RODATA_VAR(u64, filter_min_process_age_ns, 0)

// inverse_pac_mask is set during load time.
BPF_RODATA_VAR(u64, inverse_pac_mask, 0)

// vma_lookup_enabled is set during load time.
// It is enabled only on kernels where the loaded BPF object can call bpf_find_vma().
BPF_RODATA_VAR(bool, vma_lookup_enabled, false)

// vma_vm_file_offset is set during load time.
// The offset of vm_file within vm_area_struct.
BPF_RODATA_VAR(u32, vma_vm_file_offset, 0)

// vma_vm_flags_offset is set during load time.
// The offset of vm_flags, or __vm_flags, within vm_area_struct.
BPF_RODATA_VAR(u32, vma_vm_flags_offset, 0)

// tpbase_offset is set during load time.
// The offset of the Thread Pointer Base variable in `task_struct`. It is
// populated by the host agent based on kernel code analysis.
BPF_RODATA_VAR(u64, tpbase_offset, 0)

// task_group_leader_offset is set during load time.
// The offset of group_leader within `task_struct`.
BPF_RODATA_VAR(u32, task_group_leader_offset, 0)

// task_stack_offset is set during load time.
// The offset of stack base within `task_struct`.
BPF_RODATA_VAR(u32, task_stack_offset, 0)

// task_start_time_offset is set during load time.
// The offset of start_time within `task_struct`.
BPF_RODATA_VAR(u32, task_start_time_offset, 0)

// stack_ptregs_offset is set during load time.
// The offset of struct pt_regs within the kernel entry stack.
BPF_RODATA_VAR(u32, stack_ptregs_offset, 0)

// If enabled, the profiler translates host-level PIDs/TGIDs into the
// corresponding IDs within a specific PID namespace. This is essential
// for sidecar deployments to report PIDs consistent with the container's
// internal view (e.g., reporting PID 1 instead of the host PID).
BPF_RODATA_VAR(bool, pid_ns_translation_enabled, false)

// The inode number of the target PID namespace.
// Obtained by calling stat() on /proc/self/ns/pid.
BPF_RODATA_VAR(u64, target_pid_ns_inode, 0)

// The device ID (st_dev) of the target PID namespace inode.
// Required by the bpf_get_ns_current_pid_tgid helper to uniquely
// identify the namespace filesystem (nsfs) instance.
BPF_RODATA_VAR(u64, target_pid_ns_dev, 0)
// origin_id_sampling is set during load time.
BPF_RODATA_VAR(u16, origin_id_sampling, 0)
// origin_id_hw_cpu_cycles is set during load time.
BPF_RODATA_VAR(u16, origin_id_hw_cpu_cycles, 0)
// origin_id_hw_instructions is set during load time.
BPF_RODATA_VAR(u16, origin_id_hw_instructions, 0)
// origin_id_amd_brs is set during load time.
BPF_RODATA_VAR(u16, origin_id_amd_brs, 0)
// enable_per_sample_counters is set during load time. When false, the verifier
// eliminates the perf counter read path from the software-clock entry program.
BPF_RODATA_VAR(bool, enable_per_sample_counters, false)
// enable_per_sample_branch_misses gates the additive branch-miss map read.
BPF_RODATA_VAR(bool, enable_per_sample_branch_misses, false)

#define PER_SAMPLE_COUNTER_BASE          (1ULL << 0)
#define PER_SAMPLE_COUNTER_BRANCH_MISSES (1ULL << 1)

// Readable, non-sampling perf events installed by userspace, indexed by CPU.
struct per_sample_cycles_t {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 0);
} per_sample_cycles SEC(".maps");

struct per_sample_instructions_t {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 0);
} per_sample_instructions SEC(".maps");

struct per_sample_branch_misses_t {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 0);
} per_sample_branch_misses SEC(".maps");

// Userspace sets availability bits only after every CPU fd for a counter set
// has been installed. This prevents repeated helper failures after fail-soft setup.
struct per_sample_counter_enabled_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 1);
} per_sample_counter_enabled SEC(".maps");

// One previous reading per CPU. Per-CPU storage avoids synchronization in the
// sampling path and follows the CPU-wide scope of the perf events above.
struct per_sample_counter_state_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, PerSampleCounterState);
  __uint(max_entries, 1);
} per_sample_counter_state SEC(".maps");

// Macro to create a map named exe_id_to_X_stack_deltas that is a nested maps with a fileID for the
// outer map and an array as inner map that holds up to 2^X stack delta entries for the given
// fileID.
#define STACK_DELTA_BUCKET(X)                                                                      \
  struct exe_id_to_##X##_stack_deltas_t {                                                          \
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);                                                       \
    __type(key, u64);                                                                              \
    __type(value, u32);                                                                            \
    __uint(max_entries, 4096);                                                                     \
    __array(                                                                                       \
      values, struct {                                                                             \
        __uint(type, BPF_MAP_TYPE_ARRAY);                                                          \
        __uint(max_entries, 1 << X);                                                               \
        __type(key, u32);                                                                          \
        __type(value, StackDelta);                                                                 \
      });                                                                                          \
  } exe_id_to_##X##_stack_deltas SEC(".maps");

// Create buckets to hold the stack delta information for the executables.
STACK_DELTA_BUCKET(8);
STACK_DELTA_BUCKET(9);
STACK_DELTA_BUCKET(10);
STACK_DELTA_BUCKET(11);
STACK_DELTA_BUCKET(12);
STACK_DELTA_BUCKET(13);
STACK_DELTA_BUCKET(14);
STACK_DELTA_BUCKET(15);
STACK_DELTA_BUCKET(16);
STACK_DELTA_BUCKET(17);
STACK_DELTA_BUCKET(18);
STACK_DELTA_BUCKET(19);
STACK_DELTA_BUCKET(20);
STACK_DELTA_BUCKET(21);
STACK_DELTA_BUCKET(22);
STACK_DELTA_BUCKET(23);

// An array of unwind info contains the all the different UnwindInfo instances
// needed system wide. Individual stack delta entries refer to this array.
struct unwind_info_array_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, UnwindInfo);
  __uint(max_entries, UNWIND_INFO_MAX_ENTRIES);
} unwind_info_array SEC(".maps");

// The decision whether to unwind native stacks or interpreter stacks is made by checking if a given
// PC address falls into the "interpreter loop" of an interpreter. This map helps identify such
// loops: The keys are those executable section IDs that contain interpreter loops, the values
// identify the offset range within this executable section that contains the interpreter loop.
struct interpreter_offsets_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, OffsetRange);
  __uint(max_entries, 32);
} interpreter_offsets SEC(".maps");

// Maps fileID and page to information of stack deltas associated with that page.
struct stack_delta_page_to_info_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, StackDeltaPageKey);
  __type(value, StackDeltaPageInfo);
  __uint(max_entries, 40000);
} stack_delta_page_to_info SEC(".maps");

#include "native_stack_trace.h"

// unwind_native is the tail call destination for PROG_UNWIND_NATIVE.
static EBPF_INLINE int unwind_native(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  int unwinder;
  ErrorCode error;
  for (int i = 0; i < NATIVE_FRAMES_PER_PROGRAM; i++) {
    unwinder = PROG_UNWIND_STOP;

    // Unwind native code
    DEBUG_PRINT("==== unwind_native %d ====", trace->num_frames);
    increment_metric(metricID_UnwindNativeAttempts);

    // Push frame first. The PC is valid because a text section mapping was found.
    DEBUG_PRINT(
      "Pushing %llx %llx to position %u on stack",
      record->state.text_section_id,
      record->state.text_section_offset,
      trace->num_frames);
    error = push_native(
      &record->state,
      trace,
      record->state.text_section_id,
      record->state.text_section_offset,
      record->state.return_address);
    if (error) {
      DEBUG_PRINT("failed to push native frame");
      break;
    }

    // Unwind the native frame using stack deltas. Stop if no next frame.
    bool stop;
    // This program can unwind Go frames, so no frame is delegated.
    error = unwind_one_frame(record, &stop, NULL);
    if (error || stop) {
      break;
    }

    // Continue unwinding
    DEBUG_UNWIND_STATE(&record->state);
    error = get_next_unwinder_after_native_frame(record, &unwinder);
    if (error || unwinder != PROG_UNWIND_NATIVE) {
      break;
    }
  }

  // Tail call needed for recursion, switching to interpreter unwinder, or reporting
  // trace due to end-of-trace or error. The unwinder program index is set accordingly.
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("bpf_tail call failed for %d in unwind_native", unwinder);
  return -1;
}

// scale_counter_delta computes floor(raw * enabled / running). The fast path
// preserves full precision. The overflow fallback divides first, saturates if
// the integral term overflows, and conservatively omits an unsafe fractional
// multiplication rather than wrapping the reported delta.
static inline u64 scale_counter_delta(u64 raw, u64 enabled, u64 running)
{
  const u64 max_u64 = ~(u64)0;
  if (!raw || !enabled || !running) {
    return 0;
  }

  if (raw <= max_u64 / enabled) {
    return raw * enabled / running;
  }

  u64 quotient  = raw / running;
  u64 remainder = raw % running;
  if (quotient > max_u64 / enabled) {
    return max_u64;
  }

  u64 scaled = quotient * enabled;
  if (remainder <= max_u64 / enabled) {
    u64 fractional = remainder * enabled / running;
    if (fractional > max_u64 - scaled) {
      return max_u64;
    }
    scaled += fractional;
  }
  return scaled;
}

static inline u64 read_counter_delta(void *events, PerfCounterValue *previous, bool *previous_valid)
{
  PerfCounterValue current = {};
  if (bpf_perf_event_read_value(events, BPF_F_CURRENT_CPU, &current, sizeof(current)) < 0) {
    // Do not bridge a failed interval into the next sampled stack.
    *previous_valid = false;
    return 0;
  }

  u64 scaled = 0;
  if (
    *previous_valid && current.value >= previous->value && current.enabled >= previous->enabled &&
    current.running >= previous->running) {
    u64 raw_delta     = current.value - previous->value;
    u64 enabled_delta = current.enabled - previous->enabled;
    u64 running_delta = current.running - previous->running;
    if (running_delta != 0) {
      scaled = scale_counter_delta(raw_delta, enabled_delta, running_delta);
    }
  }

  *previous       = current;
  *previous_valid = true;
  return scaled;
}

static inline void
collect_per_sample_counters(u64 *cycles_delta, u64 *instructions_delta, u64 *branch_misses_delta)
{
  *cycles_delta        = 0;
  *instructions_delta  = 0;
  *branch_misses_delta = 0;
  if (!enable_per_sample_counters) {
    return;
  }

  u32 key                     = 0;
  PerSampleCounterState *prev = bpf_map_lookup_elem(&per_sample_counter_state, &key);
  u64 *enabled                = bpf_map_lookup_elem(&per_sample_counter_enabled, &key);
  if (!prev || !enabled) {
    return;
  }

  if (*enabled & PER_SAMPLE_COUNTER_BASE) {
    *cycles_delta = read_counter_delta(&per_sample_cycles, &prev->cycles, &prev->cycles_valid);
    *instructions_delta =
      read_counter_delta(&per_sample_instructions, &prev->instructions, &prev->instructions_valid);
  }
  if (enable_per_sample_branch_misses && (*enabled & PER_SAMPLE_COUNTER_BRANCH_MISSES)) {
    *branch_misses_delta = read_counter_delta(
      &per_sample_branch_misses, &prev->branch_misses, &prev->branch_misses_valid);
  }

  static inline int native_tracer_entry_impl(
    struct bpf_perf_event_data * ctx, u16 origin, bool is_amd_brs, bool read_counters)
  {
    u64 cycles_delta        = 0;
    u64 instructions_delta  = 0;
    u64 branch_misses_delta = 0;
    if (read_counters) {
      collect_per_sample_counters(&cycles_delta, &instructions_delta, &branch_misses_delta);
    }
    u32 pid = 0;
    u32 tid = 0;
    if (!get_pid_tgid(&pid, &tid)) {
      return 0;
    }

    if (pid == 0 && filter_idle_frames) {
      return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    if (is_amd_brs) {
      return collect_lbr_only_trace((struct pt_regs *)&ctx->regs, origin, pid, tid, ts);
    }
    return collect_trace(
      (struct pt_regs *)&ctx->regs,
      origin,
      pid,
      tid,
      ts,
      0,
      cycles_delta,
      instructions_delta,
      branch_misses_delta);
  }

  SEC("perf_event/native_tracer_entry_sw_cpu_clock")
  int native_tracer_entry_sw_cpu_clock(struct bpf_perf_event_data * ctx)
  {
    return native_tracer_entry_impl(ctx, origin_id_sampling, false, true);
  }

  SEC("perf_event/native_tracer_entry_hw_cpu_cycles")
  int native_tracer_entry_hw_cpu_cycles(struct bpf_perf_event_data * ctx)
  {
    return native_tracer_entry_impl(ctx, origin_id_hw_cpu_cycles, false, false);
  }

  SEC("perf_event/native_tracer_entry_hw_instructions")
  int native_tracer_entry_hw_instructions(struct bpf_perf_event_data * ctx)
  {
    return native_tracer_entry_impl(ctx, origin_id_hw_instructions, false, false);
  }

  SEC("perf_event/native_tracer_entry_amd_brs")
  int native_tracer_entry_amd_brs(struct bpf_perf_event_data * ctx)
  {
    return native_tracer_entry_impl(ctx, origin_id_amd_brs, true, false);
  }
  MULTI_USE_FUNC(unwind_native)
