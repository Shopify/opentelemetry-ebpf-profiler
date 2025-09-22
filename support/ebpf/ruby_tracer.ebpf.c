// This file contains the code and map definitions for the Ruby tracer

#include "ruby_tracer.h"
#include "bpfdefs.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"

// Map from Ruby process IDs to a structure containing addresses of variables
// we require in order to build the stack trace
bpf_map_def SEC("maps") ruby_procs = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(pid_t),
  .value_size  = sizeof(RubyProcInfo),
  .max_entries = 1024,
};

// The number of Ruby frames to unwind per frame-unwinding eBPF program. If
// we start running out of instructions in the walk_ruby_stack program, one
// option is to adjust this number downwards.
// NOTE the maximum size stack is this times 33
#define FRAMES_PER_WALK_RUBY_STACK 64

// Ruby VM frame flags are internal indicators for the VM interpreter to
// treat frames in a dedicated way.
// https://github.com/ruby/ruby/blob/5741ae379b2037ad5968b6994309e1d25cda6e1a/vm_core.h#L1208
#define RUBY_FRAME_FLAG_BMETHOD 0x0040
#define RUBY_FRAME_FLAG_LAMBDA  0x0100

#define VM_ENV_FLAG_LOCAL 0x02
#define RUBY_FL_USHIFT    12
#define IMEMO_MASK        0x0f
#define IMEMO_CREF        1 /*!< class reference */
#define IMEMO_SVAR        2 /*!< special variable */
#define IMEMO_MENT        6

// https://github.com/ruby/ruby/blob/2083fa89fc29005035c1a098185c4b707686a437/vm_core.h#L1415-L1416
// NOTE - we do byte-indexing in kernel space, but array in userspace offsets by type size
#define VM_ENV_DATA_INDEX_ME_CREF (-2 * sizeof(size_t)) /* ep[-2] */
#define VM_ENV_DATA_INDEX_SPECVAL (-1 * sizeof(size_t)) /* ep[-1] */

// Record a Ruby cfp frame
// Accept a flag to mask into the upper bits of file so we can indicate,
// what type of "extra" address we are sending, if any.
// eg: 0x0 -> nothing extra is packed
//     0x1 -> it contains the cfp, which may be more volatile
//     0x2 -> it contains the method entry we were able to resolve
//     0x3 -> it contains the ep or something else, in the future
// this can be masked out of File in userspace, since we only need 48 bits for the address
// when processing the "extra" we can use this to determine if we should just
// treat it as a method entry right away, or need to do additional parsing
// Note that extra contains only 48 bits, and we are using the upper bits of file to store the type
// info
static EBPF_INLINE ErrorCode
push_ruby_extra(Trace *trace, u64 file, u64 line, u64 extra, u8 extra_addr_type)
{
  if (extra_addr_type != ADDR_TYPE_NONE) {
    // Ensure address is actually no more than 48-bits
    u64 addr = file & ADDR_MASK_48_BIT;
    if (addr != file) {
      DEBUG_PRINT("ruby: error pushing extra addr, file data was more than 48 bits");
    } else {
      // Shift data to bits 48-55
      u64 packed = addr | ((u64)extra_addr_type << 48);
      file       = packed;
    }
  }
  return _push_with_extra(trace, file, line, extra, FRAME_MARKER_RUBY);
}

// Check for ruby method entry
// this uses the heuristic that often the CME will be in the first local entry
// if it isn't, it will return the EP
static EBPF_INLINE int check_method_entry(
  const u64 ep, u64 *extra_addr, u8 *addr_type)
{
  u64 env_me_cref = 0;

  if (bpf_probe_read_user(
        &env_me_cref, sizeof(env_me_cref), (void *)(ep + VM_ENV_DATA_INDEX_ME_CREF))) {
    DEBUG_PRINT("ruby: failed to get env_me_cref");
    return -1;
  }

  if (env_me_cref == 0) {
    return -1;
  }

  // should be at offset 0 on the struct, and size of VALUE, so u64 should fit it
  u64 rbasic_flags = 0;

  DEBUG_PRINT("ruby: checking %llx", env_me_cref);
  if (bpf_probe_read_user(&rbasic_flags, sizeof(rbasic_flags), (void *)(env_me_cref))) {
    DEBUG_PRINT("ruby: failed to read flags to check method entry %llx", env_me_cref);
    return -1;
  }

  if (((rbasic_flags >> RUBY_FL_USHIFT) & IMEMO_MASK)== IMEMO_MENT) {
    DEBUG_PRINT("ruby: imemo type is method entry");
    *addr_type  = ADDR_TYPE_CME;
    *extra_addr = env_me_cref;
    return 0;
  }
  return -1;
}

// walk_ruby_stack processes a Ruby VM stack, extracts information from the individual frames and
// pushes this information to user space for symbolization of these frames.
//
// Ruby unwinder workflow:
// From the current execution context struct [0] we can get pointers to the current Ruby VM stack
// as well as to the current call frame pointer (cfp).
// On the Ruby VM stack we have for each cfp one struct [1]. These cfp structs then point to
// instruction sequence (iseq) structs [2] that store the information about file and function name
// that we forward to user space for the symbolization process of the frame, or they may
// point to a callable method entry (cme) [3]. In the Ruby's own backtrace functions, they
// may store either of these [4]. In the case of a cme, since ruby 3.3.0 [5] class names
// have been stored as an easily accessible struct member on the classext, accessible
// through the cme. We will check the frame for IMEMO_MENT to see if it is a cme frame,
// and if so we will try to get the classname. The iseq body is accessible through
// additional indirection of the cme, so we can still get the file and function names
// through the existing method.
//
// If the frame is a cme, we will push it with a separate frame type to userspace
// so that the Symbolizer will know what type of pointer we have given it, and
// can search the struct at the right offsets for the classpath and iseq body.
//
// If the frame is the iseq type, the original logic of just extracting the function
// and file names and line numbers is executed.
//
// [0] rb_execution_context_struct
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L843
//
// [1] rb_control_frame_struct
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L760
//
// [3] rb_callable_method_entry_struct
// https://github.com/ruby/ruby/blob/fd59ac6410d0cc93a8baaa42df77491abdb2e9b6/method.h#L63-L69
//
// [4] thread_profile_frames frame storage of cme or iseq
// https://github.com/ruby/ruby/blob/fd59ac6410d0cc93a8baaa42df77491abdb2e9b6/vm_backtrace.c#L1754-L1761
//
// [5] classpath stored as struct member instead of ivar
// https://github.com/ruby/ruby/commit/abff5f62037284024aaf469fc46a6e8de98fa1e3

static EBPF_INLINE ErrorCode walk_ruby_stack(
  PerCPURecord *record,
  const RubyProcInfo *rubyinfo,
  const void *current_ctx_addr,
  int *next_unwinder)
{
  if (!current_ctx_addr) {
    *next_unwinder = get_next_unwinder_after_interpreter();
    return ERR_OK;
  }

  Trace *trace = &record->trace;

  *next_unwinder = PROG_UNWIND_STOP;

  // stack_ptr points to the frame of the Ruby VM call stack that will be unwound next
  void *stack_ptr        = record->rubyUnwindState.stack_ptr;
  // last_stack_frame points to the last frame on the Ruby VM stack we want to process
  void *last_stack_frame = record->rubyUnwindState.last_stack_frame;

  if (!stack_ptr || !last_stack_frame) {
    // stack_ptr_current points to the current frame in the Ruby VM call stack
    void *stack_ptr_current;
    // stack_size does not reflect the number of frames on the Ruby VM stack
    // but contains the current stack size in words.
    // stack_size = size in word (size in bytes / sizeof(VALUE))
    // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L846
    size_t stack_size;

    if (bpf_probe_read_user(
          &stack_ptr_current,
          sizeof(stack_ptr_current),
          (void *)(current_ctx_addr + rubyinfo->vm_stack))) {
      DEBUG_PRINT("ruby: failed to read current stack pointer");
      increment_metric(metricID_UnwindRubyErrReadStackPtr);
      return ERR_RUBY_READ_STACK_PTR;
    }

    if (bpf_probe_read_user(
          &stack_size, sizeof(stack_size), (void *)(current_ctx_addr + rubyinfo->vm_stack_size))) {
      DEBUG_PRINT("ruby: failed to get stack size");
      increment_metric(metricID_UnwindRubyErrReadStackSize);
      return ERR_RUBY_READ_STACK_SIZE;
    }

    // Calculate the base of the stack so we can calculate the number of frames from it.
    // Ruby places two dummy frames on the Ruby VM stack in which we are not interested.
    // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_backtrace.c#L477-L485
    last_stack_frame = stack_ptr_current + (rubyinfo->size_of_value * stack_size) -
                       (2 * rubyinfo->size_of_control_frame_struct);

    if (bpf_probe_read_user(
          &stack_ptr, sizeof(stack_ptr), (void *)(current_ctx_addr + rubyinfo->cfp))) {
      DEBUG_PRINT("ruby: failed to get cfp");
      increment_metric(metricID_UnwindRubyErrReadCfp);
      return ERR_RUBY_READ_CFP;
    }
  }

  // iseq_addr holds the address to a rb_iseq_struct struct
  void *iseq_addr;
  // iseq_body points to a rb_iseq_constant_body struct
  void *iseq_body;
  // pc stores the Ruby VM program counter information
  u64 pc;
  // iseq_encoded holds the instruction address and operands of a particular instruction sequence
  // The format of this element is documented in:
  // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L328-L348
  u64 iseq_encoded;
  // iseq_size holds the size in bytes of a particular instruction sequence
  u32 iseq_size;
  s64 n;
  u64 extra_addr;
  u8 extra_addr_type;

  UNROLL for (u32 i = 0; i < FRAMES_PER_WALK_RUBY_STACK; ++i)
  {
    pc              = 0;
    iseq_addr       = NULL;
    extra_addr      = 0;
    extra_addr_type = 0;

    bpf_probe_read_user(&iseq_addr, sizeof(iseq_addr), (void *)(stack_ptr + rubyinfo->iseq));
    bpf_probe_read_user(&pc, sizeof(pc), (void *)(stack_ptr + rubyinfo->pc));

    u64 ep = 0;
    if (bpf_probe_read_user(&ep, sizeof(ep), (void *)(stack_ptr + rubyinfo->ep))) {
      DEBUG_PRINT("ruby: failed to get ep");
      increment_metric(metricID_UnwindRubyErrReadEp);
      return ERR_RUBY_READ_EP;
    }

    // If iseq or pc is 0, then this frame represents a registered hook.
    // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm.c#L1960
    if (pc == 0 || iseq_addr == NULL) {
      // Ruby frames without a PC or iseq are special frames and do not hold information
      // we can use further on. So we either skip them or ask the native unwinder to continue.

      if (rubyinfo->version < 0x20600) {
        // With Ruby version 2.6 the scope of our entry symbol ruby_current_execution_context_ptr
        // got extended. We need this extension to jump back unwinding Ruby VM frames if we
        // continue at this point with unwinding native frames.
        // As this is not available for Ruby versions < 2.6 we just skip this indicator frame and
        // continue unwinding Ruby VM frames. Due to this issue, the ordering of Ruby and native
        // frames might not be correct for Ruby versions < 2.6.
        goto skip;
      }

      if (
        (ep & (RUBY_FRAME_FLAG_LAMBDA | RUBY_FRAME_FLAG_BMETHOD)) ==
        (RUBY_FRAME_FLAG_LAMBDA | RUBY_FRAME_FLAG_BMETHOD)) {
        // When identifying Ruby lambda blocks at this point, we do not want to return to the
        // native unwinder. So we just skip this Ruby VM frame.
        goto skip;
      }

      stack_ptr += rubyinfo->size_of_control_frame_struct;
      *next_unwinder = PROG_UNWIND_NATIVE;
      goto save_state;
    }

    // This mimics the "happy path" of check_method_entry, where it succeeds on the first loop
    // write a flag to the mask-out of the "File" Id which will indicate what type of address is in
    // extra, if any: check if it is local, and if it is not, just push the next EP to check as that
    // should be a rarer case https://github.com/ruby/ruby/blob/master/vm_insnhelper.c#L770 if it is
    // local, check the method entry
    // https://github.com/ruby/ruby/blob/master/vm_insnhelper.c#L738-L762
    // if imemo type is IMEMO_MENT, then push the address of the method entry and indicate
    // the type via the flag
    // if it is NOT IMEMO_MENT, then push this to userspace and let them try to resolve it
    // this way we can do some basic checks in bpf, but not need to unroll a loop checking
    // if all of this fails, push the CFP and hopefully userspace can figure it out, or else fall
    // back to iseq body
    if (check_method_entry(ep, &extra_addr, &extra_addr_type) != 0) {
      extra_addr      = (u64)stack_ptr;
      extra_addr_type = ADDR_TYPE_CFP;
    }

    if (bpf_probe_read_user(&iseq_body, sizeof(iseq_body), (void *)(iseq_addr + rubyinfo->body))) {
      DEBUG_PRINT("ruby: failed to get iseq body");
      increment_metric(metricID_UnwindRubyErrReadIseqBody);
      return ERR_RUBY_READ_ISEQ_BODY;
    }

    if (bpf_probe_read_user(
          &iseq_encoded, sizeof(iseq_encoded), (void *)(iseq_body + rubyinfo->iseq_encoded))) {
      DEBUG_PRINT("ruby: failed to get iseq encoded");
      increment_metric(metricID_UnwindRubyErrReadIseqEncoded);
      return ERR_RUBY_READ_ISEQ_ENCODED;
    }

    if (bpf_probe_read_user(
          &iseq_size, sizeof(iseq_size), (void *)(iseq_body + rubyinfo->iseq_size))) {
      DEBUG_PRINT("ruby: failed to get iseq size");
      increment_metric(metricID_UnwindRubyErrReadIseqSize);
      return ERR_RUBY_READ_ISEQ_SIZE;
    }
    // To get the line number iseq_encoded is subtracted from pc. This result also represents the
    // size of the current instruction sequence. If the calculated size of the instruction sequence
    // is greater than the value in iseq_encoded we don't report this pc to user space.
    //
    // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_backtrace.c#L47-L48
    n = (pc - iseq_encoded) / rubyinfo->size_of_value;
    if (n > iseq_size || n < 0) {
      DEBUG_PRINT("ruby: skipping invalid instruction sequence");
      goto skip;
    }

    // For symbolization of the frame we forward the information about the instruction sequence
    // and program counter to user space.
    // From this we can then extract information like file or function name and line number.
    ErrorCode error = push_ruby_extra(trace, (u64)iseq_body, pc, extra_addr, extra_addr_type);
    if (error) {
      DEBUG_PRINT("ruby: failed to push frame");
      return error;
    }
    increment_metric(metricID_UnwindRubyFrames);

  skip:
    if (last_stack_frame <= stack_ptr) {
      // We have processed all frames in the Ruby VM and can stop here.
      *next_unwinder = PROG_UNWIND_NATIVE;
      return ERR_OK;
    }
    stack_ptr += rubyinfo->size_of_control_frame_struct;
  }
  *next_unwinder = PROG_UNWIND_RUBY;

save_state:
  // Store the current progress in the Ruby unwind state so we can continue walking the stack
  // after the tail call.
  record->rubyUnwindState.stack_ptr        = stack_ptr;
  record->rubyUnwindState.last_stack_frame = last_stack_frame;

  return ERR_OK;
}

static EBPF_INLINE u64 addr_for_tls_symbol(u64 symbol, bool dtv, u32 module_id, u32 dtv_step)
{
  u64 tsd_base;
  if (tsd_get_base((void **)&tsd_base) != 0) {
    DEBUG_PRINT("ruby: failed to get TSD base for TLS symbol lookup");
    return 0;
  }

  int err;
  u64 addr;

  if (dtv) {
    u64 dtv_addr;
#if defined(__x86_64__)
    // On x86-64, the FS register points to the TCB
    // The DTV is typically at offset 0 or 8 from the TCB
    // You may need to adjust this offset based on your glibc version

    // Try offset 8 first (common in modern glibc)
    // https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86_64/nptl/tls.h;h=683f8bfdfcad45734c4cc1aeea844582a5528640;hb=HEAD#l46
    if ((err = bpf_probe_read_user(&dtv_addr, sizeof(void *), (void *)(tsd_base + 8)))) {
      // If that fails, try offset 0
      if ((err = bpf_probe_read_user(&dtv_addr, sizeof(void *), (void *)tsd_base))) {
        DEBUG_PRINT("ruby: failed to read TLS DTV addr: %d", err);
        return 0;
      }
    }
#elif defined(__aarch64__)
    // on aarch64, it is just at tsdbase
    // https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/aarch64/nptl/tls.h;h=ede7c0ddc46fb82fa92d7abac2d5b208eeafb7d4;hb=HEAD#l45
    if ((err = bpf_probe_read_user(&dtv_addr, sizeof(void *), (void *)(tsd_base)))) {
      DEBUG_PRINT("ruby: failed to read TLS DTV addr: %d", err);
      return 0;
    }
#endif

    // DTV layout is the same across architectures:
    // DTV[0] = generation counter
    // DTV[1] = module 1's TLS block
    // DTV[2] = module 2's TLS block
    // ...
    u64 dtv_offset = module_id * dtv_step;

    if ((err = bpf_probe_read_user(&addr, sizeof(void *), (void *)(dtv_addr + dtv_offset)))) {
      DEBUG_PRINT(
        "ruby: failed to read TLS block addr for module %d at DTV offset %llu: %d",
        module_id,
        dtv_offset,
        err);
      return 0;
    }
    addr += symbol;
  } else {
    addr = tsd_base + symbol;
  }
  return addr;
}
// unwind_ruby is the tail call destination for PROG_UNWIND_RUBY.
static EBPF_INLINE int unwind_ruby(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  int unwinder           = get_next_unwinder_after_interpreter();
  ErrorCode error        = ERR_OK;
  u32 pid                = record->trace.pid;
  RubyProcInfo *rubyinfo = bpf_map_lookup_elem(&ruby_procs, &pid);
  if (!rubyinfo) {
    DEBUG_PRINT("No Ruby introspection data");
    error = ERR_RUBY_NO_PROC_INFO;
    increment_metric(metricID_UnwindRubyErrNoProcInfo);
    goto exit;
  }

  increment_metric(metricID_UnwindRubyAttempts);

  // Pointer for an address to a rb_execution_context_struct struct.
  void *current_ctx_addr = NULL;

  if (rubyinfo->version >= 0x30004) {
    // With Ruby 3.x and its internal change of the execution model, we can no longer
    // access rb_execution_context_struct directly. We will look up the
    // ruby_current_ec from thread local storage, analogous to how it is done
    // in ruby itself
    // https://github.com/ruby/ruby/blob/6c0315d99a93bdea947f821bd337000420ab41d1/vm_core.h#L2024

    u64 tls_symbol = rubyinfo->current_ec_tls_offset;
    DEBUG_PRINT("ruby: got TLS offset %llu", tls_symbol);
    // assume libruby.so is the first module, which is usually the case.
    // ruby interpreter also only triggers on libruby.so matches, so no need to check for static
    // case.
    u64 tls_current_ec_addr =
      addr_for_tls_symbol(tls_symbol, true, rubyinfo->tls_module_index, rubyinfo->dtv_entry_step);
    DEBUG_PRINT("ruby: got TLS addr 0x%llx", (u64)tls_current_ec_addr);

    if (bpf_probe_read_user(
          &current_ctx_addr, sizeof(current_ctx_addr), (void *)(tls_current_ec_addr))) {
      goto exit;
    }

    DEBUG_PRINT("ruby: EC from TLS: 0x%llx", (u64)current_ctx_addr);
  } else if (rubyinfo->version >= 0x30000) {
    // https://github.com/ruby/ruby/commit/7b3948750e1b1dd8cb271c0a7377b911bb3b8f1b
    // there is no guarantee than an EC exists before 3.0.3
    // ruby versions 3.0.0 - 3.0.3 will use a maybe invalid EC if multiple ractors / threads
    void *single_main_ractor = NULL;
    if (bpf_probe_read_user(
          &single_main_ractor, sizeof(single_main_ractor), (void *)rubyinfo->current_ctx_ptr)) {
      goto exit;
    }

    if (bpf_probe_read_user(
          &current_ctx_addr,
          sizeof(current_ctx_addr),
          (void *)(single_main_ractor + rubyinfo->running_ec))) {
      goto exit;
    }
  } else {
    if (bpf_probe_read_user(
          &current_ctx_addr, sizeof(current_ctx_addr), (void *)rubyinfo->current_ctx_ptr)) {
      goto exit;
    }
  }

  if (!current_ctx_addr) {
    goto exit;
  }

  error = walk_ruby_stack(record, rubyinfo, current_ctx_addr, &unwinder);

exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  return -1;
}
MULTI_USE_FUNC(unwind_ruby)
