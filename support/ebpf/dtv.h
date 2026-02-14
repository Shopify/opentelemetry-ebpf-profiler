// DTV (Dynamic Thread Vector) TLS access helper shared across interpreters.
//
// Callers must include bpfdefs.h, tsd.h (and their transitive deps like types.h,
// tracemgmt.h) before including this header.

#ifndef OPTI_DTV_H
#define OPTI_DTV_H

// read_tls_addr_from_dtv resolves a TLS variable address via the DTV (for dlopen'd libraries).
// `symbol` is the offset of the variable within the module's TLS block.
// `module_id` is the DTPMOD module ID.
// `dtv_off` is the byte offset from TP (or from the indirect pointer) to the DTV pointer.
// `dtv_step` is the DTV entry stride (16 for glibc, 8 for musl).
// `dtv_indirect` if 1, dereference TP+0 first then add dtv_off (aarch64 glibc/musl pattern).
// Returns the resolved address or 0 on failure.
static EBPF_INLINE u64 read_tls_addr_from_dtv(u64 symbol, u32 module_id,
                                               s16 dtv_off, u8 dtv_step, u8 dtv_indirect)
{
  int err;
  u64 addr;

  u64 tsd_base;
  if (tsd_get_base((void **)&tsd_base) != 0) {
    DEBUG_PRINT("[TLCR] dtv: failed to get TSD base");
    return 0;
  }

  // Find the DTV pointer. The access pattern varies by libc and architecture:
  //   glibc x86_64:  DTV = *(TP + 8)           [indirect=0, offset=8]
  //   glibc aarch64: DTV = *(*(TP + 0) + 0)    [indirect=1, offset=0]
  //   musl  x86_64:  DTV = *(*(TP + 0) + 8)    [indirect=1, offset=8]
  //   musl  aarch64: DTV = *(*(TP + 0) + (-8))  [indirect=1, offset=-8]
  u64 dtv_ptr_base = tsd_base;
  if (dtv_indirect) {
    if ((err = bpf_probe_read_user(&dtv_ptr_base, sizeof(void *), (void *)tsd_base))) {
      DEBUG_PRINT("[TLCR] dtv: failed indirect base read: %d", err);
      return 0;
    }
  }

  u64 dtv_addr;
  if ((err = bpf_probe_read_user(&dtv_addr, sizeof(void *),
                                 (void *)((s64)dtv_ptr_base + dtv_off)))) {
    DEBUG_PRINT("[TLCR] dtv: failed DTV ptr read at base+%d: %d", dtv_off, err);
    return 0;
  }

  // DTV layout: DTV[0] = generation counter, DTV[module_id] = TLS block pointer
  u64 dtv_entry_offset = (u64)module_id * (u64)dtv_step;

  if ((err = bpf_probe_read_user(&addr, sizeof(void *),
                                 (void *)(dtv_addr + dtv_entry_offset)))) {
    DEBUG_PRINT("[TLCR] dtv: failed TLS block read mod=%d off=%llu: %d",
                module_id, dtv_entry_offset, err);
    return 0;
  }

  addr += symbol;
  return addr;
}

#endif // OPTI_DTV_H
