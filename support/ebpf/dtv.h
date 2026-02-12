// DTV (Dynamic Thread Vector) TLS access helper shared across interpreters.
//
// Callers must include bpfdefs.h, tsd.h (and their transitive deps like types.h,
// tracemgmt.h) before including this header.

#ifndef OPTI_DTV_H
#define OPTI_DTV_H

// read_tls_addr_from_dtv resolves a TLS variable address via the DTV (for dlopen'd libraries).
// `symbol` is the offset of the variable within the module's TLS block.
// `module_id` is the DTPMOD module ID.
// `dtv_step` is the DTV entry stride (typically 16 = sizeof(void*) * 2).
// Returns the resolved address or 0 on failure.
static EBPF_INLINE u64 read_tls_addr_from_dtv(u64 symbol, u32 module_id, u32 dtv_step)
{
  int err;
  u64 addr;

  u64 tsd_base;
  if (tsd_get_base((void **)&tsd_base) != 0) {
    DEBUG_PRINT("dtv: failed to get TSD base for TLS symbol lookup");
    return 0;
  }

  u64 dtv_addr;
  // On x86-64, the FS register points to the TCB
  // The DTV is typically at offset 0 or 8 from the TCB
  // https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86_64/nptl/tls.h;h=683f8bfdfcad45734c4cc1aeea844582a5528640;hb=HEAD#l46
  if ((err = bpf_probe_read_user(&dtv_addr, sizeof(void *), (void *)(tsd_base + 8)))) {
    DEBUG_PRINT("dtv: failed to read TLS DTV addr: %d", err);
    return 0;
  }

  // DTV layout is the same across architectures:
  // DTV[0] = generation counter
  // DTV[1] = module 1's TLS block
  // DTV[2] = module 2's TLS block
  // ...
  u64 dtv_offset = module_id * dtv_step;

  if ((err = bpf_probe_read_user(&addr, sizeof(void *), (void *)(dtv_addr + dtv_offset)))) {
    DEBUG_PRINT(
      "dtv: failed to read TLS block addr for module %d at DTV offset %llu: %d",
      module_id,
      dtv_offset,
      err);
    return 0;
  }
  addr += symbol;
  return addr;
}

#endif // OPTI_DTV_H
