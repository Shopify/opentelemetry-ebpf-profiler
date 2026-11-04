// Hand-written assembly whose symbols lack the `.type` or `.size` directives that
// compilers always emit. Built into `asm-symbols` (see Makefile).

    .text

    // Normal function: STT_FUNC with a size. The untyped alias at the same address
    // must not hide or split it.
    .globl sized_func
    .type sized_func, %function
    .globl sized_func_alias
sized_func_alias:
sized_func:
    nop
    ret
    .size sized_func, .-sized_func

    // STT_FUNC without `.size`, e.g. ONNX Runtime's MLAS kernels.
    .globl sizeless_func
    .type sizeless_func, %function
sizeless_func:
    nop
    nop
    ret

    // Neither `.type` nor `.size` (STT_NOTYPE), e.g. Ruby's `coroutine_transfer`.
    .globl untyped_label
untyped_label:
    nop
    ret

    // STT_NOTYPE with a size.
    .globl sized_label
sized_label:
    nop
    ret
    .size sized_label, .-sized_label

    // A label inside a sized function is part of that function.
    .globl outer_func
    .type outer_func, %function
outer_func:
    nop
inner_label:
    nop
    ret
    .size outer_func, .-outer_func

    // The last symbol of a section extends to the end of the section.
    .globl last_sizeless_func
    .type last_sizeless_func, %function
last_sizeless_func:
    nop
    nop
    nop
    ret

    .data

    // Not code: labels outside executable sections are ignored.
    .globl data_label
data_label:
    .quad 0
