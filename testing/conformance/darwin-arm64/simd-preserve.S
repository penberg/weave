# Test callee-saved SIMD register preservation (d8-d15)
#
# CHECK: PASS: d8_preserved
# CHECK: PASS: d9_preserved
# CHECK: PASS: d10_preserved
# CHECK: PASS: d11_preserved

.global _main

_clobber_simd:
    // Clobber caller-saved FP registers
    fmov d0, #1.0
    fmov d1, #2.0
    fmov d2, #3.0
    fmov d3, #4.0
    fmov d4, #5.0
    fmov d5, #6.0
    fmov d6, #7.0
    fmov d7, #8.0
    ret

_main:
    // Save link register
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // Load known values into callee-saved FP regs
    fmov d8, #10.0
    fmov d9, #11.0
    fmov d10, #12.0
    fmov d11, #13.0

    // Call function that clobbers d0-d7
    bl _clobber_simd

    // Verify d8 preserved
    fcvtzs x0, d8
    cmp x0, #10
    b.ne test_failed
    mov x0, #1
    adr x1, msg_d8
    mov x2, #19
    mov x16, #4
    svc #0x80

    // Verify d9 preserved
    fcvtzs x0, d9
    cmp x0, #11
    b.ne test_failed
    mov x0, #1
    adr x1, msg_d9
    mov x2, #19
    mov x16, #4
    svc #0x80

    // Verify d10 preserved
    fcvtzs x0, d10
    cmp x0, #12
    b.ne test_failed
    mov x0, #1
    adr x1, msg_d10
    mov x2, #20
    mov x16, #4
    svc #0x80

    // Verify d11 preserved
    fcvtzs x0, d11
    cmp x0, #13
    b.ne test_failed
    mov x0, #1
    adr x1, msg_d11
    mov x2, #20
    mov x16, #4
    svc #0x80

    // All passed
    ldp x29, x30, [sp], #16
    mov x0, #0
    mov x16, #1
    svc #0x80

test_failed:
    ldp x29, x30, [sp], #16
    mov x0, #1
    mov x16, #1
    svc #0x80

msg_d8:  .ascii "PASS: d8_preserved\n"
msg_d9:  .ascii "PASS: d9_preserved\n"
msg_d10: .ascii "PASS: d10_preserved\n"
msg_d11: .ascii "PASS: d11_preserved\n"
