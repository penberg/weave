# Regression test: LDR Ft, [PC+imm] must not clobber guest GPRs
#
# The translator must not clobber guest-visible registers when expanding
# FP literal loads. We save/restore any scratch we use (x11). This test
# sets x17 and x11 to known values, performs FP literal loads (s and d),
# and verifies both survive.
#
# CHECK: PASS: x17_surv
# CHECK: PASS: x11_surv

.global _main

_main:
    // x17 := 0x123456789ABCDEF0
    movz x17, #0xDEF0, lsl #0
    movk x17, #0x9ABC, lsl #16
    movk x17, #0x5678, lsl #32
    movk x17, #0x1234, lsl #48

    // x11 := 0x000000000000002A
    mov  x11, #42

    // Do FP literal loads that previously clobbered x17
    ldr s0, lit_f32
    ldr d1, lit_f64
    ldr q2, lit_f128

    // Minimal check: verify lower 64 bits of q2 match lit_f128
    ldr x14, lit_f128
    fmov x15, d2
    cmp x15, x14
    b.ne test_failed

    // Verify x17 still holds the magic value (use x13 as temp to avoid clobbering x11)
    movz x13, #0xDEF0, lsl #0
    movk x13, #0x9ABC, lsl #16
    movk x13, #0x5678, lsl #32
    movk x13, #0x1234, lsl #48
    cmp x17, x13
    b.ne test_failed

    // Print PASS for x17
    mov x0, #1
    adr x1, msg
    mov x2, #15                // len("PASS: x17_surv\n") = 15
    mov x16, #4
    svc #0x80

    // Verify x11 survived and print PASS
    mov  x12, #42
    cmp  x11, x12
    b.ne test_failed
    mov x0, #1
    adr x1, msg11
    mov x2, #15                // len("PASS: x11_surv\n") = 15
    mov x16, #4
    svc #0x80

    // Exit 0
    mov x0, #0
    mov x16, #1
    svc #0x80

test_failed:
    mov x0, #1
    mov x16, #1
    svc #0x80

.p2align 2
lit_f32:
    .long 0x40000000           // 2.0f

lit_f64:
    .quad 0x4008000000000000   // 3.0

lit_f128:
    .quad 0x4008000000000000   // lower 64 bits
    .quad 0x4010000000000000   // upper 64 bits

msg:     .ascii "PASS: x17_surv\n"
msg11:   .ascii "PASS: x11_surv\n"
