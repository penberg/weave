# Test multiply and divide instructions
#
# CHECK: PASS: mul
# CHECK: PASS: smull
# CHECK: PASS: umull
# CHECK: PASS: sdiv
# CHECK: PASS: udiv
# CHECK: PASS: madd
# CHECK: PASS: msub
# CHECK: PASS: smulh
# CHECK: PASS: umulh

.global _main

_main:
    // mul: 7 * 6 = 42
    mov x0, #7
    mov x1, #6
    mul x2, x0, x1
    cmp x2, #42
    b.ne test_failed
    mov x0, #1
    adr x1, msg_mul
    mov x2, #10
    mov x16, #4
    svc #0x80

    // smull: -3 * 7 = -21 (signed 32→64)
    movn w0, #2              // w0 = -3
    mov w1, #7
    smull x2, w0, w1         // x2 = -21
    cmn x2, #21              // x2 + 21 == 0?
    b.eq 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_smull
    mov x2, #12
    mov x16, #4
    svc #0x80

    // umull: 30 * 40 = 1200 (unsigned 32→64)
    mov w0, #30
    mov w1, #40
    umull x2, w0, w1
    cmp x2, #1200
    b.ne test_failed
    mov x0, #1
    adr x1, msg_umull
    mov x2, #12
    mov x16, #4
    svc #0x80

    // sdiv: 42 / 6 = 7
    mov x0, #42
    mov x1, #6
    sdiv x2, x0, x1
    cmp x2, #7
    b.ne test_failed
    mov x0, #1
    adr x1, msg_sdiv
    mov x2, #11
    mov x16, #4
    svc #0x80

    // udiv: 100 / 10 = 10
    mov x0, #100
    mov x1, #10
    udiv x2, x0, x1
    cmp x2, #10
    b.ne test_failed
    mov x0, #1
    adr x1, msg_udiv
    mov x2, #11
    mov x16, #4
    svc #0x80

    // madd: 3 * 4 + 5 = 17
    mov x0, #3
    mov x1, #4
    mov x3, #5
    madd x2, x0, x1, x3
    cmp x2, #17
    b.ne test_failed
    mov x0, #1
    adr x1, msg_madd
    mov x2, #11
    mov x16, #4
    svc #0x80

    // msub: 20 - 3 * 4 = 8
    mov x0, #3
    mov x1, #4
    mov x3, #20
    msub x2, x0, x1, x3
    cmp x2, #8
    b.ne test_failed
    mov x0, #1
    adr x1, msg_msub
    mov x2, #11
    mov x16, #4
    svc #0x80

    // smulh: (2^32) * (2^32) → upper 64 bits = 1
    movz x0, #1, lsl #32     // x0 = 2^32
    movz x1, #1, lsl #32     // x1 = 2^32
    smulh x2, x0, x1         // upper 64 of (2^32 * 2^32) = upper 64 of 2^64 = 1
    cmp x2, #1
    b.ne test_failed
    mov x0, #1
    adr x1, msg_smulh
    mov x2, #12
    mov x16, #4
    svc #0x80

    // umulh: same as smulh for positive values
    movz x0, #1, lsl #32
    movz x1, #1, lsl #32
    umulh x2, x0, x1
    cmp x2, #1
    b.ne test_failed
    mov x0, #1
    adr x1, msg_umulh
    mov x2, #12
    mov x16, #4
    svc #0x80

    // All passed
    mov x0, #0
    mov x16, #1
    svc #0x80

test_failed:
    mov x0, #1
    mov x16, #1
    svc #0x80

msg_mul:   .ascii "PASS: mul\n"
msg_smull: .ascii "PASS: smull\n"
msg_umull: .ascii "PASS: umull\n"
msg_sdiv:  .ascii "PASS: sdiv\n"
msg_udiv:  .ascii "PASS: udiv\n"
msg_madd:  .ascii "PASS: madd\n"
msg_msub:  .ascii "PASS: msub\n"
msg_smulh: .ascii "PASS: smulh\n"
msg_umulh: .ascii "PASS: umulh\n"
