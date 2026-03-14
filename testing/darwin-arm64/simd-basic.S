# Test basic SIMD and floating-point operations
#
# CHECK: PASS: fmov
# CHECK: PASS: fadd
# CHECK: PASS: fsub
# CHECK: PASS: fmul
# CHECK: PASS: fdiv
# CHECK: PASS: fcvt
# CHECK: PASS: vec_add

.global _main

_main:
    // fmov: load FP immediate, convert to int, verify
    fmov d0, #1.0
    fcvtzs x0, d0
    cmp x0, #1
    b.ne test_failed
    mov x0, #1
    adr x1, msg_fmov
    mov x2, #11
    mov x16, #4
    svc #0x80

    // fadd: 2.0 + 3.0 = 5.0
    fmov d0, #2.0
    fmov d1, #3.0
    fadd d2, d0, d1
    fcvtzs x0, d2
    cmp x0, #5
    b.ne test_failed
    mov x0, #1
    adr x1, msg_fadd
    mov x2, #11
    mov x16, #4
    svc #0x80

    // fsub: 8.0 - 3.0 = 5.0
    fmov d0, #8.0
    fmov d1, #3.0
    fsub d2, d0, d1
    fcvtzs x0, d2
    cmp x0, #5
    b.ne test_failed
    mov x0, #1
    adr x1, msg_fsub
    mov x2, #11
    mov x16, #4
    svc #0x80

    // fmul: 3.0 * 4.0 = 12.0
    fmov d0, #3.0
    fmov d1, #4.0
    fmul d2, d0, d1
    fcvtzs x0, d2
    cmp x0, #12
    b.ne test_failed
    mov x0, #1
    adr x1, msg_fmul
    mov x2, #11
    mov x16, #4
    svc #0x80

    // fdiv: 8.0 / 2.0 = 4.0
    fmov d0, #8.0
    fmov d1, #2.0
    fdiv d2, d0, d1
    fcvtzs x0, d2
    cmp x0, #4
    b.ne test_failed
    mov x0, #1
    adr x1, msg_fdiv
    mov x2, #11
    mov x16, #4
    svc #0x80

    // fcvt: single to double conversion
    fmov s0, #2.0
    fcvt d1, s0
    fcvtzs x0, d1
    cmp x0, #2
    b.ne test_failed
    mov x0, #1
    adr x1, msg_fcvt
    mov x2, #11
    mov x16, #4
    svc #0x80

    // Vector add: v0 = {1,2,3,4}, v1 = {10,20,30,40}, v2 = v0+v1
    adr x0, vec_a
    ldr q0, [x0]
    adr x0, vec_b
    ldr q1, [x0]
    add v2.4s, v0.4s, v1.4s
    mov w0, v2.s[0]           // extract first element
    cmp w0, #11               // 1 + 10 = 11
    b.ne test_failed
    mov w0, v2.s[1]
    cmp w0, #22               // 2 + 20 = 22
    b.ne test_failed
    mov x0, #1
    adr x1, msg_vec_add
    mov x2, #14
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

msg_fmov:    .ascii "PASS: fmov\n"
msg_fadd:    .ascii "PASS: fadd\n"
msg_fsub:    .ascii "PASS: fsub\n"
msg_fmul:    .ascii "PASS: fmul\n"
msg_fdiv:    .ascii "PASS: fdiv\n"
msg_fcvt:    .ascii "PASS: fcvt\n"
msg_vec_add: .ascii "PASS: vec_add\n"

.p2align 4
vec_a: .long 1, 2, 3, 4
vec_b: .long 10, 20, 30, 40
