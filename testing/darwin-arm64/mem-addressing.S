# Test memory addressing modes
#
# CHECK: PASS: base_imm
# CHECK: PASS: pre_index
# CHECK: PASS: post_index
# CHECK: PASS: reg_offset
# CHECK: PASS: stp_ldp
# CHECK: PASS: ldrsw

.global _main

_main:
    // Allocate stack space
    sub sp, sp, #128

    // base + immediate offset
    mov x0, #0xABCD
    str x0, [sp, #0]
    ldr x1, [sp, #0]
    cmp x0, x1
    b.ne test_failed
    mov x0, #1
    adr x1, msg_base_imm
    mov x2, #15
    mov x16, #4
    svc #0x80

    // pre-index: ldr x0, [x1, #offset]!  -- x1 updated before load
    mov x0, #0x1234
    str x0, [sp, #16]         // store at sp+16
    add x3, sp, #0            // x3 = sp
    ldr x1, [x3, #16]!        // x1 = [x3+16], x3 = x3+16
    cmp x1, x0
    b.ne test_failed
    // Verify x3 was updated
    add x4, sp, #16
    cmp x3, x4
    b.ne test_failed
    mov x0, #1
    adr x1, msg_pre_index
    mov x2, #16
    mov x16, #4
    svc #0x80

    // post-index: ldr x0, [x1], #offset  -- x1 updated after load
    mov x0, #0x5678
    str x0, [sp, #32]         // store at sp+32
    add x3, sp, #32           // x3 = sp+32
    ldr x1, [x3], #8          // x1 = [x3], x3 = x3+8
    cmp x1, x0
    b.ne test_failed
    // Verify x3 was updated to sp+40
    add x4, sp, #40
    cmp x3, x4
    b.ne test_failed
    mov x0, #1
    adr x1, msg_post_index
    mov x2, #17
    mov x16, #4
    svc #0x80

    // register offset: ldr x0, [x1, x2]
    mov x0, #0x9999
    str x0, [sp, #48]         // store at sp+48
    mov x3, sp
    mov x4, #48
    ldr x1, [x3, x4]          // load from sp + 48
    cmp x1, x0
    b.ne test_failed
    mov x0, #1
    adr x1, msg_reg_offset
    mov x2, #17
    mov x16, #4
    svc #0x80

    // stp/ldp: store pair and load pair
    mov x0, #0xAAAA
    mov x1, #0xBBBB
    stp x0, x1, [sp, #64]
    ldp x2, x3, [sp, #64]
    cmp x2, x0
    b.ne test_failed
    cmp x3, x1
    b.ne test_failed
    mov x0, #1
    adr x1, msg_stp_ldp
    mov x2, #14
    mov x16, #4
    svc #0x80

    // ldrsw: sign-extending 32-bit load
    movn w0, #0               // w0 = 0xFFFFFFFF = -1 as i32
    str w0, [sp, #80]
    ldrsw x1, [sp, #80]       // sign-extend to 64-bit
    movn x2, #0               // x2 = 0xFFFFFFFFFFFFFFFF = -1
    cmp x1, x2
    b.ne test_failed
    mov x0, #1
    adr x1, msg_ldrsw
    mov x2, #12
    mov x16, #4
    svc #0x80

    // Restore stack and exit
    add sp, sp, #128
    mov x0, #0
    mov x16, #1
    svc #0x80

test_failed:
    add sp, sp, #128
    mov x0, #1
    mov x16, #1
    svc #0x80

msg_base_imm:   .ascii "PASS: base_imm\n"
msg_pre_index:  .ascii "PASS: pre_index\n"
msg_post_index: .ascii "PASS: post_index\n"
msg_reg_offset: .ascii "PASS: reg_offset\n"
msg_stp_ldp:    .ascii "PASS: stp_ldp\n"
msg_ldrsw:      .ascii "PASS: ldrsw\n"
