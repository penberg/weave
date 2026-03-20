# Test ADR and ADRP PC-relative addressing
#
# CHECK: PASS: adr_fwd
# CHECK: PASS: adr_bwd
# CHECK: PASS: adrp_add
# CHECK: PASS: adr_multi

.global _main

    // Place some data before _main for backward ADR test
    b _main
backward_data:
    .quad 0xCAFEBABE

_main:
    // Test 1: ADR forward — load address of data after code
    adr x0, forward_data
    ldr x1, [x0]
    movz x2, #0xBEEF
    movk x2, #0xDEAD, lsl #16
    cmp x1, x2
    b.ne test_failed
    mov x0, #1
    adr x1, msg_adr_fwd
    mov x2, #14
    mov x16, #4
    svc #0x80

    // Test 2: ADR backward — load address of data before code
    adr x0, backward_data
    ldr x1, [x0]
    movz x2, #0xBABE
    movk x2, #0xCAFE, lsl #16
    cmp x1, x2
    b.ne test_failed
    mov x0, #1
    adr x1, msg_adr_bwd
    mov x2, #14
    mov x16, #4
    svc #0x80

    // Test 3: ADRP + ADD pattern (typical compiler output)
    adrp x0, page_data@PAGE
    add x0, x0, page_data@PAGEOFF
    ldr x1, [x0]
    movz x2, #0x4567
    movk x2, #0x0123, lsl #16
    cmp x1, x2
    b.ne test_failed
    mov x0, #1
    adr x1, msg_adrp_add
    mov x2, #15
    mov x16, #4
    svc #0x80

    // Test 4: Multiple ADR in sequence
    adr x0, seq_data1
    ldr x1, [x0]
    cmp x1, #100
    b.ne test_failed
    adr x0, seq_data2
    ldr x1, [x0]
    cmp x1, #200
    b.ne test_failed
    adr x0, seq_data3
    ldr x1, [x0]
    cmp x1, #300
    b.ne test_failed
    mov x0, #1
    adr x1, msg_adr_multi
    mov x2, #16
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

.p2align 3
forward_data:
    .quad 0xDEADBEEF

page_data:
    .quad 0x01234567

seq_data1:
    .quad 100
seq_data2:
    .quad 200
seq_data3:
    .quad 300

msg_adr_fwd:   .ascii "PASS: adr_fwd\n"
msg_adr_bwd:   .ascii "PASS: adr_bwd\n"
msg_adrp_add:  .ascii "PASS: adrp_add\n"
msg_adr_multi: .ascii "PASS: adr_multi\n"
