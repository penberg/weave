# Test computed branch via jump table (ADR + LDR offset + ADD + BR)
#
# CHECK: PASS: case_0
# CHECK: PASS: case_1
# CHECK: PASS: case_2
# CHECK: PASS: case_3

.global _main

_main:
    mov x19, #0              // case index

dispatch:
    cmp x19, #4
    b.ge done
    adr x1, jump_table
    ldr w2, [x1, x19, lsl #2]   // load 32-bit offset
    add x1, x1, w2, sxtw        // table base + sign-extended offset
    br x1                        // computed branch

case_0:
    mov x0, #1
    adr x1, msg_case0
    mov x2, #13
    mov x16, #4
    svc #0x80
    add x19, x19, #1
    b dispatch

case_1:
    mov x0, #1
    adr x1, msg_case1
    mov x2, #13
    mov x16, #4
    svc #0x80
    add x19, x19, #1
    b dispatch

case_2:
    mov x0, #1
    adr x1, msg_case2
    mov x2, #13
    mov x16, #4
    svc #0x80
    add x19, x19, #1
    b dispatch

case_3:
    mov x0, #1
    adr x1, msg_case3
    mov x2, #13
    mov x16, #4
    svc #0x80
    add x19, x19, #1
    b dispatch

done:
    mov x0, #0
    mov x16, #1
    svc #0x80

.p2align 2
jump_table:
    .long case_0 - jump_table
    .long case_1 - jump_table
    .long case_2 - jump_table
    .long case_3 - jump_table

msg_case0: .ascii "PASS: case_0\n"
msg_case1: .ascii "PASS: case_1\n"
msg_case2: .ascii "PASS: case_2\n"
msg_case3: .ascii "PASS: case_3\n"
