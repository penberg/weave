# Test backward branches (loops with negative offsets)
#
# CHECK: PASS: loop_b
# CHECK: PASS: loop_bcond
# CHECK: PASS: loop_cbnz
# CHECK: PASS: nested_loop

.global _main

_main:
    // Test 1: Backward unconditional branch (b)
    // Count from 0 to 10 using unconditional backward branch
    mov x19, #0              // counter
1:  add x19, x19, #1
    cmp x19, #10
    b.eq 2f                  // exit when done
    b 1b                     // backward b
2:  cmp x19, #10
    b.ne test_failed
    mov x0, #1
    adr x1, msg_loop_b
    mov x2, #13
    mov x16, #4
    svc #0x80

    // Test 2: Backward conditional branch (b.lt)
    mov x19, #0
3:  add x19, x19, #1
    cmp x19, #5
    b.lt 3b                  // backward b.lt while < 5
    cmp x19, #5
    b.ne test_failed
    mov x0, #1
    adr x1, msg_loop_bcond
    mov x2, #17
    mov x16, #4
    svc #0x80

    // Test 3: Backward cbnz
    mov x19, #5
4:  sub x19, x19, #1
    cbnz x19, 4b             // backward cbnz while != 0
    cmp x19, #0
    b.ne test_failed
    mov x0, #1
    adr x1, msg_loop_cbnz
    mov x2, #16
    mov x16, #4
    svc #0x80

    // Test 4: Nested backward branches (outer * inner iterations)
    mov x19, #3              // outer count
    mov x21, #0              // accumulator
5:  mov x20, #4              // inner count
6:  add x21, x21, #1
    sub x20, x20, #1
    cbnz x20, 6b             // inner backward cbnz
    sub x19, x19, #1
    cbnz x19, 5b             // outer backward cbnz
    cmp x21, #12             // 3 * 4 = 12
    b.ne test_failed
    mov x0, #1
    adr x1, msg_nested_loop
    mov x2, #18
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

msg_loop_b:      .ascii "PASS: loop_b\n"
msg_loop_bcond:  .ascii "PASS: loop_bcond\n"
msg_loop_cbnz:   .ascii "PASS: loop_cbnz\n"
msg_nested_loop: .ascii "PASS: nested_loop\n"
