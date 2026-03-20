# Test all 16 ARM64 condition codes
#
# CHECK: PASS: b.eq
# CHECK: PASS: b.ne
# CHECK: PASS: b.hs
# CHECK: PASS: b.lo
# CHECK: PASS: b.mi
# CHECK: PASS: b.pl
# CHECK: PASS: b.vs
# CHECK: PASS: b.vc
# CHECK: PASS: b.hi
# CHECK: PASS: b.ls
# CHECK: PASS: b.ge
# CHECK: PASS: b.lt
# CHECK: PASS: b.gt
# CHECK: PASS: b.le
# CHECK: PASS: b.al

.global _main

_main:
    // b.eq (Z=1): equal
    mov x0, #5
    cmp x0, #5
    b.eq 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_eq
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.ne (Z=0): not equal
    mov x0, #5
    cmp x0, #3
    b.ne 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_ne
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.hs (C=1): unsigned higher or same
    mov x0, #5
    cmp x0, #3
    b.hs 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_hs
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.lo (C=0): unsigned lower
    mov x0, #3
    cmp x0, #5
    b.lo 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_lo
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.mi (N=1): negative
    mov x0, #1
    cmp x0, #5
    b.mi 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_mi
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.pl (N=0): positive or zero
    mov x0, #5
    cmp x0, #1
    b.pl 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_pl
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.vs (V=1): signed overflow
    // LONG_MAX - (-1) = LONG_MAX + 1 = overflow
    movn x0, #0
    lsr x0, x0, #1          // x0 = 0x7FFFFFFFFFFFFFFF = LONG_MAX
    movn x1, #0              // x1 = -1
    cmp x0, x1
    b.vs 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_vs
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.vc (V=0): no overflow
    mov x0, #5
    cmp x0, #3
    b.vc 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_vc
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.hi (C=1 & Z=0): unsigned higher
    mov x0, #5
    cmp x0, #3
    b.hi 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_hi
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.ls (C=0 | Z=1): unsigned lower or same
    mov x0, #3
    cmp x0, #5
    b.ls 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_ls
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.ge (N==V): signed greater or equal
    mov x0, #5
    cmp x0, #3
    b.ge 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_ge
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.lt (N!=V): signed less than
    mov x0, #3
    cmp x0, #5
    b.lt 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_lt
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.gt (Z=0 & N==V): signed greater than
    mov x0, #5
    cmp x0, #3
    b.gt 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_gt
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.le (Z=1 | N!=V): signed less or equal
    mov x0, #3
    cmp x0, #5
    b.le 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_le
    mov x2, #11
    mov x16, #4
    svc #0x80

    // b.al: always
    b.al 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_al
    mov x2, #11
    mov x16, #4
    svc #0x80

    // All tests passed
    mov x0, #0
    mov x16, #1
    svc #0x80

test_failed:
    mov x0, #1
    mov x16, #1
    svc #0x80

// String data (each "PASS: b.XX\n" is 11 bytes)
msg_eq:  .ascii "PASS: b.eq\n"
msg_ne:  .ascii "PASS: b.ne\n"
msg_hs:  .ascii "PASS: b.hs\n"
msg_lo:  .ascii "PASS: b.lo\n"
msg_mi:  .ascii "PASS: b.mi\n"
msg_pl:  .ascii "PASS: b.pl\n"
msg_vs:  .ascii "PASS: b.vs\n"
msg_vc:  .ascii "PASS: b.vc\n"
msg_hi:  .ascii "PASS: b.hi\n"
msg_ls:  .ascii "PASS: b.ls\n"
msg_ge:  .ascii "PASS: b.ge\n"
msg_lt:  .ascii "PASS: b.lt\n"
msg_gt:  .ascii "PASS: b.gt\n"
msg_le:  .ascii "PASS: b.le\n"
msg_al:  .ascii "PASS: b.al\n"
