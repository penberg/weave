# Test arithmetic instructions that set flags
#
# CHECK: PASS: adds_zero
# CHECK: PASS: subs_neg
# CHECK: PASS: adds_carry
# CHECK: PASS: adds_ovfl
# CHECK: PASS: cmn
# CHECK: PASS: tst
# CHECK: PASS: ands
# CHECK: PASS: adcs
# CHECK: PASS: sbcs

.global _main

_main:
    // adds producing zero (Z=1)
    mov x0, #5
    movn x1, #4              // x1 = -5
    adds x2, x0, x1          // 5 + (-5) = 0, Z=1
    b.eq 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_adds_zero
    mov x2, #16
    mov x16, #4
    svc #0x80

    // subs producing negative (N=1)
    mov x0, #3
    mov x1, #10
    subs x2, x0, x1          // 3 - 10 = -7, N=1
    b.mi 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_subs_neg
    mov x2, #15
    mov x16, #4
    svc #0x80

    // adds producing carry (C=1)
    movn x0, #0              // x0 = 0xFFFFFFFFFFFFFFFF = -1
    mov x1, #2
    adds x2, x0, x1          // -1 + 2 = 1 with carry
    b.cs 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_adds_carry
    mov x2, #17
    mov x16, #4
    svc #0x80

    // adds producing overflow (V=1)
    movn x0, #0
    lsr x0, x0, #1           // x0 = LONG_MAX
    mov x1, #1
    adds x2, x0, x1          // LONG_MAX + 1 = overflow
    b.vs 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_adds_ovfl
    mov x2, #16
    mov x16, #4
    svc #0x80

    // cmn (compare negative = add without storing)
    mov x0, #5
    movn x1, #4              // x1 = -5
    cmn x0, x1               // 5 + (-5) = 0, Z=1
    b.eq 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_cmn
    mov x2, #10
    mov x16, #4
    svc #0x80

    // tst (AND without storing)
    movz x0, #0xFF00
    movz x1, #0x00FF
    tst x0, x1               // 0xFF00 & 0x00FF = 0, Z=1
    b.eq 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_tst
    mov x2, #10
    mov x16, #4
    svc #0x80

    // ands (AND with flags)
    mov x0, #0xFF
    mov x1, #0x0F
    ands x2, x0, x1          // 0xFF & 0x0F = 0x0F, Z=0
    b.ne 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_ands
    mov x2, #11
    mov x16, #4
    svc #0x80

    // adcs (add with carry)
    // First set carry: -1 + 2 = 1 with C=1
    movn x0, #0
    mov x1, #2
    adds x3, x0, x1          // C=1
    // Now adcs: 0 + 0 + carry = 1
    mov x0, #0
    mov x1, #0
    adcs x2, x0, x1          // 0 + 0 + 1 = 1
    cmp x2, #1
    b.eq 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_adcs
    mov x2, #11
    mov x16, #4
    svc #0x80

    // sbcs (subtract with carry/borrow)
    // Set carry: cmp 5, 3 -> C=1 (no borrow)
    mov x0, #5
    cmp x0, #3               // C=1
    // sbcs: 10 - 5 - !C = 10 - 5 - 0 = 5
    mov x0, #10
    mov x1, #5
    sbcs x2, x0, x1
    cmp x2, #5
    b.eq 1f
    b test_failed
1:  mov x0, #1
    adr x1, msg_sbcs
    mov x2, #11
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

msg_adds_zero:  .ascii "PASS: adds_zero\n"
msg_subs_neg:   .ascii "PASS: subs_neg\n"
msg_adds_carry: .ascii "PASS: adds_carry\n"
msg_adds_ovfl:  .ascii "PASS: adds_ovfl\n"
msg_cmn:        .ascii "PASS: cmn\n"
msg_tst:        .ascii "PASS: tst\n"
msg_ands:       .ascii "PASS: ands\n"
msg_adcs:       .ascii "PASS: adcs\n"
msg_sbcs:       .ascii "PASS: sbcs\n"
