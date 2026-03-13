# Test shift and bitwise operations
#
# CHECK: PASS: lsl
# CHECK: PASS: lsr
# CHECK: PASS: asr
# CHECK: PASS: ror
# CHECK: PASS: and
# CHECK: PASS: orr
# CHECK: PASS: eor
# CHECK: PASS: bic
# CHECK: PASS: clz
# CHECK: PASS: rev

.global _main

_main:
    // lsl: 1 << 4 = 16
    mov x0, #1
    lsl x1, x0, #4
    cmp x1, #16
    b.ne test_failed
    mov x0, #1
    adr x1, msg_lsl
    mov x2, #10
    mov x16, #4
    svc #0x80

    // lsr: 0x80 >> 4 = 8
    mov x0, #0x80
    lsr x1, x0, #4
    cmp x1, #8
    b.ne test_failed
    mov x0, #1
    adr x1, msg_lsr
    mov x2, #10
    mov x16, #4
    svc #0x80

    // asr: -128 >> 4 = -8 (arithmetic shift preserves sign)
    mov x0, #-128
    asr x1, x0, #4
    mov x2, #-8
    cmp x1, x2
    b.ne test_failed
    mov x0, #1
    adr x1, msg_asr
    mov x2, #10
    mov x16, #4
    svc #0x80

    // ror: rotate right 1 by 1 → MSB set
    mov x0, #1
    ror x1, x0, #1
    lsr x2, x1, #63           // extract bit 63
    cmp x2, #1
    b.ne test_failed
    mov x0, #1
    adr x1, msg_ror
    mov x2, #10
    mov x16, #4
    svc #0x80

    // and: 0xFF & 0x0F = 0x0F
    mov x0, #0xFF
    mov x1, #0x0F
    and x2, x0, x1
    cmp x2, #0x0F
    b.ne test_failed
    mov x0, #1
    adr x1, msg_and
    mov x2, #10
    mov x16, #4
    svc #0x80

    // orr: 0xF0 | 0x0F = 0xFF
    mov x0, #0xF0
    mov x1, #0x0F
    orr x2, x0, x1
    cmp x2, #0xFF
    b.ne test_failed
    mov x0, #1
    adr x1, msg_orr
    mov x2, #10
    mov x16, #4
    svc #0x80

    // eor: 0xFF ^ 0x0F = 0xF0
    mov x0, #0xFF
    mov x1, #0x0F
    eor x2, x0, x1
    cmp x2, #0xF0
    b.ne test_failed
    mov x0, #1
    adr x1, msg_eor
    mov x2, #10
    mov x16, #4
    svc #0x80

    // bic: 0xFF & ~0x0F = 0xF0
    mov x0, #0xFF
    mov x1, #0x0F
    bic x2, x0, x1
    cmp x2, #0xF0
    b.ne test_failed
    mov x0, #1
    adr x1, msg_bic
    mov x2, #10
    mov x16, #4
    svc #0x80

    // clz: count leading zeros of 1 = 63
    mov x0, #1
    clz x1, x0
    cmp x1, #63
    b.ne test_failed
    mov x0, #1
    adr x1, msg_clz
    mov x2, #10
    mov x16, #4
    svc #0x80

    // rev: byte-reverse 0x0000000000000102 → 0x0201000000000000
    movz x0, #0x0102
    rev x1, x0
    lsr x2, x1, #56           // top byte should be 0x02
    cmp x2, #2
    b.ne test_failed
    mov x0, #1
    adr x1, msg_rev
    mov x2, #10
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

msg_lsl: .ascii "PASS: lsl\n"
msg_lsr: .ascii "PASS: lsr\n"
msg_asr: .ascii "PASS: asr\n"
msg_ror: .ascii "PASS: ror\n"
msg_and: .ascii "PASS: and\n"
msg_orr: .ascii "PASS: orr\n"
msg_eor: .ascii "PASS: eor\n"
msg_bic: .ascii "PASS: bic\n"
msg_clz: .ascii "PASS: clz\n"
msg_rev: .ascii "PASS: rev\n"
