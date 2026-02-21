# LDR literal (PC-relative data load) tests
#
# These tests verify that LDR literal instructions are correctly
# translated. The translator must rewrite them because they encode
# a PC-relative offset — if copied verbatim to the code cache, the
# CPU would compute the target from the wrong PC and load garbage.

.global _main

_main:
    # -------------------------------------------------------
    # Test 1: LDR Xt, <label>  (64-bit integer literal load)
    # -------------------------------------------------------
    ldr x0, const64
    movz x1, #0xBEEF, lsl #0
    movk x1, #0xDEAD, lsl #16
    movk x1, #0, lsl #32
    movk x1, #0, lsl #48
    cmp x0, x1
    b.ne test_failed_1

    # -------------------------------------------------------
    # Test 2: LDR Wt, <label>  (32-bit integer literal load)
    # -------------------------------------------------------
    ldr w2, const32
    movz w3, #0x4321
    movk w3, #0x8765, lsl #16
    cmp w2, w3
    b.ne test_failed_2

    # -------------------------------------------------------
    # Test 3: LDRSW Xt, <label>  (sign-extending 32-bit load)
    # -------------------------------------------------------
    ldrsw x4, const_neg
    # const_neg is 0xFFFFFFF0 = -16 as i32
    # After sign-extension to 64 bits: 0xFFFFFFFFFFFFFFF0
    movn x5, #0xF          // x5 = ~0xF = 0xFFFFFFFFFFFFFFF0
    cmp x4, x5
    b.ne test_failed_3

    # -------------------------------------------------------
    # Test 4: LDR St, <label>  (32-bit FP literal load)
    #
    # Load the float constant 2.0 (IEEE 754: 0x40000000) from
    # a literal pool, then convert to integer and check.
    # -------------------------------------------------------
    ldr s0, const_float
    fcvtzs w6, s0           // w6 = (int)2.0 = 2
    cmp w6, #2
    b.ne test_failed_4

    # -------------------------------------------------------
    # Test 5: LDR Dt, <label>  (64-bit FP literal load)
    #
    # Load the double constant 3.0 (IEEE 754: 0x4008000000000000)
    # -------------------------------------------------------
    ldr d1, const_double
    fcvtzs w7, d1           // w7 = (int)3.0 = 3
    cmp w7, #3
    b.ne test_failed_5

    # All tests passed
    movz x0, #0
    movz x16, #1
    svc #0x80

test_failed_1:
    movz x0, #1
    movz x16, #1
    svc #0x80

test_failed_2:
    movz x0, #2
    movz x16, #1
    svc #0x80

test_failed_3:
    movz x0, #3
    movz x16, #1
    svc #0x80

test_failed_4:
    movz x0, #4
    movz x16, #1
    svc #0x80

test_failed_5:
    movz x0, #5
    movz x16, #1
    svc #0x80

# -------------------------------------------------------
# Literal pool — data embedded after the code
# -------------------------------------------------------
.p2align 2
const64:
    .quad 0xDEADBEEF

const32:
    .long 0x87654321

const_neg:
    .long 0xFFFFFFF0         // -16 as a signed 32-bit integer

const_float:
    .long 0x40000000         // 2.0f in IEEE 754

const_double:
    .quad 0x4008000000000000 // 3.0 in IEEE 754 double
