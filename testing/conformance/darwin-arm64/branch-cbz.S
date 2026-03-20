# Compare-and-branch (CBZ/CBNZ) tests
#
# Tests CBZ/CBNZ with both 64-bit (Xn) and 32-bit (Wn) register forms.
# The 32-bit form only checks the lower 32 bits — upper 32 bits are ignored.
# This is critical when functions return 32-bit values (int), because the
# ARM64 ABI leaves the upper 32 bits of the return register UNDEFINED.

.global _main

_main:
    # -------------------------------------------------------
    # Test 1: CBZ Xn with Xn == 0 → should branch
    # -------------------------------------------------------
    movz x0, #0
    cbz x0, test1_pass

    movz x0, #1
    movz x16, #1
    svc #0x80

test1_pass:
    # -------------------------------------------------------
    # Test 2: CBZ Xn with Xn != 0 → should NOT branch
    # -------------------------------------------------------
    movz x1, #42
    cbz x1, test_failed

    # -------------------------------------------------------
    # Test 3: CBNZ Xn with Xn != 0 → should branch
    # -------------------------------------------------------
    movz x2, #1
    cbnz x2, test3_pass

    movz x0, #3
    movz x16, #1
    svc #0x80

test3_pass:
    # -------------------------------------------------------
    # Test 4: CBNZ Xn with Xn == 0 → should NOT branch
    # -------------------------------------------------------
    movz x3, #0
    cbnz x3, test_failed

    # -------------------------------------------------------
    # Test 5: CBZ Wn with upper 32 bits non-zero (the critical test)
    #
    # Set x0 = 0x0000BEEF_00000000 — lower 32 bits are zero.
    # CBZ W0 checks only w0 (lower 32 bits) = 0, so it SHOULD branch.
    # A buggy translator that uses 64-bit CMP will see x0 != 0
    # and incorrectly fall through.
    # -------------------------------------------------------
    movz x0, #0
    movk x0, #0xBEEF, lsl #32
    cbz w0, test5_pass

    # Bug: translator used 64-bit CMP instead of 32-bit CBZ
    movz x0, #5
    movz x16, #1
    svc #0x80

test5_pass:
    # -------------------------------------------------------
    # Test 6: CBNZ Wn with upper 32 bits non-zero, lower 32 bits zero
    #
    # x1 = 0x0000DEAD_00000000 — w1 = 0.
    # CBNZ W1 checks w1 = 0, so it should NOT branch.
    # A buggy translator using 64-bit CMP sees x1 != 0 and branches.
    # -------------------------------------------------------
    movz x1, #0
    movk x1, #0xDEAD, lsl #32
    cbnz w1, test_failed

    # -------------------------------------------------------
    # Test 7: CBZ Wn with lower 32 bits non-zero (should NOT branch)
    # -------------------------------------------------------
    movz x2, #7
    cbz w2, test_failed

    # -------------------------------------------------------
    # Test 8: CBNZ Wn with lower 32 bits non-zero (should branch)
    # -------------------------------------------------------
    movz x3, #1
    movk x3, #0xCAFE, lsl #48
    cbnz w3, test8_pass

    movz x0, #8
    movz x16, #1
    svc #0x80

test8_pass:
    # -------------------------------------------------------
    # Test 9: CBZ Wn with ALL 64 bits non-zero, lower 32 = 0
    #
    # x4 = 0xFFFF_FFFF_0000_0000
    # CBZ W4 → w4 = 0, should branch
    # -------------------------------------------------------
    movn x4, #0             // x4 = 0xFFFFFFFFFFFFFFFF
    lsl x4, x4, #32         // x4 = 0xFFFFFFFF00000000
    cbz w4, test9_pass

    movz x0, #9
    movz x16, #1
    svc #0x80

test9_pass:
    # -------------------------------------------------------
    # Test 10: CBNZ Wn with x5 = 0 (both halves zero)
    # CBNZ W5 → w5 = 0, should NOT branch
    # -------------------------------------------------------
    movz x5, #0
    cbnz w5, test_failed

    # All tests passed
    movz x0, #0
    movz x16, #1
    svc #0x80

test_failed:
    movz x0, #99
    movz x16, #1
    svc #0x80
