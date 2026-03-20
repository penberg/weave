# Test branch test (TBZ/TBNZ)
# Tests tbz (branch if bit is zero) and tbnz (branch if bit is not zero)

.global _main

_main:
    # Test 1: tbz - branch if bit 0 is zero
    # x0 = 0b10 (bit 0 is 0)
    movz x0, #2
    tbz x0, #0, tbz_bit0_pass

    # If we get here, tbz failed
    movz x0, #1
    movz x16, #1
    svc #0x80

tbz_bit0_pass:
    # Test 2: tbz should NOT branch if bit is set
    # x1 = 0b01 (bit 0 is 1)
    movz x1, #1
    tbz x1, #0, test_failed

    # Test 3: tbnz - branch if bit 0 is not zero
    # x2 = 0b01 (bit 0 is 1)
    movz x2, #1
    tbnz x2, #0, tbnz_bit0_pass

    # If we get here, tbnz failed
    movz x0, #2
    movz x16, #1
    svc #0x80

tbnz_bit0_pass:
    # Test 4: tbnz should NOT branch if bit is zero
    # x3 = 0b10 (bit 0 is 0)
    movz x3, #2
    tbnz x3, #0, test_failed

    # Test 5: tbz with higher bit (bit 4)
    # x4 = 0b01111 = 15 (bit 4 is 0)
    movz x4, #15
    tbz x4, #4, tbz_bit4_pass

    # If we get here, tbz bit 4 failed
    movz x0, #3
    movz x16, #1
    svc #0x80

tbz_bit4_pass:
    # Test 6: tbnz with higher bit (bit 4)
    # x5 = 0b10000 = 16 (bit 4 is 1)
    movz x5, #16
    tbnz x5, #4, tbnz_bit4_pass

    # If we get here, tbnz bit 4 failed
    movz x0, #4
    movz x16, #1
    svc #0x80

tbnz_bit4_pass:
    # All tests passed
    movz x0, #0
    movz x16, #1
    svc #0x80

test_failed:
    movz x0, #5
    movz x16, #1
    svc #0x80
