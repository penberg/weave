# NZCV flag preservation tests for CBZ/CBNZ/TBZ/TBNZ
#
# CBZ, CBNZ, TBZ, and TBNZ do NOT modify the NZCV condition flags.
# If the translator replaces them with CMP or TST instructions, the
# flags from a preceding comparison will be corrupted, causing
# subsequent conditional branches (B.cond) to take the wrong path.
#
# Pattern under test:
#   cmp <reg>, <val>       ; sets NZCV
#   cbz/cbnz/tbz/tbnz     ; must NOT modify NZCV
#   b.cond                 ; must use NZCV from the cmp, not the cbz/tbz

.global _main

_main:
    # -------------------------------------------------------
    # Test 1: CMP sets Z=1, CBZ must not clear it
    #
    # cmp x0, #5 with x0=5 → Z=1
    # cbz x1, ... with x1≠0 → falls through, must NOT touch Z
    # b.eq target → should branch because Z=1 from cmp
    # -------------------------------------------------------
    movz x0, #5
    movz x1, #1            // x1 != 0, so CBZ will fall through
    cmp x0, #5             // Z=1 (equal)
    cbz x1, test_failed    // x1 != 0 → falls through; must NOT change Z
    b.eq test1_pass        // Z should still be 1 from cmp → branch

    movz x0, #1
    movz x16, #1
    svc #0x80

test1_pass:
    # -------------------------------------------------------
    # Test 2: CMP sets Z=0, CBNZ must not set it
    #
    # cmp x2, #10 with x2=7 → Z=0
    # cbnz x3, ... with x3≠0 → branches away
    # (fallthrough would mean cbnz didn't branch — fail)
    # At branch target: b.ne should work because Z=0
    # -------------------------------------------------------
    movz x2, #7
    movz x3, #1            // x3 != 0, so CBNZ will branch
    cmp x2, #10            // Z=0 (not equal)
    cbnz x3, test2_cbnz_taken // x3 != 0 → branch; must NOT change Z

    movz x0, #2
    movz x16, #1
    svc #0x80

test2_cbnz_taken:
    b.ne test2_pass         // Z should still be 0 from cmp → branch

    movz x0, #12
    movz x16, #1
    svc #0x80

test2_pass:
    # -------------------------------------------------------
    # Test 3: CMP sets Z=1, TBZ must not clear it
    #
    # cmp x4, #3 with x4=3 → Z=1
    # tbz x5, #0, ... with bit 0 of x5 = 1 → falls through
    # b.eq target → should branch because Z=1
    # -------------------------------------------------------
    movz x4, #3
    movz x5, #1            // bit 0 = 1, so TBZ falls through
    cmp x4, #3             // Z=1 (equal)
    tbz x5, #0, test_failed // bit 0 is 1 → falls through; must NOT change Z
    b.eq test3_pass         // Z should still be 1 → branch

    movz x0, #3
    movz x16, #1
    svc #0x80

test3_pass:
    # -------------------------------------------------------
    # Test 4: CMP sets Z=1, TBNZ must not clear it
    #
    # cmp x6, #42 with x6=42 → Z=1
    # tbnz x7, #0, ... with bit 0 of x7 = 1 → branches away
    # At branch target: b.eq should work because Z=1
    # -------------------------------------------------------
    movz x6, #42
    movz x7, #1            // bit 0 = 1, so TBNZ branches
    cmp x6, #42            // Z=1 (equal)
    tbnz x7, #0, test4_tbnz_taken // bit 0 = 1 → branch; must NOT change Z

    movz x0, #4
    movz x16, #1
    svc #0x80

test4_tbnz_taken:
    b.eq test4_pass         // Z should still be 1 → branch

    movz x0, #14
    movz x16, #1
    svc #0x80

test4_pass:
    # -------------------------------------------------------
    # Test 5: CMP sets C=1 (carry), CBZ must not clear it
    #
    # cmp x8, #1 with x8=5 → C=1 (5 >= 1), Z=0
    # cbz x9, ... with x9=0 → branches away
    # At target: b.hs (unsigned >=) checks C=1 → should branch
    # -------------------------------------------------------
    movz x8, #5
    movz x9, #0            // x9 = 0, so CBZ branches
    cmp x8, #1             // C=1 (5 >= 1 unsigned), Z=0
    cbz x9, test5_cbz_taken // x9 = 0 → branch; must NOT change C

    movz x0, #5
    movz x16, #1
    svc #0x80

test5_cbz_taken:
    b.hs test5_pass         // C should still be 1 → branch (HS = carry set)

    movz x0, #15
    movz x16, #1
    svc #0x80

test5_pass:
    # -------------------------------------------------------
    # Test 6: CMP sets N=1 (negative), TBZ must not clear it
    #
    # cmp x10, x11 with x10=1, x11=5 → N=1 (1-5 is negative)
    # tbz x12, #4, ... with bit 4 of x12 = 0 → branches away
    # At target: b.lt (signed <) checks N!=V → should branch
    # -------------------------------------------------------
    movz x10, #1
    movz x11, #5
    movz x12, #0           // bit 4 = 0, so TBZ branches
    cmp x10, x11           // N=1, V=0 (1 < 5)
    tbz x12, #4, test6_tbz_taken // bit 4 = 0 → branch; must NOT change N

    movz x0, #6
    movz x16, #1
    svc #0x80

test6_tbz_taken:
    b.lt test6_pass         // N!=V should still hold → branch

    movz x0, #16
    movz x16, #1
    svc #0x80

test6_pass:
    # All tests passed
    movz x0, #0
    movz x16, #1
    svc #0x80

test_failed:
    movz x0, #99
    movz x16, #1
    svc #0x80
