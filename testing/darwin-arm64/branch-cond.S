# Conditional branch test
# Tests b.eq (branch if equal) and b.ne (branch if not equal)

.global _main

_main:
    # Test 1: b.eq (branch if equal)
    movz x0, #5
    movz x1, #5
    cmp x0, x1
    b.eq equal_test_pass
    
    # If we get here, b.eq failed
    movz x0, #1
    movz x16, #1
    svc #0x80

equal_test_pass:
    # Test 2: b.ne (branch if not equal)
    movz x2, #3
    movz x3, #7
    cmp x2, x3
    b.ne not_equal_test_pass
    
    # If we get here, b.ne failed
    movz x0, #2
    movz x16, #1
    svc #0x80

not_equal_test_pass:
    # Test 3: b.eq should NOT branch when values are different
    movz x4, #10
    movz x5, #20
    cmp x4, x5
    b.eq test_failed
    
    # Test 4: b.ne should NOT branch when values are equal
    movz x6, #42
    movz x7, #42
    cmp x6, x7
    b.ne test_failed
    
    # All tests passed
    movz x0, #0
    movz x16, #1
    svc #0x80

test_failed:
    movz x0, #3
    movz x16, #1
    svc #0x80