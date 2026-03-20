# Conditional branch test
# Tests je (jump if equal) and jne (jump if not equal)

.global _start

_start:
    # Test 1: je (jump if equal)
    movq $5, %rax
    movq $5, %rbx
    cmp %rbx, %rax
    je equal_test_pass

    # If we get here, je failed
    movq $60, %rax      # exit syscall
    movq $1, %rdi       # exit code 1
    syscall

equal_test_pass:
    # Test 2: jne (jump if not equal)
    movq $3, %rcx
    movq $7, %rdx
    cmp %rdx, %rcx
    jne not_equal_test_pass

    # If we get here, jne failed
    movq $60, %rax      # exit syscall
    movq $2, %rdi       # exit code 2
    syscall

not_equal_test_pass:
    # Test 3: je should NOT jump when values are different
    movq $10, %r8
    movq $20, %r9
    cmp %r9, %r8
    je test_failed

    # Test 4: jne should NOT jump when values are equal
    movq $42, %r10
    movq $42, %r11
    cmp %r11, %r10
    jne test_failed

    # All tests passed
    movq $60, %rax      # exit syscall
    movq $0, %rdi       # exit code 0
    syscall

test_failed:
    movq $60, %rax      # exit syscall
    movq $3, %rdi       # exit code 3
    syscall
