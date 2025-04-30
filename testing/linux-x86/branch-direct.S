# `jmp` -- Unconditional branch

.global _start

_start:
    jmp L1
L0:
    movq $60, %rax      # System call number for exit (64-bit)
    movq $0, %rdi       # Return value 0 (success)
    syscall             # Call kernel
L1:
    jmp L0
