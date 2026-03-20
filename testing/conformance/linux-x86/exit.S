.global _start

_start:
    movq $60, %rax      # System call number for exit (64-bit)
    movq $0, %rdi       # Return value 0 (success)
    syscall             # Call kernel
