# Indirect branch test - jump to address in register

.global _start

_start:
    # Test indirect JMP instruction - indirect branch via register
    # Load target address into RAX and jump to it
    leaq target_function(%rip), %rax
    jmp *%rax

target_function:
    # Simple function that exits with code 0
    movq $60, %rax      # System call number for exit (64-bit)
    movq $0, %rdi       # Return value 0 (success)
    syscall             # Call kernel
