# Function calls.
#
# This test case tests simple `call` and `ret` patterns.

.global _start

_start:
    # A single function call.
    call simple_func

    # Multiple sequential calls to same function.
    call simple_func
    call simple_func
    call simple_func

    # Nested function calls
    call nested_func

    # Exit program
    movq $60, %rax      # System call number for exit (64-bit)
    movq $0, %rdi       # Return value 0 (success)
    syscall             # Call kernel

simple_func:
    ret

nested_func:
    # Save return address on stack
    push %rbp
    mov %rsp, %rbp
    call nested_func_2
    pop %rbp
    ret

nested_func_2:
    # Save return address on stack
    push %rbp
    mov %rsp, %rbp
    call nested_func_3
    pop %rbp
    ret

nested_func_3:
    # Save return address on stack
    push %rbp
    mov %rsp, %rbp
    call simple_func
    pop %rbp
    ret
