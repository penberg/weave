.section __TEXT,__text,regular,pure_instructions
.globl _main

_main:
    // Test BR instruction - indirect branch to register
    // Load target address into x1 and branch to it
    adr x1, target_function
    br x1

target_function:
    // Simple function that exits with code 42
    mov x0, #0
    mov x16, #1
    svc #0x80
