# Function calls.
#
# This test case tests simple `bl` and `ret` patterns.

.global _main

_main:
    # A single function call.
    bl simple_func

    # Multiple sequential calls to same function.
    bl simple_func
    bl simple_func
    bl simple_func

    # Nested function calls
    bl nested_func

    # Exit program
    movz x0, #0     // Return value 0 (success)
    movz x16, #1    // System call number for exit
    svc #0x80       // Call kernel

simple_func:
    ret

nested_func:
    stp lr, xzr, [sp, #-16]!
    bl nested_func_2
    ldp lr, xzr, [sp], #16
    ret

nested_func_2:
    stp lr, xzr, [sp, #-16]!
    bl nested_func_3
    ldp lr, xzr, [sp], #16
    ret

nested_func_3:
    stp lr, xzr, [sp, #-16]!
    bl simple_func
    ldp lr, xzr, [sp], #16
    ret
