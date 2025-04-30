# `b` -- Unconditional branch

.global _main

_main:
    b L1
L0:
    movz x0, #0     // Return value 0 (success)
    movz x16, #1    // System call number for exit
    svc #0x80       // Call kernel
L1:
    b L0
