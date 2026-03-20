.global _main

_main:
    movz x0, #0     // Return value 0 (success)
    movz x16, #1    // System call number for exit
    svc #0x80       // Call kernel
