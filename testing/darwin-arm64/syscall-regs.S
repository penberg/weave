# Regression test: verify guest GPRs (x9, x10, x11) survive SVC syscalls on Darwin/arm64.
#
# CHECK: PASS: x9_surv
# CHECK: PASS: x10_surv
# CHECK: PASS: x9x10_both
# CHECK: PASS: x11_surv

.global _main

_main:
    // --- Test 1: x9 survives a single write syscall ---
    movz x9, #0x9999
    // Exercise syscall: sigreturn (no output)
    mov x0, #0
    mov x16, #184
    svc #0x80
    // Verify x9 and print PASS only if intact
    movz x11, #0x9999
    cmp x9, x11
    b.ne test_failed
    // write(1, msg_x9, 14)
    mov x0, #1
    adr x1, msg_x9
    mov x2, #14
    mov x16, #4
    svc #0x80

    // --- Test 2: x10 survives a single write syscall ---
    movz x10, #0xAAAA
    // Exercise syscall: sigreturn (no output)
    mov x0, #0
    mov x16, #184
    svc #0x80
    // Verify x10, then print PASS
    movz x11, #0xAAAA
    cmp x10, x11
    b.ne test_failed
    mov x0, #1
    adr x1, msg_x10
    mov x2, #15
    mov x16, #4
    svc #0x80

    // --- Test 3: Both x9 and x10 survive together ---
    movz x9, #0x1234
    movz x10, #0x5678
    // Exercise syscall: sigreturn (no output)
    mov x0, #0
    mov x16, #184
    svc #0x80
    // Verify both, then print PASS
    movz x11, #0x1234
    cmp x9, x11
    b.ne test_failed
    movz x11, #0x5678
    cmp x10, x11
    b.ne test_failed
    mov x0, #1
    adr x1, msg_both
    mov x2, #17
    mov x16, #4
    svc #0x80

    // --- Test 4: x11 survives a syscall too ---
    movz x11, #0xBEEF
    // Exercise syscall: sigreturn (no output)
    mov x0, #0
    mov x16, #184
    svc #0x80
    // Verify x11
    movz x12, #0xBEEF
    cmp x11, x12
    b.ne test_failed
    // Print PASS
    mov x0, #1
    adr x1, msg_x11
    mov x2, #15
    mov x16, #4
    svc #0x80

    // All passed
    mov x0, #0
    mov x16, #1
    svc #0x80

test_failed:
    mov x0, #1
    mov x16, #1
    svc #0x80

msg_x9:     .ascii "PASS: x9_surv\n"
msg_x10:    .ascii "PASS: x10_surv\n"
msg_both:   .ascii "PASS: x9x10_both\n"
msg_x11:    .ascii "PASS: x11_surv\n"
