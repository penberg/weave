# Test BLR x30 — branch-with-link when the target is in x30.
#
# The translator must preserve the branch target before loading LR with the
# return address; otherwise when rn==x30 the target is lost and the call never
# reaches the intended function.
#
# CHECK: PASS: blr_x30

.global _main

_main:
    stp x29, x30, [sp, #-16]!

    // Load target function address into x30
    adr x30, _target_func

    // BLR x30: should branch to _target_func and set x30 = next insn
    blr x30

    // _target_func sets x9 = 42 and returns here
    cmp x9, #42
    b.ne test_failed

    mov x0, #1
    adr x1, msg_pass
    mov x2, #14
    mov x16, #4
    svc #0x80

    ldp x29, x30, [sp], #16
    mov x0, #0
    mov x16, #1
    svc #0x80

_target_func:
    mov x9, #42
    ret

test_failed:
    ldp x29, x30, [sp], #16
    mov x0, #1
    mov x16, #1
    svc #0x80

msg_pass: .ascii "PASS: blr_x30\n"

