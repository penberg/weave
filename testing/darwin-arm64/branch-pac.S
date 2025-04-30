.section __TEXT,__text,regular,pure_instructions
.globl _main

_main:
    // Test PAC branch instructions (Pointer Authentication Code)
    // These are authenticated branches - we treat them as regular branches
    // since we don't implement actual pointer authentication.

    // Test BRAA - Branch to register with key A authentication
    adr x16, test_braa_target
    mov x17, #0                 // modifier (context) register
    braa x16, x17

test_braa_target:
    // Test BRAAZ - Branch to register with key A, zero modifier
    adr x16, test_braaz_target
    braaz x16

test_braaz_target:
    // Test BRAB - Branch to register with key B authentication
    adr x16, test_brab_target
    mov x17, #0                 // modifier register
    brab x16, x17

test_brab_target:
    // Test BRABZ - Branch to register with key B, zero modifier
    adr x16, test_brabz_target
    brabz x16

test_brabz_target:
    // Test BLRAA - Branch with link, key A authentication
    adr x16, test_blraa_func
    mov x17, #0
    blraa x16, x17
    b after_blraa

test_blraa_func:
    ret

after_blraa:
    // Test BLRAAZ - Branch with link, key A, zero modifier
    adr x16, test_blraaz_func
    blraaz x16
    b after_blraaz

test_blraaz_func:
    ret

after_blraaz:
    // Test BLRAB - Branch with link, key B authentication
    adr x16, test_blrab_func
    mov x17, #0
    blrab x16, x17
    b after_blrab

test_blrab_func:
    ret

after_blrab:
    // Test BLRABZ - Branch with link, key B, zero modifier
    adr x16, test_blrabz_func
    blrabz x16
    b after_blrabz

test_blrabz_func:
    ret

after_blrabz:
    // Test RETAA - Return with key A authentication
    adr x30, test_retaa_return
    // Note: paciasp would normally be used here to sign x30,
    // but we're just testing that retaa works as a return
    b test_retaa_func

test_retaa_func:
    retaa

test_retaa_return:
    // Test RETAB - Return with key B authentication
    adr x30, test_retab_return
    b test_retab_func

test_retab_func:
    retab

test_retab_return:
    // All tests passed - exit with code 0
    mov x0, #0
    mov x16, #1
    svc #0x80
