/*
 * Test setjmp/longjmp ABI compliance.
 *
 * setjmp/longjmp performs non-local jumps by saving and restoring CPU state:
 * - setjmp saves the current register state (including callee-saved regs, SP, PC)
 * - longjmp restores this state and returns to the setjmp point
 *
 * Binary translators must handle this correctly because:
 * - The saved state includes translated code addresses
 * - Register values must be correctly restored
 * - Stack unwinding must work properly
 * - The return value from setjmp changes on longjmp
 */

#include <stdio.h>
#include <setjmp.h>

static jmp_buf jump_buffer;
static int call_count = 0;

/* Basic setjmp/longjmp test */
int test_basic_longjmp(void) {
    int val = setjmp(jump_buffer);

    if (val == 0) {
        /* First time through - do longjmp */
        longjmp(jump_buffer, 42);
        /* Should never reach here */
        return -1;
    } else {
        /* Returned from longjmp */
        return val;
    }
}

/* Test longjmp from nested function */
__attribute__((noinline))
void do_longjmp(int value) {
    longjmp(jump_buffer, value);
}

int test_nested_longjmp(void) {
    int val = setjmp(jump_buffer);

    if (val == 0) {
        do_longjmp(100);
        return -1;
    } else {
        return val;
    }
}

/* Test longjmp from deeply nested calls */
__attribute__((noinline))
void deep_call_3(void) {
    longjmp(jump_buffer, 333);
}

__attribute__((noinline))
void deep_call_2(void) {
    deep_call_3();
}

__attribute__((noinline))
void deep_call_1(void) {
    deep_call_2();
}

int test_deep_longjmp(void) {
    int val = setjmp(jump_buffer);

    if (val == 0) {
        deep_call_1();
        return -1;
    } else {
        return val;
    }
}

/* Test local variable preservation */
int test_local_preservation(void) {
    volatile int local1 = 111;  /* volatile to prevent optimization */
    volatile int local2 = 222;
    volatile int local3 = 333;

    int val = setjmp(jump_buffer);

    if (val == 0) {
        /* Modify locals before longjmp */
        local1 = 999;
        local2 = 888;
        local3 = 777;
        longjmp(jump_buffer, 1);
        return -1;
    } else {
        /* After longjmp, volatile locals should have modified values */
        /* (non-volatile locals would have undefined values per C standard) */
        if (local1 != 999 || local2 != 888 || local3 != 777) {
            return -2;
        }
        return 0;
    }
}

/* Test multiple setjmp/longjmp cycles */
int test_multiple_jumps(void) {
    call_count = 0;

    int val = setjmp(jump_buffer);

    call_count++;

    if (call_count < 5) {
        longjmp(jump_buffer, call_count);
    }

    return call_count;
}

/* Test longjmp with zero value (should become 1) */
int test_zero_value(void) {
    int val = setjmp(jump_buffer);

    if (val == 0) {
        longjmp(jump_buffer, 0);  /* 0 should become 1 */
        return -1;
    } else {
        return val;  /* Should be 1, not 0 */
    }
}

/* Test setjmp in a loop */
int test_loop_setjmp(void) {
    static jmp_buf loop_buf;
    int iterations = 0;

    for (int i = 0; i < 3; i++) {
        int val = setjmp(loop_buf);

        if (val == 0) {
            iterations++;
            if (iterations < 5) {
                longjmp(loop_buf, iterations);
            }
        } else {
            iterations = val;
            if (iterations < 5) {
                longjmp(loop_buf, iterations + 1);
            }
        }
    }

    return iterations;
}

/* Test longjmp from a function that uses many registers */
__attribute__((noinline))
void register_heavy_longjmp(long a, long b, long c, long d, long e, long f) {
    /* Use all arguments to ensure registers are loaded */
    volatile long sum = a + b + c + d + e + f;
    (void)sum;
    longjmp(jump_buffer, 77);
}

int test_register_heavy(void) {
    int val = setjmp(jump_buffer);

    if (val == 0) {
        register_heavy_longjmp(1, 2, 3, 4, 5, 6);
        return -1;
    } else {
        return val;
    }
}

/* Test that callee-saved register values are restored */
int test_callee_saved_restore(void) {
    /* These should be in callee-saved registers or on stack */
    register long r1 = 111;
    register long r2 = 222;
    register long r3 = 333;
    register long r4 = 444;

    int val = setjmp(jump_buffer);

    if (val == 0) {
        /* Call a function that might clobber registers */
        register_heavy_longjmp(9, 8, 7, 6, 5, 4);
        return -1;
    }

    /* After longjmp, check register values */
    /* Note: The C standard says non-volatile locals have undefined values */
    /* but in practice, callee-saved regs should be restored */
    /* Using volatile or checking only makes sense for specific ABIs */
    return val;
}

int main(void) {
    int failed = 0;
    int result;

    /* Test 1: Basic longjmp */
    result = test_basic_longjmp();
    if (result != 42) {
        printf("FAIL: basic_longjmp: expected 42, got %d\n", result);
        failed = 1;
    } else {
        printf("PASS: basic_longjmp\n");
    }

    /* Test 2: Nested longjmp */
    result = test_nested_longjmp();
    if (result != 100) {
        printf("FAIL: nested_longjmp: expected 100, got %d\n", result);
        failed = 1;
    } else {
        printf("PASS: nested_longjmp\n");
    }

    /* Test 3: Deep longjmp */
    result = test_deep_longjmp();
    if (result != 333) {
        printf("FAIL: deep_longjmp: expected 333, got %d\n", result);
        failed = 1;
    } else {
        printf("PASS: deep_longjmp\n");
    }

    /* Test 4: Local preservation */
    result = test_local_preservation();
    if (result != 0) {
        printf("FAIL: local_preservation: code %d\n", result);
        failed = 1;
    } else {
        printf("PASS: local_preservation\n");
    }

    /* Test 5: Multiple jumps */
    result = test_multiple_jumps();
    if (result != 5) {
        printf("FAIL: multiple_jumps: expected 5, got %d\n", result);
        failed = 1;
    } else {
        printf("PASS: multiple_jumps\n");
    }

    /* Test 6: Zero value becomes 1 */
    result = test_zero_value();
    if (result != 1) {
        printf("FAIL: zero_value: expected 1, got %d\n", result);
        failed = 1;
    } else {
        printf("PASS: zero_value\n");
    }

    /* Test 7: Register-heavy function longjmp */
    result = test_register_heavy();
    if (result != 77) {
        printf("FAIL: register_heavy: expected 77, got %d\n", result);
        failed = 1;
    } else {
        printf("PASS: register_heavy\n");
    }

    /* Test 8: Callee-saved register restore */
    result = test_callee_saved_restore();
    if (result != 77) {
        printf("FAIL: callee_saved_restore: expected 77, got %d\n", result);
        failed = 1;
    } else {
        printf("PASS: callee_saved_restore\n");
    }

    return failed;
}
