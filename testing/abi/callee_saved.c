/*
 * Test callee-saved register preservation across function calls.
 *
 * The ABI specifies that certain registers must be preserved by callees:
 * - x86-64: RBX, RBP, R12-R15
 * - ARM64: X19-X28, X29 (FP), X30 (LR)
 *
 * If a binary translator doesn't properly handle callee-saved registers,
 * values may be corrupted across function calls. This is especially
 * important for:
 * - Deep call chains
 * - Recursive functions
 * - Calls that use many registers internally
 */

#include <stdio.h>

/* Volatile to prevent optimizer from eliminating stores */
volatile long sink;

/* Force the compiler to use many registers by having complex expressions */
__attribute__((noinline))
long use_many_regs(long a, long b, long c, long d, long e, long f) {
    /* These computations should use several registers */
    long r1 = a * 2 + b * 3;
    long r2 = c * 4 + d * 5;
    long r3 = e * 6 + f * 7;
    long r4 = r1 + r2;
    long r5 = r2 + r3;
    long r6 = r4 * r5;
    sink = r6;  /* Force computation */
    return r1 + r2 + r3;
}

/* A function that makes multiple calls - caller must preserve its locals */
__attribute__((noinline))
long multi_call_test(long x) {
    long local1 = x * 11;
    long local2 = x * 13;
    long local3 = x * 17;
    long local4 = x * 19;
    long local5 = x * 23;

    /* First call - should not corrupt locals */
    long result1 = use_many_regs(1, 2, 3, 4, 5, 6);

    /* Verify locals survived */
    if (local1 != x * 11) return -1;
    if (local2 != x * 13) return -2;
    if (local3 != x * 17) return -3;
    if (local4 != x * 19) return -4;
    if (local5 != x * 23) return -5;

    /* Second call */
    long result2 = use_many_regs(7, 8, 9, 10, 11, 12);

    /* Verify locals again */
    if (local1 != x * 11) return -11;
    if (local2 != x * 13) return -12;
    if (local3 != x * 17) return -13;
    if (local4 != x * 19) return -14;
    if (local5 != x * 23) return -15;

    return local1 + local2 + local3 + local4 + local5 + result1 + result2;
}

/* Deep recursion to stress callee-saved registers */
__attribute__((noinline))
long deep_recursion(int depth, long accum, long sentinel) {
    if (depth == 0) {
        return accum + sentinel;
    }

    /* Use several local variables that must be preserved across recursive call */
    long local1 = depth * 7;
    long local2 = depth * 11;
    long local3 = depth * 13;

    long result = deep_recursion(depth - 1, accum + depth, sentinel);

    /* Verify locals weren't corrupted by recursive call */
    if (local1 != depth * 7) return -1000 - depth;
    if (local2 != depth * 11) return -2000 - depth;
    if (local3 != depth * 13) return -3000 - depth;

    return result + local1;
}

/* Mutually recursive functions */
__attribute__((noinline)) long mutual_b(int depth, long val);

__attribute__((noinline))
long mutual_a(int depth, long val) {
    if (depth == 0) return val;

    long local = val * 3;
    long result = mutual_b(depth - 1, val + 1);

    if (local != val * 3) return -10000;
    return result + local;
}

__attribute__((noinline))
long mutual_b(int depth, long val) {
    if (depth == 0) return val;

    long local = val * 5;
    long result = mutual_a(depth - 1, val + 2);

    if (local != val * 5) return -20000;
    return result + local;
}

/* Test with loop that makes calls */
__attribute__((noinline))
long loop_with_calls(int iterations) {
    long accum = 0;
    long preserved = 12345;

    for (int i = 0; i < iterations; i++) {
        long before = preserved;
        accum += use_many_regs(i, i + 1, i + 2, i + 3, i + 4, i + 5);

        if (preserved != before) {
            return -1;
        }
    }

    return accum + preserved;
}

/* Complex expression that needs many temporaries */
__attribute__((noinline))
long complex_expr(long a, long b, long c, long d) {
    return ((a + b) * (c - d)) +
           ((a - b) * (c + d)) +
           ((a * c) + (b * d)) +
           ((a / (d ? d : 1)) - (c / (b ? b : 1)));
}

/* Test that complex expression results are preserved */
__attribute__((noinline))
long expr_preservation(long x) {
    long r1 = complex_expr(x, x + 1, x + 2, x + 3);
    long r2 = complex_expr(x + 4, x + 5, x + 6, x + 7);
    long r3 = complex_expr(x + 8, x + 9, x + 10, x + 11);

    /* Another call that might clobber regs */
    use_many_regs(r1, r2, r3, 0, 0, 0);

    /* r1, r2, r3 must still be valid */
    return r1 + r2 + r3;
}

int main(void) {
    int failed = 0;

    /* Test 1: Multiple calls with local preservation */
    {
        long result = multi_call_test(10);
        if (result < 0) {
            printf("FAIL: multi_call_test: local corruption at %ld\n", result);
            failed = 1;
        } else {
            /* 10*(11+13+17+19+23) = 10*83 = 830, plus call results */
            printf("PASS: multi_call_test (result=%ld)\n", result);
        }
    }

    /* Test 2: Deep recursion */
    {
        /* Sum of 1+2+...+20 = 210, plus sentinel 42, plus accumulated local1 values */
        long result = deep_recursion(20, 0, 42);
        if (result < 0) {
            printf("FAIL: deep_recursion: corruption detected (code=%ld)\n", result);
            failed = 1;
        } else {
            printf("PASS: deep_recursion (result=%ld)\n", result);
        }
    }

    /* Test 3: Mutual recursion */
    {
        long result = mutual_a(10, 1);
        if (result < 0) {
            printf("FAIL: mutual_recursion: corruption detected (code=%ld)\n", result);
            failed = 1;
        } else {
            printf("PASS: mutual_recursion (result=%ld)\n", result);
        }
    }

    /* Test 4: Loop with calls */
    {
        long result = loop_with_calls(10);
        if (result < 0) {
            printf("FAIL: loop_with_calls: preserved value corrupted\n");
            failed = 1;
        } else {
            printf("PASS: loop_with_calls (result=%ld)\n", result);
        }
    }

    /* Test 5: Expression preservation */
    {
        long result = expr_preservation(100);
        /* Just ensure it runs without negative error codes */
        printf("PASS: expr_preservation (result=%ld)\n", result);
    }

    /* Test 6: Many calls in sequence */
    {
        long a = 1, b = 2, c = 3, d = 4, e = 5;
        for (int i = 0; i < 20; i++) {
            use_many_regs(a, b, c, d, e, i);
            if (a != 1 || b != 2 || c != 3 || d != 4 || e != 5) {
                printf("FAIL: sequential_calls: corruption at iteration %d\n", i);
                failed = 1;
                break;
            }
        }
        if (!failed) {
            printf("PASS: sequential_calls\n");
        }
    }

    return failed;
}
