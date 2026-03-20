/*
 * Test argument passing with many arguments (stack spill).
 *
 * When the number of arguments exceeds available registers, additional
 * arguments are passed on the stack:
 * - x86-64 System V: 6 integer regs (RDI,RSI,RDX,RCX,R8,R9), 8 FP regs (XMM0-7)
 * - ARM64: 8 integer regs (X0-X7), 8 FP regs (D0-D7)
 *
 * Binary translators must correctly handle:
 * - Stack argument layout and alignment
 * - Correct ordering of stack vs register arguments
 * - Stack cleanup after call
 */

#include <stdio.h>

/* 10 integer arguments - definitely spills to stack */
__attribute__((noinline))
long sum10_int(long a, long b, long c, long d, long e,
               long f, long g, long h, long i, long j) {
    return a + b + c + d + e + f + g + h + i + j;
}

/* 15 integer arguments - more stack usage */
__attribute__((noinline))
long sum15_int(long a, long b, long c, long d, long e,
               long f, long g, long h, long i, long j,
               long k, long l, long m, long n, long o) {
    return a + b + c + d + e + f + g + h + i + j + k + l + m + n + o;
}

/* Mixed types with many arguments */
__attribute__((noinline))
double mixed_many(int i1, double d1, int i2, double d2,
                  int i3, double d3, int i4, double d4,
                  int i5, double d5, int i6, double d6,
                  int i7, double d7, int i8, double d8) {
    return i1 + d1 + i2 + d2 + i3 + d3 + i4 + d4 +
           i5 + d5 + i6 + d6 + i7 + d7 + i8 + d8;
}

/* Test that spilled arguments maintain correct values */
__attribute__((noinline))
int verify_order(int a, int b, int c, int d, int e,
                 int f, int g, int h, int i, int j) {
    if (a != 1) return 1;
    if (b != 2) return 2;
    if (c != 3) return 3;
    if (d != 4) return 4;
    if (e != 5) return 5;
    if (f != 6) return 6;
    if (g != 7) return 7;
    if (h != 8) return 8;
    if (i != 9) return 9;
    if (j != 10) return 10;
    return 0;
}

/* Test with pointers - ensures address correctness on stack */
__attribute__((noinline))
long sum_ptrs(long *a, long *b, long *c, long *d, long *e,
              long *f, long *g, long *h, long *i, long *j) {
    return *a + *b + *c + *d + *e + *f + *g + *h + *i + *j;
}

/* Recursive function with many arguments tests stack frame handling */
__attribute__((noinline))
long recursive_sum(int depth, long a, long b, long c, long d,
                   long e, long f, long g, long h) {
    if (depth == 0) {
        return a + b + c + d + e + f + g + h;
    }
    return recursive_sum(depth - 1, a + 1, b + 1, c + 1, d + 1,
                         e + 1, f + 1, g + 1, h + 1);
}

/* Test calling function with many args, then using result */
__attribute__((noinline))
long chain_many(long a, long b, long c, long d, long e,
                long f, long g, long h, long i, long j) {
    long result = sum10_int(a, b, c, d, e, f, g, h, i, j);
    return result * 2;
}

/* Varargs with many preceding fixed arguments */
__attribute__((noinline))
long fixed_then_varargs(long a, long b, long c, long d, long e,
                        long f, long g, long h, ...) {
    return a + b + c + d + e + f + g + h;
}

/* All different sizes to test alignment */
__attribute__((noinline))
long mixed_sizes(char c1, short s1, int i1, long l1,
                 char c2, short s2, int i2, long l2,
                 char c3, short s3, int i3, long l3) {
    return c1 + s1 + i1 + l1 + c2 + s2 + i2 + l2 + c3 + s3 + i3 + l3;
}

int main(void) {
    int failed = 0;

    /* Test 1: 10 integer arguments */
    {
        /* 1+2+3+4+5+6+7+8+9+10 = 55 */
        long result = sum10_int(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        if (result != 55) {
            printf("FAIL: sum10_int: expected 55, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: sum10_int\n");
        }
    }

    /* Test 2: 15 integer arguments */
    {
        /* 1+2+...+15 = 120 */
        long result = sum15_int(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        if (result != 120) {
            printf("FAIL: sum15_int: expected 120, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: sum15_int\n");
        }
    }

    /* Test 3: Mixed int/double many args */
    {
        /* (1+2+3+4+5+6+7+8) + (1+2+3+4+5+6+7+8) = 36+36 = 72 */
        double result = mixed_many(1, 1.0, 2, 2.0, 3, 3.0, 4, 4.0,
                                   5, 5.0, 6, 6.0, 7, 7.0, 8, 8.0);
        if (result < 71.99 || result > 72.01) {
            printf("FAIL: mixed_many: expected 72.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: mixed_many\n");
        }
    }

    /* Test 4: Verify argument order preserved */
    {
        int result = verify_order(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        if (result != 0) {
            printf("FAIL: verify_order: mismatch at argument %d\n", result);
            failed = 1;
        } else {
            printf("PASS: verify_order\n");
        }
    }

    /* Test 5: Pointer arguments */
    {
        long vals[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
        long result = sum_ptrs(&vals[0], &vals[1], &vals[2], &vals[3], &vals[4],
                               &vals[5], &vals[6], &vals[7], &vals[8], &vals[9]);
        if (result != 550) {
            printf("FAIL: sum_ptrs: expected 550, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: sum_ptrs\n");
        }
    }

    /* Test 6: Recursive with many args */
    {
        /* Start with all 1s, recurse 5 times adding 1 each time */
        /* Final: 6+6+6+6+6+6+6+6 = 48 */
        long result = recursive_sum(5, 1, 1, 1, 1, 1, 1, 1, 1);
        if (result != 48) {
            printf("FAIL: recursive_sum: expected 48, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: recursive_sum\n");
        }
    }

    /* Test 7: Chain call with many args */
    {
        /* sum10_int(1..10) = 55, then * 2 = 110 */
        long result = chain_many(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        if (result != 110) {
            printf("FAIL: chain_many: expected 110, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: chain_many\n");
        }
    }

    /* Test 8: Fixed args before varargs */
    {
        /* 1+2+3+4+5+6+7+8 = 36 */
        long result = fixed_then_varargs(1, 2, 3, 4, 5, 6, 7, 8);
        if (result != 36) {
            printf("FAIL: fixed_then_varargs: expected 36, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: fixed_then_varargs\n");
        }
    }

    /* Test 9: Mixed sizes */
    {
        /* (1+2+3+4) + (5+6+7+8) + (9+10+11+12) = 10+26+42 = 78 */
        long result = mixed_sizes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
        if (result != 78) {
            printf("FAIL: mixed_sizes: expected 78, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: mixed_sizes\n");
        }
    }

    return failed;
}
