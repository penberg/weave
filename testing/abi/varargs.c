// CHECK: PASS: gp20_sum
// CHECK: PASS: pairs10_sum
// CHECK: PASS: ptr_call_gp12
// CHECK: PASS: forward_via_va_list
// CHECK: PASS: nested_va_copy
// CHECK: PASS: sp_align
// CHECK: PASS: promote_chars_shorts_bools
// CHECK: PASS: promote_floats_to_double
// CHECK: PASS: pairs16_sum
// CHECK: PASS: long_double_triple
// CHECK: PASS: syscall_then_varargs

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <unistd.h>

static int sum_ints(int n, ...) {
    va_list ap; va_start(ap, n);
    long long acc = 0;
    for (int i=0;i<n;i++) acc += va_arg(ap,int);
    va_end(ap);
    return (int)acc;
}

static int sum_pairs(int n_pairs, ...) {
    va_list ap; va_start(ap, n_pairs);
    long long acc = 0;
    for (int i=0;i<n_pairs;i++) {
        int x = va_arg(ap,int);
        double d = va_arg(ap,double);
        acc += x + (int)d;
    }
    va_end(ap);
    return (int)acc;
}

static int sum_ints_va(int n, va_list ap) {
    va_list cp; va_copy(cp, ap);
    long long acc = 0;
    for (int i=0;i<n;i++) acc += va_arg(cp,int);
    va_end(cp);
    return (int)acc;
}

static int forward_sum_ints(int n, ...) {
    va_list ap; va_start(ap, n);
    int r = sum_ints_va(n, ap);
    va_end(ap);
    return r;
}

static int nested_copy_helper(va_list *pap, int n) {
    va_list cp; va_copy(cp, *pap);
    long long acc = 0;
    for (int i=0;i<n;i++) acc += va_arg(cp,int);
    va_end(cp);
    return (int)acc;
}

static int nested_copy(int n, ...) {
    va_list ap; va_start(ap, n);
    int r = nested_copy_helper(&ap, n);
    va_end(ap);
    return r;
}

static int check_sp_aligned(void) {
    uintptr_t sp;
#if defined(__aarch64__)
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
#elif defined(__x86_64__)
    __asm__ volatile ("mov %%rsp, %0" : "=r"(sp));
#else
    sp = (uintptr_t)&sp;
#endif
    return (sp & 0xF) == 0;
}

static int approx_eq(double a, double b, double eps) {
    return fabs(a - b) < eps;
}

static int approx_eql(long double a, long double b, long double eps) {
    return fabsl(a - b) < eps;
}

/* Sum floats passed via varargs (promoted to double) */
static double sum_floats_promoted(int n, ...) {
    va_list ap; va_start(ap, n);
    double acc = 0.0;
    for (int i = 0; i < n; i++) acc += va_arg(ap, double);
    va_end(ap);
    return acc;
}

/* Sum long doubles passed via varargs */
static long double sum_long_double(int n, ...) {
    va_list ap; va_start(ap, n);
    long double acc = 0.0L;
    for (int i = 0; i < n; i++) acc += va_arg(ap, long double);
    va_end(ap);
    return acc;
}

/* Perform a syscall before consuming varargs, then sum ints */
static int sum_after_syscall(int n, ...) {
    (void)getpid();
    va_list ap; va_start(ap, n);
    long long acc = 0;
    for (int i = 0; i < n; i++) acc += va_arg(ap, int);
    va_end(ap);
    return (int)acc;
}

int main(void) {
    int failed = 0;

    // 1) 20 GP ints (overflows GP regs onto stack)
    int a = sum_ints(20, 1,2,3,4,5,6,7,8,9,10,
                          11,12,13,14,15,16,17,18,19,20);
    if (a == 210) printf("PASS: gp20_sum\n"); else { printf("FAIL: gp20_sum=%d\n", a); failed = 1; }

    // 2) 10 (int,double) pairs – mixes GP/FP, stresses FP spill/restore
    int b = sum_pairs(10,
        1, (double)1, 2, (double)2, 3, (double)3, 4, (double)4, 5, (double)5,
        6, (double)6, 7, (double)7, 8, (double)8, 9, (double)9, 10, (double)10);
    if (b == (1+1)+(2+2)+(3+3)+(4+4)+(5+5)+(6+6)+(7+7)+(8+8)+(9+9)+(10+10))
        printf("PASS: pairs10_sum\n");
    else { printf("FAIL: pairs10_sum=%d\n", b); failed = 1; }

    // 3) Function pointer varargs call (compiler emits BLR)
    int (*fn)(int, ...) = sum_ints;
    int c = fn(12, 1,2,3,4,5,6,7,8,9,10,11,12);
    if (c == 78) printf("PASS: ptr_call_gp12\n"); else { printf("FAIL: ptr_call_gp12=%d\n", c); failed = 1; }

    // 4) Forwarder via va_list
    int d = forward_sum_ints(10, 1,2,3,4,5,6,7,8,9,10);
    if (d == 55) printf("PASS: forward_via_va_list\n"); else { printf("FAIL: forward_via_va_list=%d\n", d); failed = 1; }

    // 5) Nested va_copy across multiple frames
    int e = nested_copy(8, 1,2,3,4,5,6,7,8);
    if (e == 36) printf("PASS: nested_va_copy\n"); else { printf("FAIL: nested_va_copy=%d\n", e); failed = 1; }

    // 6) SP alignment at entry
    if (check_sp_aligned()) printf("PASS: sp_align\n"); else { printf("FAIL: sp_align\n"); failed = 1; }

    /* 7) Default promotions: char/short/bool -> int */
    {
        int r = sum_ints(6, (char)1, (short)2, (bool)1, (char)-3, (short)-4, (bool)0);
        if (r == (1 + 2 + 1 - 3 - 4 + 0)) printf("PASS: promote_chars_shorts_bools\n");
        else { printf("FAIL: promote_chars_shorts_bools=%d\n", r); failed = 1; }
    }

    /* 8) float -> double promotion in varargs */
    {
        double s = sum_floats_promoted(3, (float)1.5f, (float)2.0f, (float)3.5f);
        if (approx_eq(s, 7.0, 1e-9)) printf("PASS: promote_floats_to_double\n");
        else { printf("FAIL: promote_floats_to_double=%f\n", s); failed = 1; }
    }

    /* 9) 16 (int,double) pairs – pushes well past register window */
    {
        int b16 = sum_pairs(16,
            1,(double)1, 2,(double)2, 3,(double)3, 4,(double)4,
            5,(double)5, 6,(double)6, 7,(double)7, 8,(double)8,
            9,(double)9, 10,(double)10, 11,(double)11, 12,(double)12,
            13,(double)13, 14,(double)14, 15,(double)15, 16,(double)16);
        int expected = 2 * (16 * 17 / 2); /* sum(1..16) * 2 */
        if (b16 == expected) printf("PASS: pairs16_sum\n");
        else { printf("FAIL: pairs16_sum=%d\n", b16); failed = 1; }
    }

    /* 10) long double in varargs (alignment and width) */
    {
        long double ld = sum_long_double(3, 1.0L, 2.0L, 3.0L);
        if (approx_eql(ld, 6.0L, 1e-12L)) printf("PASS: long_double_triple\n");
        else { printf("FAIL: long_double_triple=%.3Lf\n", ld); failed = 1; }
    }

    /* 11) syscall before reading varargs (regression guard) */
    {
        int s = sum_after_syscall(10, 1,2,3,4,5,6,7,8,9,10);
        if (s == 55) printf("PASS: syscall_then_varargs\n");
        else { printf("FAIL: syscall_then_varargs=%d\n", s); failed = 1; }
    }

    return failed ? 1 : 0;
}
