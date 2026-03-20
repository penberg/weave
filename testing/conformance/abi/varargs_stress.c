// CHECK: PASS: gp20_sum
// CHECK: PASS: pairs10_sum
// CHECK: PASS: ptr_call_gp12
// CHECK: PASS: forward_via_va_list
// CHECK: PASS: nested_va_copy
// CHECK: PASS: sp_align

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

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

    return failed ? 1 : 0;
}

