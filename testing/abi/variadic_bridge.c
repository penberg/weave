// CHECK: PASS: gp_spill_sum=78
// CHECK: PASS: mixed_pairs_sum=42
// CHECK: PASS: forward_sum=55

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

// Forward declarations
int call_ptr_ints12(void *fn,
                    int a0,
                    int a1,int a2,int a3,int a4,int a5,int a6,int a7,
                    int a8,int a9,int a10,int a11,int a12);

int call_ptr_pairs6(void *fn,
                    int n_pairs,
                    int a1,int a2,int a3,int a4,int a5,int a6);

static int sum_ints_va(int n, va_list ap) {
    long long acc = 0;
    for (int i = 0; i < n; i++) acc += va_arg(ap, int);
    return (int)acc;
}

int sum_ints(int n, ...) {
    va_list ap; va_start(ap, n);
    int r = sum_ints_va(n, ap);
    va_end(ap);
    return r;
}

static int sum_mixed_pairs_va(int n_pairs, va_list ap) {
    long long acc = 0;
    for (int i = 0; i < n_pairs; i++) {
        int x = va_arg(ap, int);
        double d = va_arg(ap, double);
        acc += x + (int)d;
    }
    return (int)acc;
}

int sum_mixed_pairs(int n_pairs, ...) {
    va_list ap; va_start(ap, n_pairs);
    int r = sum_mixed_pairs_va(n_pairs, ap);
    va_end(ap);
    return r;
}

int forward_sum_ints(int n, ...) {
    va_list ap; va_start(ap, n);
    va_list ap2; va_copy(ap2, ap);
    int r = sum_ints_va(n, ap2);
    va_end(ap2);
    va_end(ap);
    return r;
}

// Provide call_via_x30 as a standalone assembly function to ensure we see
// the incoming register/stack layout exactly as the caller set it.
int call_ptr_ints12(void *fn,
                    int a0,
                    int a1,int a2,int a3,int a4,int a5,int a6,int a7,
                    int a8,int a9,int a10,int a11,int a12) {
    int (*f)(int, ...) = (int (*)(int, ...))fn;
    return f(a0, a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12);
}

int call_ptr_pairs6(void *fn, int n_pairs, int a1,int a2,int a3,int a4,int a5,int a6) {
    int (*f)(int, ...) = (int (*)(int, ...))fn;
    return f(n_pairs,
             a1, (double)a1,
             a2, (double)a2,
             a3, (double)a3,
             a4, (double)a4,
             a5, (double)a5,
             a6, (double)a6);
}

int main(void) {
    int ok = 1;

    // A. GP-only spill: 12 ints => 78
    int a = call_ptr_ints12((void*)sum_ints,
                        12, 1,2,3,4,5,6,7,8,9,10,11,12);
    printf("%s: gp_spill_sum=%d\n", (ok &= (a==78)) ? "PASS" : "FAIL", a);

    // B. Mixed GP/FP pairs: 6 pairs => 42
    // For mixed pairs we still pass ints via this fixed-arity helper; doubles
    // are passed in FP argument registers by the C caller and forwarded across.
    int b = call_ptr_pairs6((void*)sum_mixed_pairs,
                        6, 1,2,3,4,5,6);
    printf("%s: mixed_pairs_sum=%d\n", (ok &= (b==42)) ? "PASS" : "FAIL", b);

    // C. Variadic forwarder via x30: 10 ints => 55
    int c = call_ptr_ints12((void*)forward_sum_ints,
                        10, 1,2,3,4,5,6,7,8,9,10, 0,0);
    printf("%s: forward_sum=%d\n", (ok &= (c==55)) ? "PASS" : "FAIL", c);

    return ok ? 0 : 1;
}
