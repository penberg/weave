// CHECK: PASS: int_to_float
// CHECK: PASS: float_to_int
// CHECK: PASS: fp_comparison
// CHECK: PASS: math_mixed
// CHECK: PASS: union_trick

#include <stdio.h>

__attribute__((noinline))
double int_to_double(int x) {
    return (double)x;
}

__attribute__((noinline))
int double_to_int(double x) {
    return (int)x;
}

__attribute__((noinline))
int fp_compare(double a, double b) {
    if (a > b) return 1;
    if (a < b) return -1;
    return 0;
}

__attribute__((noinline))
double mixed_compute(int n) {
    double sum = 0.0;
    for (int i = 1; i <= n; i++) {
        sum += (double)i * 0.5;
    }
    return sum;
}

int main(void) {
    int failed = 0;

    // int_to_float: round trip
    {
        int vals[] = {0, 1, -1, 42, -100, 1000000};
        int ok = 1;
        for (int i = 0; i < 6; i++) {
            if (double_to_int(int_to_double(vals[i])) != vals[i]) { ok = 0; break; }
        }
        if (ok) printf("PASS: int_to_float\n");
        else { printf("FAIL: int_to_float\n"); failed = 1; }
    }

    // float_to_int: truncation
    {
        if (double_to_int(3.7) == 3 && double_to_int(-2.9) == -2 && double_to_int(0.999) == 0) {
            printf("PASS: float_to_int\n");
        } else { printf("FAIL: float_to_int\n"); failed = 1; }
    }

    // fp_comparison in integer control flow
    {
        if (fp_compare(3.14, 2.71) == 1 && fp_compare(1.0, 2.0) == -1 && fp_compare(5.0, 5.0) == 0) {
            printf("PASS: fp_comparison\n");
        } else { printf("FAIL: fp_comparison\n"); failed = 1; }
    }

    // math_mixed: sum of i*0.5 for i=1..100 = 0.5 * 5050 = 2525.0
    {
        double result = mixed_compute(100);
        if (result > 2524.9 && result < 2525.1) {
            printf("PASS: math_mixed\n");
        } else { printf("FAIL: math_mixed: got %f\n", result); failed = 1; }
    }

    // union trick: reinterpret bits
    {
        union { float f; unsigned int i; } u;
        u.f = 1.0f;
        // IEEE 754: 1.0f = 0x3F800000
        if (u.i == 0x3F800000) {
            u.i = 0x40000000;  // 2.0f
            if (u.f > 1.99f && u.f < 2.01f) {
                printf("PASS: union_trick\n");
            } else { printf("FAIL: union_trick: float\n"); failed = 1; }
        } else { printf("FAIL: union_trick: int 0x%x\n", u.i); failed = 1; }
    }

    return failed;
}
