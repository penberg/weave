/*
 * Test floating-point argument passing ABI compliance.
 *
 * Floating-point arguments are passed in separate registers from integers:
 * - x86-64: XMM0-XMM7 for FP, RDI/RSI/RDX/RCX/R8/R9 for integers
 * - ARM64: D0-D7 for FP, X0-X7 for integers
 *
 * This tests:
 * - Pure float functions
 * - Pure double functions
 * - Mixed integer/float argument ordering
 * - Float return values
 * - Float promotion in varargs
 * - Many FP arguments (spilling to stack)
 */

#include <stdio.h>
#include <stdarg.h>
#include <math.h>

/* Basic float operations */
__attribute__((noinline))
float add_floats(float a, float b) {
    return a + b;
}

__attribute__((noinline))
double add_doubles(double a, double b) {
    return a + b;
}

/* Mixed integer and float - tests interleaved register allocation */
__attribute__((noinline))
double mixed_int_float(int i1, float f1, int i2, double d1, int i3, float f2) {
    return i1 + f1 + i2 + d1 + i3 + f2;
}

/* Alternating types stress test */
__attribute__((noinline))
double alternating(int a, double b, int c, double d, int e, double f, int g, double h) {
    return a + b + c + d + e + f + g + h;
}

/* Many FP arguments - should spill to stack */
__attribute__((noinline))
double many_fp(double a, double b, double c, double d,
               double e, double f, double g, double h,
               double i, double j) {
    return a + b + c + d + e + f + g + h + i + j;
}

/* Float return value */
__attribute__((noinline))
float return_float(int x) {
    return (float)x * 1.5f;
}

/* Double return value */
__attribute__((noinline))
double return_double(int x) {
    return (double)x * 1.5;
}

/* Varargs with floats (promoted to double) */
__attribute__((noinline))
double sum_varargs(int count, ...) {
    va_list ap;
    va_start(ap, count);
    double sum = 0.0;
    for (int i = 0; i < count; i++) {
        sum += va_arg(ap, double);
    }
    va_end(ap);
    return sum;
}

/* Test float operations that might use SIMD */
__attribute__((noinline))
float float_multiply(float a, float b, float c, float d) {
    return a * b + c * d;
}

/* Test double precision preservation */
__attribute__((noinline))
double precision_test(double x) {
    /* Operations that would lose precision if converted to float */
    return x * 1.0000000001 + 0.0000000001;
}

/* Test negative and special values */
__attribute__((noinline))
double special_values(double neg, double zero, double large) {
    return neg + zero + large;
}

/* Test passing float through multiple function calls */
__attribute__((noinline))
double chain_inner(double x) {
    return x * 2.0;
}

__attribute__((noinline))
double chain_middle(double x) {
    return chain_inner(x) + 1.0;
}

__attribute__((noinline))
double chain_outer(double x) {
    return chain_middle(x) + 2.0;
}

/* Approximate comparison for floating point */
int approx_eq(double a, double b, double epsilon) {
    return fabs(a - b) < epsilon;
}

int main(void) {
    int failed = 0;
    const double eps = 0.0001;

    /* Test 1: Basic float addition */
    {
        float result = add_floats(1.5f, 2.5f);
        if (!approx_eq(result, 4.0, eps)) {
            printf("FAIL: add_floats: expected 4.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: add_floats\n");
        }
    }

    /* Test 2: Basic double addition */
    {
        double result = add_doubles(1.5, 2.5);
        if (!approx_eq(result, 4.0, eps)) {
            printf("FAIL: add_doubles: expected 4.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: add_doubles\n");
        }
    }

    /* Test 3: Mixed integer and float arguments */
    {
        /* 1 + 2.5 + 3 + 4.5 + 5 + 6.5 = 22.5 */
        double result = mixed_int_float(1, 2.5f, 3, 4.5, 5, 6.5f);
        if (!approx_eq(result, 22.5, eps)) {
            printf("FAIL: mixed_int_float: expected 22.5, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: mixed_int_float\n");
        }
    }

    /* Test 4: Alternating int/double */
    {
        /* 1 + 2.0 + 3 + 4.0 + 5 + 6.0 + 7 + 8.0 = 36.0 */
        double result = alternating(1, 2.0, 3, 4.0, 5, 6.0, 7, 8.0);
        if (!approx_eq(result, 36.0, eps)) {
            printf("FAIL: alternating: expected 36.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: alternating\n");
        }
    }

    /* Test 5: Many FP arguments (stack spill) */
    {
        /* 1+2+3+4+5+6+7+8+9+10 = 55 */
        double result = many_fp(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0);
        if (!approx_eq(result, 55.0, eps)) {
            printf("FAIL: many_fp: expected 55.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: many_fp\n");
        }
    }

    /* Test 6: Float return value */
    {
        float result = return_float(10);
        if (!approx_eq(result, 15.0f, eps)) {
            printf("FAIL: return_float: expected 15.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: return_float\n");
        }
    }

    /* Test 7: Double return value */
    {
        double result = return_double(10);
        if (!approx_eq(result, 15.0, eps)) {
            printf("FAIL: return_double: expected 15.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: return_double\n");
        }
    }

    /* Test 8: Varargs with doubles */
    {
        double result = sum_varargs(4, 1.0, 2.0, 3.0, 4.0);
        if (!approx_eq(result, 10.0, eps)) {
            printf("FAIL: sum_varargs: expected 10.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: sum_varargs\n");
        }
    }

    /* Test 9: Float multiplication */
    {
        /* 2*3 + 4*5 = 6 + 20 = 26 */
        float result = float_multiply(2.0f, 3.0f, 4.0f, 5.0f);
        if (!approx_eq(result, 26.0f, eps)) {
            printf("FAIL: float_multiply: expected 26.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: float_multiply\n");
        }
    }

    /* Test 10: Precision preservation */
    {
        double x = 1000000000.0;
        double result = precision_test(x);
        double expected = x * 1.0000000001 + 0.0000000001;
        if (!approx_eq(result, expected, 1.0)) {  /* Larger epsilon for big numbers */
            printf("FAIL: precision_test: expected %.10f, got %.10f\n", expected, result);
            failed = 1;
        } else {
            printf("PASS: precision_test\n");
        }
    }

    /* Test 11: Special values */
    {
        double result = special_values(-100.0, 0.0, 1e10);
        double expected = -100.0 + 0.0 + 1e10;
        if (!approx_eq(result, expected, 1.0)) {
            printf("FAIL: special_values: expected %.1f, got %.1f\n", expected, result);
            failed = 1;
        } else {
            printf("PASS: special_values\n");
        }
    }

    /* Test 12: Chained function calls with floats */
    {
        /* chain_outer(5) = chain_middle(5) + 2 = (chain_inner(5) + 1) + 2 = (10 + 1) + 2 = 13 */
        double result = chain_outer(5.0);
        if (!approx_eq(result, 13.0, eps)) {
            printf("FAIL: chain_outer: expected 13.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: chain_outer\n");
        }
    }

    return failed;
}
