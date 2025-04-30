/*
 * Test function pointer and callback ABI compliance.
 *
 * Function pointers and callbacks are critical for binary translators because:
 * - Indirect calls must route through the dispatcher
 * - Callback addresses must be valid in the guest address space
 * - Arguments must be correctly passed to callback functions
 * - Return values must be correctly retrieved
 *
 * This is distinct from testing libc callbacks (like qsort) - this tests
 * pure guest-to-guest indirect calls.
 */

#include <stdio.h>

/* Basic callback types */
typedef int (*int_func_t)(int);
typedef int (*binary_func_t)(int, int);
typedef void (*void_func_t)(void);
typedef double (*double_func_t)(double, double);

/* Simple callback functions */
__attribute__((noinline))
int add_one(int x) {
    return x + 1;
}

__attribute__((noinline))
int multiply_two(int x) {
    return x * 2;
}

__attribute__((noinline))
int square(int x) {
    return x * x;
}

/* Binary operation callbacks */
__attribute__((noinline))
int add(int a, int b) {
    return a + b;
}

__attribute__((noinline))
int subtract(int a, int b) {
    return a - b;
}

__attribute__((noinline))
int multiply(int a, int b) {
    return a * b;
}

/* Double callbacks */
__attribute__((noinline))
double dadd(double a, double b) {
    return a + b;
}

__attribute__((noinline))
double dmultiply(double a, double b) {
    return a * b;
}

/* Void callback for side effects */
static int side_effect_value = 0;

__attribute__((noinline))
void set_value(void) {
    side_effect_value = 42;
}

__attribute__((noinline))
void increment_value(void) {
    side_effect_value++;
}

/* Function that calls a callback */
__attribute__((noinline))
int apply_int_func(int_func_t func, int value) {
    return func(value);
}

__attribute__((noinline))
int apply_binary_func(binary_func_t func, int a, int b) {
    return func(a, b);
}

__attribute__((noinline))
double apply_double_func(double_func_t func, double a, double b) {
    return func(a, b);
}

__attribute__((noinline))
void apply_void_func(void_func_t func) {
    func();
}

/* Array of function pointers */
int_func_t func_array[] = { add_one, multiply_two, square };

/* Test calling through array of function pointers */
__attribute__((noinline))
int apply_from_array(int index, int value) {
    return func_array[index](value);
}

/* Callback that itself uses a callback */
__attribute__((noinline))
int nested_callback(int_func_t outer, int_func_t inner, int value) {
    return outer(inner(value));
}

/* Higher-order function: returns a function pointer */
__attribute__((noinline))
int_func_t select_func(int choice) {
    switch (choice) {
        case 0: return add_one;
        case 1: return multiply_two;
        default: return square;
    }
}

/* Function that stores and later calls a callback */
static int_func_t stored_callback = NULL;

__attribute__((noinline))
void store_callback(int_func_t func) {
    stored_callback = func;
}

__attribute__((noinline))
int call_stored_callback(int value) {
    if (stored_callback) {
        return stored_callback(value);
    }
    return -1;
}

/* Callback with many arguments (tests stack/register handling) */
typedef long (*many_args_func_t)(long, long, long, long, long, long, long, long);

__attribute__((noinline))
long sum_eight(long a, long b, long c, long d, long e, long f, long g, long h) {
    return a + b + c + d + e + f + g + h;
}

__attribute__((noinline))
long apply_many_args(many_args_func_t func, long a, long b, long c, long d,
                     long e, long f, long g, long h) {
    return func(a, b, c, d, e, f, g, h);
}

/* Struct-returning callback */
struct Point {
    int x;
    int y;
};

typedef struct Point (*point_func_t)(int, int);

__attribute__((noinline))
struct Point make_point(int x, int y) {
    struct Point p = { x, y };
    return p;
}

__attribute__((noinline))
struct Point apply_point_func(point_func_t func, int x, int y) {
    return func(x, y);
}

/* Recursive callback using void* for self-reference */
typedef int (*recursive_func_t)(void *, int);

__attribute__((noinline))
int recursive_callback(void *self, int n) {
    if (n <= 0) return 1;
    recursive_func_t func = (recursive_func_t)self;
    return n * func(self, n - 1);  /* Factorial via self-reference */
}

int main(void) {
    int failed = 0;

    /* Test 1: Simple callback */
    {
        int result = apply_int_func(add_one, 10);
        if (result != 11) {
            printf("FAIL: simple_callback: expected 11, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: simple_callback\n");
        }
    }

    /* Test 2: Different callbacks same interface */
    {
        int r1 = apply_int_func(add_one, 5);
        int r2 = apply_int_func(multiply_two, 5);
        int r3 = apply_int_func(square, 5);
        if (r1 != 6 || r2 != 10 || r3 != 25) {
            printf("FAIL: different_callbacks: got %d, %d, %d\n", r1, r2, r3);
            failed = 1;
        } else {
            printf("PASS: different_callbacks\n");
        }
    }

    /* Test 3: Binary operation callback */
    {
        int r1 = apply_binary_func(add, 10, 5);
        int r2 = apply_binary_func(subtract, 10, 5);
        int r3 = apply_binary_func(multiply, 10, 5);
        if (r1 != 15 || r2 != 5 || r3 != 50) {
            printf("FAIL: binary_callback: got %d, %d, %d\n", r1, r2, r3);
            failed = 1;
        } else {
            printf("PASS: binary_callback\n");
        }
    }

    /* Test 4: Double callback */
    {
        double r1 = apply_double_func(dadd, 1.5, 2.5);
        double r2 = apply_double_func(dmultiply, 3.0, 4.0);
        if (r1 < 3.99 || r1 > 4.01 || r2 < 11.99 || r2 > 12.01) {
            printf("FAIL: double_callback: got %f, %f\n", r1, r2);
            failed = 1;
        } else {
            printf("PASS: double_callback\n");
        }
    }

    /* Test 5: Void callback */
    {
        side_effect_value = 0;
        apply_void_func(set_value);
        if (side_effect_value != 42) {
            printf("FAIL: void_callback: expected 42, got %d\n", side_effect_value);
            failed = 1;
        } else {
            printf("PASS: void_callback\n");
        }
    }

    /* Test 6: Function pointer array */
    {
        int r0 = apply_from_array(0, 10);  /* add_one(10) = 11 */
        int r1 = apply_from_array(1, 10);  /* multiply_two(10) = 20 */
        int r2 = apply_from_array(2, 10);  /* square(10) = 100 */
        if (r0 != 11 || r1 != 20 || r2 != 100) {
            printf("FAIL: array_callback: got %d, %d, %d\n", r0, r1, r2);
            failed = 1;
        } else {
            printf("PASS: array_callback\n");
        }
    }

    /* Test 7: Nested callbacks */
    {
        /* add_one(multiply_two(5)) = add_one(10) = 11 */
        int result = nested_callback(add_one, multiply_two, 5);
        if (result != 11) {
            printf("FAIL: nested_callback: expected 11, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: nested_callback\n");
        }
    }

    /* Test 8: Function returning function pointer */
    {
        int_func_t f0 = select_func(0);
        int_func_t f1 = select_func(1);
        int_func_t f2 = select_func(2);
        int r0 = f0(10);  /* add_one(10) = 11 */
        int r1 = f1(10);  /* multiply_two(10) = 20 */
        int r2 = f2(10);  /* square(10) = 100 */
        if (r0 != 11 || r1 != 20 || r2 != 100) {
            printf("FAIL: select_func: got %d, %d, %d\n", r0, r1, r2);
            failed = 1;
        } else {
            printf("PASS: select_func\n");
        }
    }

    /* Test 9: Stored callback */
    {
        store_callback(square);
        int result = call_stored_callback(7);
        if (result != 49) {
            printf("FAIL: stored_callback: expected 49, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: stored_callback\n");
        }
    }

    /* Test 10: Callback with many arguments */
    {
        long result = apply_many_args(sum_eight, 1, 2, 3, 4, 5, 6, 7, 8);
        if (result != 36) {
            printf("FAIL: many_args_callback: expected 36, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: many_args_callback\n");
        }
    }

    /* Test 11: Struct-returning callback */
    {
        struct Point p = apply_point_func(make_point, 100, 200);
        if (p.x != 100 || p.y != 200) {
            printf("FAIL: struct_callback: got (%d, %d)\n", p.x, p.y);
            failed = 1;
        } else {
            printf("PASS: struct_callback\n");
        }
    }

    /* Test 12: Recursive self-referencing callback */
    {
        /* 5! = 120 */
        int result = recursive_callback((void *)recursive_callback, 5);
        if (result != 120) {
            printf("FAIL: recursive_callback: expected 120, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: recursive_callback\n");
        }
    }

    /* Test 13: Multiple void callbacks in sequence */
    {
        side_effect_value = 0;
        for (int i = 0; i < 10; i++) {
            apply_void_func(increment_value);
        }
        if (side_effect_value != 10) {
            printf("FAIL: sequential_void: expected 10, got %d\n", side_effect_value);
            failed = 1;
        } else {
            printf("PASS: sequential_void\n");
        }
    }

    return failed;
}
