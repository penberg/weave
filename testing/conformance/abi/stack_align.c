/*
 * Test stack alignment ABI compliance.
 *
 * The ABI requires 16-byte stack alignment at function call boundaries:
 * - x86-64 System V: RSP must be 16-byte aligned before CALL, so a callee
 *   usually observes entry RSP % 16 == 8 after the return address is pushed.
 * - ARM64: SP must be 16-byte aligned at all times.
 *
 * Binary translators must preserve these rules across translated calls,
 * stack allocations, and variable-length arrays.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Read the current function's stack pointer without adding another call frame. */
static inline uintptr_t get_stack_address(void) {
    uintptr_t sp;
    /* Read actual stack pointer register */
#if defined(__aarch64__)
    __asm__ __volatile__ ("mov %0, sp" : "=r" (sp));
#elif defined(__x86_64__)
    __asm__ __volatile__ ("movq %%rsp, %0" : "=r" (sp));
#else
#error "Unsupported architecture"
#endif
    return sp;
}

static inline uintptr_t normalize_call_boundary_stack(uintptr_t sp) {
#if defined(__aarch64__)
    return sp;
#elif defined(__x86_64__)
    return sp + sizeof(uintptr_t);
#else
#error "Unsupported architecture"
#endif
}

static inline int call_boundary_is_aligned(uintptr_t sp) {
    return (normalize_call_boundary_stack(sp) % 16) == 0;
}

/* Functions with various local variable sizes */
__attribute__((noinline))
uintptr_t func_small_locals(void) {
    volatile char a;
    volatile int b;
    (void)a; (void)b;
    return get_stack_address();
}

__attribute__((noinline))
uintptr_t func_medium_locals(void) {
    volatile char buf[100];
    memset((void *)buf, 0, sizeof(buf));
    return get_stack_address();
}

__attribute__((noinline))
uintptr_t func_large_locals(void) {
    volatile char buf[1024];
    memset((void *)buf, 0, sizeof(buf));
    return get_stack_address();
}

/* Nested calls to stress stack alignment */
__attribute__((noinline))
uintptr_t nested_1(void);
__attribute__((noinline))
uintptr_t nested_2(void);
__attribute__((noinline))
uintptr_t nested_3(void);

__attribute__((noinline))
uintptr_t nested_1(void) {
    volatile int local = 1;
    (void)local;
    return nested_2();
}

__attribute__((noinline))
uintptr_t nested_2(void) {
    volatile int local = 2;
    (void)local;
    return nested_3();
}

__attribute__((noinline))
uintptr_t nested_3(void) {
    return get_stack_address();
}

/* Function with many local variables */
__attribute__((noinline))
uintptr_t many_locals(void) {
    volatile long a = 1, b = 2, c = 3, d = 4;
    volatile long e = 5, f = 6, g = 7, h = 8;
    volatile long i = 9, j = 10, k = 11, l = 12;
    (void)a; (void)b; (void)c; (void)d;
    (void)e; (void)f; (void)g; (void)h;
    (void)i; (void)j; (void)k; (void)l;
    return get_stack_address();
}

/* Recursive function to test many stack frames */
__attribute__((noinline))
int recursive_check_alignment(int depth, int failures) {
    uintptr_t sp = get_stack_address();
    if (!call_boundary_is_aligned(sp)) {
        failures++;
    }

    if (depth <= 0) {
        return failures;
    }

    volatile int local = depth;  /* Use stack space */
    (void)local;

    return recursive_check_alignment(depth - 1, failures);
}

/* Test alignment after various argument counts */
__attribute__((noinline))
uintptr_t args_1(int a) {
    (void)a;
    return get_stack_address();
}

__attribute__((noinline))
uintptr_t args_5(int a, int b, int c, int d, int e) {
    (void)a; (void)b; (void)c; (void)d; (void)e;
    return get_stack_address();
}

__attribute__((noinline))
uintptr_t args_10(int a, int b, int c, int d, int e,
                  int f, int g, int h, int i, int j) {
    (void)a; (void)b; (void)c; (void)d; (void)e;
    (void)f; (void)g; (void)h; (void)i; (void)j;
    return get_stack_address();
}

/* Test with double arguments (may use XMM registers) */
__attribute__((noinline))
uintptr_t double_args(double a, double b, double c, double d) {
    volatile double sum = a + b + c + d;
    (void)sum;
    return get_stack_address();
}

/* Test alignment after calling external function */
__attribute__((noinline))
uintptr_t after_printf(void) {
    printf("");  /* Empty printf - still requires call */
    return get_stack_address();
}

/* Aligned data operations that would fault on misalignment */
__attribute__((noinline))
int aligned_data_test(void) {
    /* These operations may require alignment on some architectures */
    volatile double d1 = 1.5;
    volatile double d2 = 2.5;
    volatile double result = d1 * d2;

    if (result < 3.74 || result > 3.76) {
        return -1;
    }
    return 0;
}

/* Test VLA (variable-length array) alignment */
__attribute__((noinline))
uintptr_t vla_test(int size) {
    volatile char vla[size];
    memset((void *)vla, 0, size);
    return get_stack_address();
}

/* Test alignment preservation across multiple calls */
__attribute__((noinline))
int multi_call_alignment(void) {
    uintptr_t (*volatile small_fn)(void) = func_small_locals;
    uintptr_t (*volatile medium_fn)(void) = func_medium_locals;
    uintptr_t (*volatile large_fn)(void) = func_large_locals;
    uintptr_t sp1 = small_fn();
    uintptr_t sp2 = medium_fn();
    uintptr_t sp3 = large_fn();

    /* Indirect calls keep the call boundary opaque to the optimizer. */
    if (!call_boundary_is_aligned(sp1)) return 1;
    if (!call_boundary_is_aligned(sp2)) return 2;
    if (!call_boundary_is_aligned(sp3)) return 3;
    return 0;
}

int main(void) {
    int failed = 0;

    /* Test 1: Basic stack alignment check */
    {
        uintptr_t sp = get_stack_address();
        if (sp % 16 != 0) {
            printf("FAIL: basic_alignment: sp=0x%lx (mod 16 = %lu)\n",
                   (unsigned long)sp, (unsigned long)(sp % 16));
            failed = 1;
        } else {
            printf("PASS: basic_alignment\n");
        }
    }

    /* Test 2: Alignment with small locals */
    {
        uintptr_t sp = func_small_locals();
        if (!call_boundary_is_aligned(sp)) {
            printf("FAIL: small_locals: sp=0x%lx (call-boundary mod 16 = %lu)\n",
                   (unsigned long)sp,
                   (unsigned long)(normalize_call_boundary_stack(sp) % 16));
            failed = 1;
        } else {
            printf("PASS: small_locals\n");
        }
    }

    /* Test 3: Alignment with medium locals */
    {
        uintptr_t sp = func_medium_locals();
        if (!call_boundary_is_aligned(sp)) {
            printf("FAIL: medium_locals: sp=0x%lx (call-boundary mod 16 = %lu)\n",
                   (unsigned long)sp,
                   (unsigned long)(normalize_call_boundary_stack(sp) % 16));
            failed = 1;
        } else {
            printf("PASS: medium_locals\n");
        }
    }

    /* Test 4: Alignment with large locals */
    {
        uintptr_t sp = func_large_locals();
        if (!call_boundary_is_aligned(sp)) {
            printf("FAIL: large_locals: sp=0x%lx (call-boundary mod 16 = %lu)\n",
                   (unsigned long)sp,
                   (unsigned long)(normalize_call_boundary_stack(sp) % 16));
            failed = 1;
        } else {
            printf("PASS: large_locals\n");
        }
    }

    /* Test 5: Nested function calls */
    {
        uintptr_t sp = nested_1();
        if (!call_boundary_is_aligned(sp)) {
            printf("FAIL: nested_calls: sp=0x%lx (call-boundary mod 16 = %lu)\n",
                   (unsigned long)sp,
                   (unsigned long)(normalize_call_boundary_stack(sp) % 16));
            failed = 1;
        } else {
            printf("PASS: nested_calls\n");
        }
    }

    /* Test 6: Many local variables */
    {
        uintptr_t sp = many_locals();
        if (!call_boundary_is_aligned(sp)) {
            printf("FAIL: many_locals: sp=0x%lx (call-boundary mod 16 = %lu)\n",
                   (unsigned long)sp,
                   (unsigned long)(normalize_call_boundary_stack(sp) % 16));
            failed = 1;
        } else {
            printf("PASS: many_locals\n");
        }
    }

    /* Test 7: Recursive alignment check */
    {
        int failures = recursive_check_alignment(20, 0);
        if (failures > 0) {
            printf("FAIL: recursive_alignment: %d misaligned frames\n", failures);
            failed = 1;
        } else {
            printf("PASS: recursive_alignment\n");
        }
    }

    /* Test 8: Various argument counts */
    {
        uintptr_t sp1 = args_1(1);
        uintptr_t sp5 = args_5(1, 2, 3, 4, 5);
        uintptr_t sp10 = args_10(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);

        if (!call_boundary_is_aligned(sp1) ||
            !call_boundary_is_aligned(sp5) ||
            !call_boundary_is_aligned(sp10)) {
            printf("FAIL: various_args: misaligned\n");
            failed = 1;
        } else {
            printf("PASS: various_args\n");
        }
    }

    /* Test 9: Double arguments */
    {
        uintptr_t sp = double_args(1.0, 2.0, 3.0, 4.0);
        if (!call_boundary_is_aligned(sp)) {
            printf("FAIL: double_args: sp=0x%lx (call-boundary mod 16 = %lu)\n",
                   (unsigned long)sp,
                   (unsigned long)(normalize_call_boundary_stack(sp) % 16));
            failed = 1;
        } else {
            printf("PASS: double_args\n");
        }
    }

    /* Test 10: After printf call */
    {
        uintptr_t sp = after_printf();
        if (!call_boundary_is_aligned(sp)) {
            printf("FAIL: after_printf: sp=0x%lx (call-boundary mod 16 = %lu)\n",
                   (unsigned long)sp,
                   (unsigned long)(normalize_call_boundary_stack(sp) % 16));
            failed = 1;
        } else {
            printf("PASS: after_printf\n");
        }
    }

    /* Test 11: Aligned data operations */
    {
        int result = aligned_data_test();
        if (result != 0) {
            printf("FAIL: aligned_data_test\n");
            failed = 1;
        } else {
            printf("PASS: aligned_data_test\n");
        }
    }

    /* Test 12: VLA alignment */
    {
        uintptr_t sp = vla_test(100);
        if (!call_boundary_is_aligned(sp)) {
            printf("FAIL: vla_alignment: sp=0x%lx (call-boundary mod 16 = %lu)\n",
                   (unsigned long)sp,
                   (unsigned long)(normalize_call_boundary_stack(sp) % 16));
            failed = 1;
        } else {
            printf("PASS: vla_alignment\n");
        }
    }

    /* Test 13: Multi-call alignment consistency */
    {
        int result = multi_call_alignment();
        if (result != 0) {
            printf("FAIL: multi_call_alignment: error at check %d\n", result);
            failed = 1;
        } else {
            printf("PASS: multi_call_alignment\n");
        }
    }

    return failed;
}
