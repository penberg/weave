/*
 * Test tail call optimization ABI compliance.
 *
 * Tail call optimization (TCO) converts a call at the end of a function
 * into a jump, reusing the current stack frame. This affects:
 * - Stack frame layout
 * - Return address handling
 * - Callee-saved register restoration
 *
 * Binary translators must handle both:
 * - Regular tail calls (direct jumps)
 * - Indirect tail calls through function pointers
 *
 * Note: Whether TCO occurs depends on compiler optimization level.
 * These tests should work regardless of whether TCO is applied.
 */

#include <stdio.h>

/* Simple tail-recursive factorial */
__attribute__((noinline))
long factorial_tail(long n, long acc) {
    if (n <= 1) return acc;
    return factorial_tail(n - 1, n * acc);  /* Tail call */
}

__attribute__((noinline))
long factorial(long n) {
    return factorial_tail(n, 1);
}

/* Tail-recursive sum */
__attribute__((noinline))
long sum_tail(long n, long acc) {
    if (n <= 0) return acc;
    return sum_tail(n - 1, acc + n);  /* Tail call */
}

__attribute__((noinline))
long sum_to_n(long n) {
    return sum_tail(n, 0);
}

/* Mutual tail recursion */
__attribute__((noinline)) int is_odd(int n);

__attribute__((noinline))
int is_even(int n) {
    if (n == 0) return 1;
    return is_odd(n - 1);  /* Tail call to different function */
}

__attribute__((noinline))
int is_odd(int n) {
    if (n == 0) return 0;
    return is_even(n - 1);  /* Tail call to different function */
}

/* Deep tail recursion - tests stack usage */
__attribute__((noinline))
long deep_tail(long depth, long value) {
    if (depth <= 0) return value;
    return deep_tail(depth - 1, value + 1);  /* Should not grow stack with TCO */
}

/* Tail call with struct return */
struct Result {
    long value;
    int count;
};

__attribute__((noinline))
struct Result count_tail(long n, long sum, int count) {
    if (n <= 0) {
        struct Result r = { sum, count };
        return r;
    }
    return count_tail(n - 1, sum + n, count + 1);  /* Tail call returning struct */
}

__attribute__((noinline))
struct Result count_and_sum(long n) {
    return count_tail(n, 0, 0);
}

/* Tail call through function pointer */
typedef long (*tail_func_t)(long, long);

__attribute__((noinline))
long indirect_helper(long n, long acc) {
    if (n <= 1) return acc;
    return n * acc;  /* Not tail recursive - used as target */
}

__attribute__((noinline))
long indirect_tail(tail_func_t func, long n, long acc) {
    if (n <= 1) return acc;
    return func(n, acc);  /* Tail call through function pointer */
}

/* Tail call after side effects */
static long side_effect_counter = 0;

__attribute__((noinline))
long tail_with_side_effect(long n, long acc) {
    if (n <= 0) return acc;
    side_effect_counter++;
    return tail_with_side_effect(n - 1, acc + n);  /* Tail call after side effect */
}

/* Conditional tail call */
__attribute__((noinline))
long cond_tail_a(long n);

__attribute__((noinline))
long cond_tail_b(long n) {
    if (n <= 0) return 0;
    if (n % 2 == 0) {
        return cond_tail_a(n - 1);  /* Tail call to a */
    }
    return cond_tail_b(n - 2) + 1;  /* Not a tail call */
}

__attribute__((noinline))
long cond_tail_a(long n) {
    if (n <= 0) return 0;
    if (n % 2 == 1) {
        return cond_tail_b(n - 1);  /* Tail call to b */
    }
    return cond_tail_a(n - 2) + 1;  /* Not a tail call */
}

/* Trampoline pattern - explicit continuation passing */
typedef struct Bounce {
    int done;
    long value;
    long arg1;
    long arg2;
} Bounce;

__attribute__((noinline))
Bounce bounce_fib(long n, long a, long b) {
    if (n <= 0) {
        return (Bounce){ 1, a, 0, 0 };
    }
    return (Bounce){ 0, 0, n - 1, a + b };
}

__attribute__((noinline))
long trampoline_fib(long n) {
    long a = 0, b = 1;
    while (n > 0) {
        long next = a + b;
        a = b;
        b = next;
        n--;
    }
    return a;
}

/* Multiple return paths, some tail calls */
__attribute__((noinline))
long multi_return(long n, long acc) {
    if (n < 0) return -1;  /* Error case */
    if (n == 0) return acc;  /* Base case */
    if (n == 1) return acc + 1;  /* Special case */
    return multi_return(n - 2, acc + n);  /* Tail call */
}

int main(void) {
    int failed = 0;

    /* Test 1: Tail-recursive factorial */
    {
        long result = factorial(10);
        if (result != 3628800) {
            printf("FAIL: factorial: expected 3628800, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: factorial\n");
        }
    }

    /* Test 2: Tail-recursive sum */
    {
        long result = sum_to_n(100);
        if (result != 5050) {
            printf("FAIL: sum_to_n: expected 5050, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: sum_to_n\n");
        }
    }

    /* Test 3: Mutual tail recursion - is_even */
    {
        int r1 = is_even(100);
        int r2 = is_even(101);
        if (r1 != 1 || r2 != 0) {
            printf("FAIL: is_even: got %d, %d\n", r1, r2);
            failed = 1;
        } else {
            printf("PASS: is_even\n");
        }
    }

    /* Test 4: Mutual tail recursion - is_odd */
    {
        int r1 = is_odd(100);
        int r2 = is_odd(101);
        if (r1 != 0 || r2 != 1) {
            printf("FAIL: is_odd: got %d, %d\n", r1, r2);
            failed = 1;
        } else {
            printf("PASS: is_odd\n");
        }
    }

    /* Test 5: Deep tail recursion */
    {
        /* With TCO, this should not overflow stack */
        /* Without TCO, this is shallow enough to succeed anyway */
        long result = deep_tail(1000, 0);
        if (result != 1000) {
            printf("FAIL: deep_tail: expected 1000, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: deep_tail\n");
        }
    }

    /* Test 6: Tail call returning struct */
    {
        struct Result r = count_and_sum(10);
        /* sum = 1+2+...+10 = 55, count = 10 */
        if (r.value != 55 || r.count != 10) {
            printf("FAIL: count_and_sum: got value=%ld, count=%d\n", r.value, r.count);
            failed = 1;
        } else {
            printf("PASS: count_and_sum\n");
        }
    }

    /* Test 7: Indirect tail call */
    {
        long result = indirect_tail(indirect_helper, 5, 1);
        /* indirect_helper(5, 1) = 5 * 1 = 5 */
        if (result != 5) {
            printf("FAIL: indirect_tail: expected 5, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: indirect_tail\n");
        }
    }

    /* Test 8: Tail call with side effects */
    {
        side_effect_counter = 0;
        long result = tail_with_side_effect(10, 0);
        /* sum = 1+2+...+10 = 55, counter should be 10 */
        if (result != 55 || side_effect_counter != 10) {
            printf("FAIL: tail_with_side_effect: result=%ld, counter=%ld\n",
                   result, side_effect_counter);
            failed = 1;
        } else {
            printf("PASS: tail_with_side_effect\n");
        }
    }

    /* Test 9: Trampoline Fibonacci */
    {
        long result = trampoline_fib(20);
        /* fib(20) = 6765 */
        if (result != 6765) {
            printf("FAIL: trampoline_fib: expected 6765, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: trampoline_fib\n");
        }
    }

    /* Test 10: Multiple return paths */
    {
        long r1 = multi_return(-1, 0);   /* Error */
        long r2 = multi_return(0, 100);  /* Base */
        long r3 = multi_return(1, 100);  /* Special */
        long r4 = multi_return(10, 0);   /* Tail recursive: 10+8+6+4+2 = 30 */
        if (r1 != -1 || r2 != 100 || r3 != 101 || r4 != 30) {
            printf("FAIL: multi_return: got %ld, %ld, %ld, %ld\n", r1, r2, r3, r4);
            failed = 1;
        } else {
            printf("PASS: multi_return\n");
        }
    }

    /* Test 11: Large factorial (test precision and correctness) */
    {
        long result = factorial(12);
        if (result != 479001600) {
            printf("FAIL: factorial(12): expected 479001600, got %ld\n", result);
            failed = 1;
        } else {
            printf("PASS: factorial(12)\n");
        }
    }

    return failed;
}
