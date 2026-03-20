// CHECK: PASS: for_loop
// CHECK: PASS: while_loop
// CHECK: PASS: do_while_loop
// CHECK: PASS: break_loop
// CHECK: PASS: continue_loop
// CHECK: PASS: nested_loops
// CHECK: PASS: loop_with_call
// CHECK: PASS: large_iteration

#include <stdio.h>

__attribute__((noinline))
long sum_range(long n) {
    long sum = 0;
    for (long i = 1; i <= n; i++)
        sum += i;
    return sum;
}

__attribute__((noinline))
long while_countdown(long n) {
    long sum = 0;
    while (n > 0) {
        sum += n;
        n--;
    }
    return sum;
}

__attribute__((noinline))
long do_while_test(long n) {
    long count = 0;
    do {
        count++;
        n--;
    } while (n > 0);
    return count;
}

__attribute__((noinline))
long break_test(void) {
    long sum = 0;
    for (int i = 0; i < 100; i++) {
        if (i == 10) break;
        sum += i;
    }
    return sum; // 0+1+...+9 = 45
}

__attribute__((noinline))
long continue_test(void) {
    long sum = 0;
    for (int i = 1; i <= 10; i++) {
        if (i % 2 == 0) continue;
        sum += i;
    }
    return sum; // 1+3+5+7+9 = 25
}

__attribute__((noinline))
long nested_loop_test(void) {
    long count = 0;
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 4; j++)
            for (int k = 0; k < 3; k++)
                count++;
    return count; // 5*4*3 = 60
}

__attribute__((noinline))
long identity(long x) {
    return x;
}

__attribute__((noinline))
long loop_call_test(void) {
    long sum = 0;
    for (int i = 1; i <= 10; i++)
        sum += identity(i);
    return sum; // 55
}

__attribute__((noinline))
long large_iter_test(void) {
    long sum = 0;
    for (int i = 0; i < 10000; i++)
        sum += i;
    return sum; // 10000*9999/2 = 49995000
}

int main(void) {
    int failed = 0;

    if (sum_range(100) == 5050) printf("PASS: for_loop\n");
    else { printf("FAIL: for_loop\n"); failed = 1; }

    if (while_countdown(10) == 55) printf("PASS: while_loop\n");
    else { printf("FAIL: while_loop\n"); failed = 1; }

    if (do_while_test(5) == 5) printf("PASS: do_while_loop\n");
    else { printf("FAIL: do_while_loop\n"); failed = 1; }

    if (break_test() == 45) printf("PASS: break_loop\n");
    else { printf("FAIL: break_loop\n"); failed = 1; }

    if (continue_test() == 25) printf("PASS: continue_loop\n");
    else { printf("FAIL: continue_loop\n"); failed = 1; }

    if (nested_loop_test() == 60) printf("PASS: nested_loops\n");
    else { printf("FAIL: nested_loops\n"); failed = 1; }

    if (loop_call_test() == 55) printf("PASS: loop_with_call\n");
    else { printf("FAIL: loop_with_call\n"); failed = 1; }

    if (large_iter_test() == 49995000) printf("PASS: large_iteration\n");
    else { printf("FAIL: large_iteration\n"); failed = 1; }

    return failed;
}
