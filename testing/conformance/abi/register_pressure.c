// CHECK: PASS: many_locals
// CHECK: PASS: locals_across_call
// CHECK: PASS: nested_pressure
// CHECK: PASS: array_pressure

#include <stdio.h>

volatile int side_effect;

__attribute__((noinline))
void clobber(void) {
    side_effect = 42;
}

__attribute__((noinline))
long many_locals_fn(long x) {
    long a = x + 1, b = x + 2, c = x + 3, d = x + 4, e = x + 5;
    long f = x + 6, g = x + 7, h = x + 8, i = x + 9, j = x + 10;
    long k = x + 11, l = x + 12, m = x + 13, n = x + 14, o = x + 15;
    long p = x + 16, q = x + 17, r = x + 18, s = x + 19, t = x + 20;
    return a + b + c + d + e + f + g + h + i + j +
           k + l + m + n + o + p + q + r + s + t;
}

__attribute__((noinline))
long locals_across_call_fn(long x) {
    long a = x * 2, b = x * 3, c = x * 5, d = x * 7, e = x * 11;
    long f = x * 13, g = x * 17, h = x * 19, i = x * 23, j = x * 29;
    long k = x * 31, l = x * 37, m = x * 41, n = x * 43, o = x * 47;
    clobber();
    return a + b + c + d + e + f + g + h + i + j + k + l + m + n + o;
}

__attribute__((noinline))
long pressure_inner(long x) {
    long a = x + 1, b = x + 2, c = x + 3, d = x + 4;
    long e = x + 5, f = x + 6, g = x + 7, h = x + 8;
    clobber();
    return a + b + c + d + e + f + g + h;
}

__attribute__((noinline))
long pressure_outer(long x) {
    long a = x * 2, b = x * 3, c = x * 4, d = x * 5;
    long r1 = pressure_inner(a);
    long r2 = pressure_inner(b);
    if (a != x * 2 || b != x * 3 || c != x * 4 || d != x * 5) return -1;
    return r1 + r2 + c + d;
}

__attribute__((noinline))
long array_pressure_fn(long x) {
    long arr[20];
    for (int i = 0; i < 20; i++)
        arr[i] = x + i;
    clobber();
    long sum = 0;
    for (int i = 0; i < 20; i++)
        sum += arr[i];
    return sum;
}

int main(void) {
    int failed = 0;

    // many_locals: sum of (x+1) + (x+2) + ... + (x+20) = 20*x + 210
    {
        long r = many_locals_fn(100);
        if (r == 20 * 100 + 210) printf("PASS: many_locals\n");
        else { printf("FAIL: many_locals: got %ld\n", r); failed = 1; }
    }

    // locals_across_call: x*(2+3+5+7+11+13+17+19+23+29+31+37+41+43+47)
    {
        long x = 10;
        long expected = x * (2+3+5+7+11+13+17+19+23+29+31+37+41+43+47);
        long r = locals_across_call_fn(x);
        if (r == expected) printf("PASS: locals_across_call\n");
        else { printf("FAIL: locals_across_call: got %ld expected %ld\n", r, expected); failed = 1; }
    }

    // nested_pressure
    {
        long r = pressure_outer(10);
        if (r >= 0) printf("PASS: nested_pressure\n");
        else { printf("FAIL: nested_pressure\n"); failed = 1; }
    }

    // array_pressure: sum of (x+0) + (x+1) + ... + (x+19) = 20*x + 190
    {
        long r = array_pressure_fn(50);
        if (r == 20 * 50 + 190) printf("PASS: array_pressure\n");
        else { printf("FAIL: array_pressure: got %ld\n", r); failed = 1; }
    }

    return failed;
}
