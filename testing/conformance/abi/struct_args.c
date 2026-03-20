/*
 * Test struct passing ABI compliance.
 *
 * This tests how structs are passed to and returned from functions.
 * The ABI specifies different handling based on struct size and composition:
 * - Small structs (≤16 bytes on x86-64, ≤16 bytes on ARM64) passed in registers
 * - Larger structs passed via hidden pointer
 * - Structs with floating-point members may use FP registers
 *
 * Binary translators must correctly handle the memory layout and register
 * allocation for struct arguments and return values.
 */

#include <stdio.h>
#include <string.h>

/* Small struct - fits in one register */
struct Small {
    int x;
};

/* Two-member struct - fits in two registers or one 64-bit register */
struct Pair {
    int a;
    int b;
};

/* Struct exactly 16 bytes - boundary case for register passing */
struct Point3D {
    double x;
    double y;
};

/* Large struct - must be passed via hidden pointer */
struct Large {
    int data[8];  /* 32 bytes */
};

/* Mixed int/float struct - tests FP register allocation */
struct Mixed {
    int i;
    float f;
    double d;
};

/* Nested struct */
struct Nested {
    struct Pair p;
    int z;
};

/* Prevent inlining to ensure actual function calls */
__attribute__((noinline))
struct Small make_small(int x) {
    struct Small s = { x };
    return s;
}

__attribute__((noinline))
int use_small(struct Small s) {
    return s.x * 2;
}

__attribute__((noinline))
struct Pair make_pair(int a, int b) {
    struct Pair p = { a, b };
    return p;
}

__attribute__((noinline))
int use_pair(struct Pair p) {
    return p.a + p.b;
}

__attribute__((noinline))
struct Point3D make_point(double x, double y) {
    struct Point3D p = { x, y };
    return p;
}

__attribute__((noinline))
double use_point(struct Point3D p) {
    return p.x + p.y;
}

__attribute__((noinline))
struct Large make_large(int seed) {
    struct Large l;
    for (int i = 0; i < 8; i++) {
        l.data[i] = seed + i;
    }
    return l;
}

__attribute__((noinline))
int use_large(struct Large l) {
    int sum = 0;
    for (int i = 0; i < 8; i++) {
        sum += l.data[i];
    }
    return sum;
}

__attribute__((noinline))
struct Mixed make_mixed(int i, float f, double d) {
    struct Mixed m = { i, f, d };
    return m;
}

__attribute__((noinline))
double use_mixed(struct Mixed m) {
    return m.i + m.f + m.d;
}

__attribute__((noinline))
struct Nested make_nested(int a, int b, int z) {
    struct Nested n = { { a, b }, z };
    return n;
}

__attribute__((noinline))
int use_nested(struct Nested n) {
    return n.p.a + n.p.b + n.z;
}

/* Test struct passed along with other arguments */
__attribute__((noinline))
int mixed_args(int before, struct Pair p, int after) {
    return before + p.a + p.b + after;
}

/* Test multiple struct arguments */
__attribute__((noinline))
int multi_struct(struct Small s1, struct Pair p, struct Small s2) {
    return s1.x + p.a + p.b + s2.x;
}

int main(void) {
    int failed = 0;

    /* Test 1: Small struct */
    {
        struct Small s = make_small(42);
        int result = use_small(s);
        if (result != 84) {
            printf("FAIL: small struct: expected 84, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: small struct\n");
        }
    }

    /* Test 2: Pair struct */
    {
        struct Pair p = make_pair(10, 20);
        int result = use_pair(p);
        if (result != 30) {
            printf("FAIL: pair struct: expected 30, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: pair struct\n");
        }
    }

    /* Test 3: Point3D (floating point struct) */
    {
        struct Point3D p = make_point(1.5, 2.5);
        double result = use_point(p);
        if (result < 3.99 || result > 4.01) {
            printf("FAIL: point struct: expected 4.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: point struct\n");
        }
    }

    /* Test 4: Large struct (hidden pointer) */
    {
        struct Large l = make_large(10);
        int result = use_large(l);
        /* Sum of 10+11+12+13+14+15+16+17 = 108 */
        if (result != 108) {
            printf("FAIL: large struct: expected 108, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: large struct\n");
        }
    }

    /* Test 5: Mixed int/float struct */
    {
        struct Mixed m = make_mixed(10, 2.5f, 3.5);
        double result = use_mixed(m);
        if (result < 15.99 || result > 16.01) {
            printf("FAIL: mixed struct: expected 16.0, got %f\n", result);
            failed = 1;
        } else {
            printf("PASS: mixed struct\n");
        }
    }

    /* Test 6: Nested struct */
    {
        struct Nested n = make_nested(1, 2, 3);
        int result = use_nested(n);
        if (result != 6) {
            printf("FAIL: nested struct: expected 6, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: nested struct\n");
        }
    }

    /* Test 7: Struct mixed with scalar arguments */
    {
        struct Pair p = { 100, 200 };
        int result = mixed_args(1, p, 2);
        if (result != 303) {
            printf("FAIL: mixed args: expected 303, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: mixed args\n");
        }
    }

    /* Test 8: Multiple struct arguments */
    {
        struct Small s1 = { 1 };
        struct Pair p = { 10, 20 };
        struct Small s2 = { 2 };
        int result = multi_struct(s1, p, s2);
        if (result != 33) {
            printf("FAIL: multi struct: expected 33, got %d\n", result);
            failed = 1;
        } else {
            printf("PASS: multi struct\n");
        }
    }

    return failed;
}
