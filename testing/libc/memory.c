// CHECK: PASS: malloc_free
// CHECK: PASS: realloc_grow
// CHECK: PASS: realloc_shrink
// CHECK: PASS: calloc_zero
// CHECK: PASS: large_alloc

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    int failed = 0;

    // malloc and free
    {
        int *p = malloc(10 * sizeof(int));
        if (!p) { printf("FAIL: malloc_free: alloc\n"); return 1; }
        for (int i = 0; i < 10; i++) p[i] = i * i;
        int ok = 1;
        for (int i = 0; i < 10; i++) {
            if (p[i] != i * i) { ok = 0; break; }
        }
        free(p);
        if (ok) printf("PASS: malloc_free\n");
        else { printf("FAIL: malloc_free\n"); failed = 1; }
    }

    // realloc grow
    {
        int *p = malloc(5 * sizeof(int));
        for (int i = 0; i < 5; i++) p[i] = i + 100;
        p = realloc(p, 10 * sizeof(int));
        if (!p) { printf("FAIL: realloc_grow: alloc\n"); return 1; }
        // Original data should be preserved
        int ok = 1;
        for (int i = 0; i < 5; i++) {
            if (p[i] != i + 100) { ok = 0; break; }
        }
        // Fill new area
        for (int i = 5; i < 10; i++) p[i] = i + 200;
        for (int i = 5; i < 10; i++) {
            if (p[i] != i + 200) { ok = 0; break; }
        }
        free(p);
        if (ok) printf("PASS: realloc_grow\n");
        else { printf("FAIL: realloc_grow\n"); failed = 1; }
    }

    // realloc shrink
    {
        int *p = malloc(10 * sizeof(int));
        for (int i = 0; i < 10; i++) p[i] = i;
        p = realloc(p, 3 * sizeof(int));
        if (!p) { printf("FAIL: realloc_shrink: alloc\n"); return 1; }
        int ok = 1;
        for (int i = 0; i < 3; i++) {
            if (p[i] != i) { ok = 0; break; }
        }
        free(p);
        if (ok) printf("PASS: realloc_shrink\n");
        else { printf("FAIL: realloc_shrink\n"); failed = 1; }
    }

    // calloc zeroing
    {
        int *p = calloc(10, sizeof(int));
        if (!p) { printf("FAIL: calloc_zero: alloc\n"); return 1; }
        int ok = 1;
        for (int i = 0; i < 10; i++) {
            if (p[i] != 0) { ok = 0; break; }
        }
        free(p);
        if (ok) printf("PASS: calloc_zero\n");
        else { printf("FAIL: calloc_zero\n"); failed = 1; }
    }

    // Large allocation + memset + verify
    {
        size_t size = 1024 * 1024;  // 1MB
        char *p = malloc(size);
        if (!p) { printf("FAIL: large_alloc: alloc\n"); return 1; }
        memset(p, 0x55, size);
        int ok = 1;
        // Check a few spots
        if ((unsigned char)p[0] != 0x55) ok = 0;
        if ((unsigned char)p[size/2] != 0x55) ok = 0;
        if ((unsigned char)p[size-1] != 0x55) ok = 0;
        free(p);
        if (ok) printf("PASS: large_alloc\n");
        else { printf("FAIL: large_alloc\n"); failed = 1; }
    }

    return failed;
}
