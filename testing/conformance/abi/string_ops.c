// CHECK: PASS: strlen_test
// CHECK: PASS: strcmp_test
// CHECK: PASS: strcpy_test
// CHECK: PASS: memcpy_test
// CHECK: PASS: memset_test
// CHECK: PASS: memmove_test
// CHECK: PASS: strncmp_test

#include <stdio.h>
#include <string.h>

int main(void) {
    int failed = 0;

    // strlen
    {
        if (strlen("") == 0 && strlen("hello") == 5 && strlen("hello world") == 11) {
            printf("PASS: strlen_test\n");
        } else { printf("FAIL: strlen_test\n"); failed = 1; }
    }

    // strcmp
    {
        if (strcmp("abc", "abc") == 0 && strcmp("abc", "abd") < 0 && strcmp("abd", "abc") > 0 && strcmp("", "") == 0) {
            printf("PASS: strcmp_test\n");
        } else { printf("FAIL: strcmp_test\n"); failed = 1; }
    }

    // strcpy
    {
        char buf[32];
        strcpy(buf, "hello world");
        if (strcmp(buf, "hello world") == 0) {
            printf("PASS: strcpy_test\n");
        } else { printf("FAIL: strcpy_test\n"); failed = 1; }
    }

    // memcpy
    {
        char src[] = "ABCDEFGHIJ";
        char dst[16] = {0};
        memcpy(dst, src, 10);
        if (memcmp(dst, src, 10) == 0) {
            printf("PASS: memcpy_test\n");
        } else { printf("FAIL: memcpy_test\n"); failed = 1; }
    }

    // memset
    {
        char buf[16];
        memset(buf, 0xAA, 16);
        int ok = 1;
        for (int i = 0; i < 16; i++) {
            if ((unsigned char)buf[i] != 0xAA) { ok = 0; break; }
        }
        if (ok) printf("PASS: memset_test\n");
        else { printf("FAIL: memset_test\n"); failed = 1; }
    }

    // memmove (overlapping)
    {
        char buf[32] = "0123456789";
        memmove(buf + 2, buf, 8);  // "01012345679"
        if (buf[0] == '0' && buf[1] == '1' && buf[2] == '0' && buf[3] == '1' && buf[4] == '2') {
            printf("PASS: memmove_test\n");
        } else { printf("FAIL: memmove_test\n"); failed = 1; }
    }

    // strncmp
    {
        if (strncmp("hello", "hello world", 5) == 0 && strncmp("abc", "abd", 2) == 0 && strncmp("abc", "abd", 3) < 0) {
            printf("PASS: strncmp_test\n");
        } else { printf("FAIL: strncmp_test\n"); failed = 1; }
    }

    return failed;
}
