// CHECK: sprintf: Hello 42
// CHECK: snprintf: Hello
// CHECK: sscanf: 123 456
// CHECK: fprintf: ok
// CHECK: fmt_d: -42
// CHECK: fmt_u: 42
// CHECK: fmt_x: 2a
// CHECK: fmt_o: 52
// CHECK: fmt_c: A
// CHECK: fmt_s: hello
// CHECK: fmt_ld: 1234567890
// CHECK: fmt_f: 3.140000
// CHECK: fmt_e: 3.140000e+00
// CHECK: fmt_g: 3.14
// CHECK: fmt_pct: 100%

#include <stdio.h>
#include <string.h>

int main(void) {
    // sprintf
    {
        char buf[64];
        sprintf(buf, "Hello %d", 42);
        printf("sprintf: %s\n", buf);
    }

    // snprintf (truncation)
    {
        char buf[6];
        snprintf(buf, 6, "Hello World");
        printf("snprintf: %s\n", buf);
    }

    // sscanf
    {
        int a, b;
        sscanf("123 456", "%d %d", &a, &b);
        printf("sscanf: %d %d\n", a, b);
    }

    // fprintf to stdout
    {
        fprintf(stdout, "fprintf: ok\n");
    }

    // Various format specifiers
    printf("fmt_d: %d\n", -42);
    printf("fmt_u: %u\n", 42);
    printf("fmt_x: %x\n", 42);
    printf("fmt_o: %o\n", 42);
    printf("fmt_c: %c\n", 'A');
    printf("fmt_s: %s\n", "hello");
    printf("fmt_ld: %ld\n", 1234567890L);
    printf("fmt_f: %f\n", 3.14);
    printf("fmt_e: %e\n", 3.14);
    printf("fmt_g: %g\n", 3.14);
    printf("fmt_pct: 100%%\n");

    return 0;
}
