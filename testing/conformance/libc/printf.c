// CHECK: literal n=13 |Hello, world!|
// CHECK: signed n=6 |-42 17|
// CHECK: bases n=16 |42 0x2a 0X2A 052|
// CHECK: width_lr n=17 ||   123| |123   ||
// CHECK: zero_pad n=13 |000123 -00123|
// CHECK: sign_flags n=8 |+7 -7  7|
// CHECK: int_precision n=16 ||00012| |000| |||
// CHECK: dynamic_wp n=10 ||    0023||
// CHECK: dynamic_neg_w n=8 ||42    ||
// CHECK: str_wp n=23 ||      conf| |pri     ||
// CHECK: str_dynamic n=8 ||abc| |||
// CHECK: char_pct n=7 |A %   Z|
// CHECK: len_signed n=34 |32000 120 1234567890 1234567890123|
// CHECK: len_unsigned n=41 |65000 250 4000000000 18446744073709551615|
// CHECK: trunc_small n=6 |abcd|
// CHECK: trunc_tiny n=3 ||
// CHECK: percent_n n=6 written=3 |abcXYZ|
// CHECK: null_size n=9
// CHECK: printf_direct: 7 ok
// CHECK: printf_direct_ret n=20

#include <stdarg.h>
#include <stdio.h>

static void run_case(const char *name, const char *fmt, ...)
{
    char buf[128];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    printf("%s n=%d |%s|\n", name, n, buf);
}

int main(void)
{
    char small[5];
    char tiny[1];
    char buf[128];
    int n;
    int written;
    int direct_n;

    run_case("literal", "Hello, world!");
    run_case("signed", "%d %i", -42, 17);
    run_case("bases", "%u %#x %#X %#o", 42u, 42u, 42u, 42u);
    run_case("width_lr", "|%6d| |%-6d|", 123, 123);
    run_case("zero_pad", "%06d %06d", 123, -123);
    run_case("sign_flags", "%+d %+d % d", 7, -7, 7);
    run_case("int_precision", "|%.5d| |%.3d| |%.0d|", 12, 0, 0);
    run_case("dynamic_wp", "|%*.*d|", 8, 4, 23);
    run_case("dynamic_neg_w", "|%*d|", -6, 42);
    run_case("str_wp", "|%10.4s| |%-8.3s|", "conformance", "printf");
    run_case("str_dynamic", "|%.*s| |%.*s|", 3, "abcdef", 0, "abcdef");
    run_case("char_pct", "%c %% %3c", 'A', 'Z');
    run_case("len_signed", "%hd %hhd %ld %lld",
             (short)32000, (signed char)120, 1234567890L, 1234567890123LL);
    run_case("len_unsigned", "%hu %hhu %lu %llu",
             (unsigned short)65000, (unsigned char)250,
             4000000000UL, 18446744073709551615ULL);

    n = snprintf(small, sizeof(small), "abcdef");
    printf("trunc_small n=%d |%s|\n", n, small);

    n = snprintf(tiny, sizeof(tiny), "xyz");
    printf("trunc_tiny n=%d |%s|\n", n, tiny);

    written = -1;
    n = snprintf(buf, sizeof(buf), "abc%nXYZ", &written);
    printf("percent_n n=%d written=%d |%s|\n", n, written, buf);

    n = snprintf(NULL, 0, "value=%d", 123);
    printf("null_size n=%d\n", n);

    direct_n = printf("printf_direct: %d %s\n", 7, "ok");
    printf("printf_direct_ret n=%d\n", direct_n);

    return 0;
}
