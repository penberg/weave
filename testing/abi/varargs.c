#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>

// Helper to write int (avoid using printf)
void write_int(long val) {
    char buf[24];
    int len = 0;
    if (val == 0) {
        buf[len++] = '0';
    } else {
        char tmp[24];
        int i = 0;
        unsigned long v = (val < 0) ? -val : val;
        if (val < 0) {
            buf[len++] = '-';
        }
        while (v > 0) {
            tmp[i++] = '0' + (v % 10);
            v /= 10;
        }
        while (i > 0) buf[len++] = tmp[--i];
    }
    write(1, buf, len);
}

// Helper to write hex
void write_hex(unsigned long val) {
    char buf[20] = "0x";
    const char *hex = "0123456789abcdef";
    int len = 2;
    if (val == 0) {
        buf[len++] = '0';
    } else {
        char tmp[16];
        int i = 0;
        while (val > 0) {
            tmp[i++] = hex[val & 0xf];
            val >>= 4;
        }
        while (i > 0) buf[len++] = tmp[--i];
    }
    write(1, buf, len);
}

// Test 1: Simple va_arg in same function
void test1_simple(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    int val = va_arg(ap, int);
    va_end(ap);
    write(1, "test1: ", 7);
    write_int(val);
    write(1, "\n", 1);
}

// Test 2: Pass va_list to another function (like printf does)
void helper2(va_list ap) {
    int val = va_arg(ap, int);
    write(1, "test2: ", 7);
    write_int(val);
    write(1, "\n", 1);
}

void test2_pass_valist(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    helper2(ap);  // Pass va_list by value
    va_end(ap);
}

// Test 3: Pass pointer to va_list (how printf really works)
void helper3(va_list *ap) {
    int val = va_arg(*ap, int);
    write(1, "test3: ", 7);
    write_int(val);
    write(1, "\n", 1);
}

void test3_pass_valist_ptr(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    helper3(&ap);  // Pass pointer to va_list
    va_end(ap);
}

// Test 4: sprintf (test formatting without stdout complexity)
void test4_sprintf() {
    char buf[64];
    memset(buf, 'X', sizeof(buf));  // Fill with X to see what gets written
    int ret = sprintf(buf, "test4: %d", 42);
    // Show what was formatted
    write(1, "sprintf returned: ", 18);
    write_int(ret);
    write(1, ", result: [", 11);
    write(1, buf, strlen(buf));
    write(1, "]\n", 2);
}

// Test 4b: vsprintf to see va_list handling
void do_vsprintf(char *buf, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    // Show va_list and raw memory bytes
    write(1, "va_list=", 8);
    write_hex((unsigned long)ap);
    write(1, ", bytes: ", 9);
    unsigned char *bytes = (unsigned char*)ap;
    for (int i = 0; i < 16; i++) {
        write_hex(bytes[i]);
        write(1, " ", 1);
    }
    write(1, ", as_int=", 9);
    write_int(*(int*)ap);
    write(1, ", as_long=", 10);
    write_int(*(long*)ap);
    write(1, "\n", 1);
    vsprintf(buf, fmt, ap);
    va_end(ap);
}

void test4b_vsprintf() {
    char buf[64];
    do_vsprintf(buf, "test4b: %d", 42);
    write(1, "vsprintf result: [", 18);
    write(1, buf, strlen(buf));
    write(1, "]\n", 2);
}

// Test 4c: Mimic what vsprintf does internally (multiple nested function calls with va_list)
__attribute__((noinline))
int do_format_int(va_list *ap) {
    int val = va_arg(*ap, int);
    return val;
}

__attribute__((noinline))
void do_format(char *buf, const char *fmt, va_list ap) {
    // Mimic vsprintf: call another function to read va_arg
    int val = do_format_int(&ap);
    // Format manually
    char *p = buf;
    while (*fmt && *fmt != '%') *p++ = *fmt++;
    if (*fmt == '%') {
        fmt++; // skip %
        fmt++; // skip d
        // Convert val to string
        if (val == 0) {
            *p++ = '0';
        } else {
            char tmp[20];
            int i = 0;
            int v = val;
            while (v > 0) {
                tmp[i++] = '0' + (v % 10);
                v /= 10;
            }
            while (i > 0) *p++ = tmp[--i];
        }
    }
    *p = '\0';
}

void test4c_nested() {
    char buf[64];
    va_list ap;
    // Can't use va_start without a real varargs function, so use inline
    // We'll create a wrapper
}

// Wrapper to test nested va_list handling
void do_nested(char *buf, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    write(1, "test4c: before do_format, ap=", 29);
    write_hex((unsigned long)ap);
    write(1, ", [ap]=", 7);
    write_int(*(int*)ap);
    write(1, "\n", 1);
    do_format(buf, fmt, ap);
    va_end(ap);
}

void test4c() {
    char buf[64];
    do_nested(buf, "value: %d", 42);
    write(1, "test4c result: [", 16);
    write(1, buf, strlen(buf));
    write(1, "]\n", 2);
}

// Test 5: snprintf
void test5_snprintf() {
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "test5: %d", 42);
    write(1, buf, len);
    write(1, "\n", 1);
}

int main() {
    test1_simple("msg", 42);
    test2_pass_valist("msg", 42);
    test3_pass_valist_ptr("msg", 42);
    test4_sprintf();
    test4b_vsprintf();
    test4c();
    test5_snprintf();
    return 0;
}
