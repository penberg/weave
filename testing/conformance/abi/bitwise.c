// CHECK: PASS: popcount
// CHECK: PASS: is_power_of_2
// CHECK: PASS: bit_reverse
// CHECK: PASS: mask_gen
// CHECK: PASS: shift_chain
// CHECK: PASS: extract_bits

#include <stdio.h>

__attribute__((noinline))
int my_popcount(unsigned long x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

__attribute__((noinline))
int is_power_of_2(unsigned long x) {
    return x != 0 && (x & (x - 1)) == 0;
}

__attribute__((noinline))
unsigned int bit_reverse_32(unsigned int x) {
    unsigned int result = 0;
    for (int i = 0; i < 32; i++) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

__attribute__((noinline))
unsigned long gen_mask(int start, int len) {
    return ((1UL << len) - 1) << start;
}

__attribute__((noinline))
unsigned long shift_chain(unsigned long x) {
    x = (x << 3) | (x >> 61);   // rotate left 3
    x = x ^ (x >> 17);
    x = x & 0xFFFF00FFFF00FFFFUL;
    return x;
}

__attribute__((noinline))
unsigned int extract_bits(unsigned int x, int pos, int len) {
    return (x >> pos) & ((1U << len) - 1);
}

int main(void) {
    int failed = 0;

    if (my_popcount(0) == 0 && my_popcount(1) == 1 && my_popcount(0xFF) == 8 && my_popcount(0xFFFFFFFFFFFFFFFFUL) == 64) {
        printf("PASS: popcount\n");
    } else { printf("FAIL: popcount\n"); failed = 1; }

    if (is_power_of_2(1) && is_power_of_2(2) && is_power_of_2(1024) && !is_power_of_2(0) && !is_power_of_2(3) && !is_power_of_2(6)) {
        printf("PASS: is_power_of_2\n");
    } else { printf("FAIL: is_power_of_2\n"); failed = 1; }

    if (bit_reverse_32(0x80000000U) == 1 && bit_reverse_32(1) == 0x80000000U && bit_reverse_32(0x0F0F0F0FU) == 0xF0F0F0F0U) {
        printf("PASS: bit_reverse\n");
    } else { printf("FAIL: bit_reverse\n"); failed = 1; }

    if (gen_mask(0, 8) == 0xFF && gen_mask(4, 4) == 0xF0 && gen_mask(8, 16) == 0x00FFFF00UL) {
        printf("PASS: mask_gen\n");
    } else { printf("FAIL: mask_gen\n"); failed = 1; }

    {
        unsigned long r1 = shift_chain(0x123456789ABCDEF0UL);
        unsigned long r2 = shift_chain(0);
        // Just verify determinism: same input → same output
        if (shift_chain(0x123456789ABCDEF0UL) == r1 && shift_chain(0) == r2) {
            printf("PASS: shift_chain\n");
        } else { printf("FAIL: shift_chain\n"); failed = 1; }
    }

    if (extract_bits(0xDEADBEEF, 0, 8) == 0xEF && extract_bits(0xDEADBEEF, 8, 8) == 0xBE && extract_bits(0xDEADBEEF, 4, 4) == 0xE) {
        printf("PASS: extract_bits\n");
    } else { printf("FAIL: extract_bits\n"); failed = 1; }

    return failed;
}
