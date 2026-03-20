// CHECK: PASS: small_switch
// CHECK: PASS: large_switch
// CHECK: PASS: char_switch
// CHECK: PASS: negative_switch
// CHECK: PASS: default_switch
// CHECK: PASS: nested_switch
// CHECK: PASS: fallthrough_switch

#include <stdio.h>

__attribute__((noinline))
int small_switch(int x) {
    switch (x) {
        case 1: return 10;
        case 2: return 20;
        case 3: return 30;
        default: return -1;
    }
}

__attribute__((noinline))
int large_switch(int x) {
    switch (x) {
        case 0: return 100;
        case 1: return 101;
        case 2: return 102;
        case 3: return 103;
        case 4: return 104;
        case 5: return 105;
        case 6: return 106;
        case 7: return 107;
        case 8: return 108;
        case 9: return 109;
        case 10: return 110;
        case 11: return 111;
        default: return -1;
    }
}

__attribute__((noinline))
int char_switch(char c) {
    switch (c) {
        case 'a': return 1;
        case 'b': return 2;
        case 'z': return 26;
        default: return 0;
    }
}

__attribute__((noinline))
int negative_switch(int x) {
    switch (x) {
        case -3: return 30;
        case -2: return 20;
        case -1: return 10;
        case 0: return 0;
        case 1: return -10;
        default: return 99;
    }
}

__attribute__((noinline))
int nested_switch(int a, int b) {
    switch (a) {
        case 1:
            switch (b) {
                case 10: return 110;
                case 20: return 120;
                default: return 100;
            }
        case 2:
            switch (b) {
                case 10: return 210;
                case 20: return 220;
                default: return 200;
            }
        default: return -1;
    }
}

__attribute__((noinline))
int fallthrough_switch(int x) {
    int result = 0;
    switch (x) {
        case 3: result += 100;
            /* fallthrough */
        case 2: result += 10;
            /* fallthrough */
        case 1: result += 1;
            break;
        default: result = -1;
    }
    return result;
}

int main(void) {
    int failed = 0;

    // small_switch
    if (small_switch(1) == 10 && small_switch(2) == 20 && small_switch(3) == 30 && small_switch(99) == -1) {
        printf("PASS: small_switch\n");
    } else {
        printf("FAIL: small_switch\n");
        failed = 1;
    }

    // large_switch (likely generates jump table at -O2)
    {
        int ok = 1;
        for (int i = 0; i <= 11; i++) {
            if (large_switch(i) != 100 + i) { ok = 0; break; }
        }
        if (ok && large_switch(99) == -1) {
            printf("PASS: large_switch\n");
        } else {
            printf("FAIL: large_switch\n");
            failed = 1;
        }
    }

    // char_switch
    if (char_switch('a') == 1 && char_switch('b') == 2 && char_switch('z') == 26 && char_switch('x') == 0) {
        printf("PASS: char_switch\n");
    } else {
        printf("FAIL: char_switch\n");
        failed = 1;
    }

    // negative_switch
    if (negative_switch(-3) == 30 && negative_switch(-1) == 10 && negative_switch(0) == 0 && negative_switch(1) == -10) {
        printf("PASS: negative_switch\n");
    } else {
        printf("FAIL: negative_switch\n");
        failed = 1;
    }

    // default_switch
    if (small_switch(999) == -1 && large_switch(-1) == -1 && negative_switch(100) == 99) {
        printf("PASS: default_switch\n");
    } else {
        printf("FAIL: default_switch\n");
        failed = 1;
    }

    // nested_switch
    if (nested_switch(1, 10) == 110 && nested_switch(1, 20) == 120 && nested_switch(2, 10) == 210 && nested_switch(2, 20) == 220 && nested_switch(3, 10) == -1) {
        printf("PASS: nested_switch\n");
    } else {
        printf("FAIL: nested_switch\n");
        failed = 1;
    }

    // fallthrough_switch
    if (fallthrough_switch(1) == 1 && fallthrough_switch(2) == 11 && fallthrough_switch(3) == 111 && fallthrough_switch(99) == -1) {
        printf("PASS: fallthrough_switch\n");
    } else {
        printf("FAIL: fallthrough_switch\n");
        failed = 1;
    }

    return failed;
}
