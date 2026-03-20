// CHECK: PASS: goto_state_machine
// CHECK: PASS: nested_if_else
// CHECK: PASS: ternary_chain
// CHECK: PASS: short_circuit
// CHECK: PASS: multi_return

#include <stdio.h>

__attribute__((noinline))
int state_machine(int input) {
    int state = 0;
    int result = 0;
    const char *data = "abcxyz";
    int i = 0;

state_A:
    if (data[i] == '\0') goto done;
    if (data[i] >= 'a' && data[i] <= 'c') { result += 1; i++; goto state_B; }
    i++; goto state_A;

state_B:
    if (data[i] == '\0') goto done;
    if (data[i] >= 'x' && data[i] <= 'z') { result += 10; i++; goto state_A; }
    i++; goto state_B;

done:
    return result;
}

__attribute__((noinline))
int nested_if(int a, int b, int c, int d, int e) {
    if (a > 0) {
        if (b > 0) {
            if (c > 0) {
                if (d > 0) {
                    if (e > 0) return 1;
                    else return 2;
                } else return 3;
            } else return 4;
        } else return 5;
    } else return 6;
}

__attribute__((noinline))
int ternary_chain_fn(int x) {
    return x > 100 ? 5 :
           x > 50  ? 4 :
           x > 20  ? 3 :
           x > 10  ? 2 :
           x > 0   ? 1 : 0;
}

static int call_count;

__attribute__((noinline))
int side_effect_true(void) {
    call_count++;
    return 1;
}

__attribute__((noinline))
int side_effect_false(void) {
    call_count++;
    return 0;
}

__attribute__((noinline))
int multi_return_fn(int x) {
    if (x < 0) return -1;
    if (x == 0) return 0;
    if (x < 10) return 1;
    if (x < 100) return 2;
    if (x < 1000) return 3;
    return 4;
}

int main(void) {
    int failed = 0;

    // goto state machine: processes "abcxyz"
    // a->state_B(+1), b->state_B(stays), c->state_B(stays)...
    // Actually let me trace: start at state_A, i=0
    // i=0: 'a' is a-c, result+=1(=1), i=1, goto state_B
    // i=1: 'b' is not x-z, i=2, goto state_B
    // i=2: 'c' is not x-z, i=3, goto state_B
    // i=3: 'x' is x-z, result+=10(=11), i=4, goto state_A
    // i=4: 'y' is not a-c, i=5, goto state_A
    // i=5: 'z' is not a-c, i=6, goto state_A
    // i=6: '\0', goto done. result = 11
    {
        int r = state_machine(0);
        if (r == 11) printf("PASS: goto_state_machine\n");
        else { printf("FAIL: goto_state_machine: got %d\n", r); failed = 1; }
    }

    // nested_if_else
    {
        if (nested_if(1,1,1,1,1) == 1 && nested_if(1,1,1,1,-1) == 2 &&
            nested_if(1,1,1,-1,0) == 3 && nested_if(1,1,-1,0,0) == 4 &&
            nested_if(1,-1,0,0,0) == 5 && nested_if(-1,0,0,0,0) == 6) {
            printf("PASS: nested_if_else\n");
        } else { printf("FAIL: nested_if_else\n"); failed = 1; }
    }

    // ternary_chain
    {
        if (ternary_chain_fn(200) == 5 && ternary_chain_fn(75) == 4 &&
            ternary_chain_fn(30) == 3 && ternary_chain_fn(15) == 2 &&
            ternary_chain_fn(5) == 1 && ternary_chain_fn(-1) == 0) {
            printf("PASS: ternary_chain\n");
        } else { printf("FAIL: ternary_chain\n"); failed = 1; }
    }

    // short_circuit: && should not evaluate RHS if LHS is false
    {
        call_count = 0;
        int r1 = side_effect_false() && side_effect_true();
        int c1 = call_count; // should be 1 (only false called)

        call_count = 0;
        int r2 = side_effect_true() || side_effect_false();
        int c2 = call_count; // should be 1 (only true called)

        if (r1 == 0 && c1 == 1 && r2 == 1 && c2 == 1) {
            printf("PASS: short_circuit\n");
        } else { printf("FAIL: short_circuit\n"); failed = 1; }
    }

    // multi_return
    {
        if (multi_return_fn(-5) == -1 && multi_return_fn(0) == 0 &&
            multi_return_fn(5) == 1 && multi_return_fn(50) == 2 &&
            multi_return_fn(500) == 3 && multi_return_fn(5000) == 4) {
            printf("PASS: multi_return\n");
        } else { printf("FAIL: multi_return\n"); failed = 1; }
    }

    return failed;
}
