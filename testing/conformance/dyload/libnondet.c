// A library that performs non-deterministic operations.
// When run under Weave, these should be intercepted and made deterministic.

#include <stdlib.h>
#include <time.h>

// Returns a "random" number - non-deterministic without Weave
int nondet_rand(void) {
    return rand();
}

// Returns current time - non-deterministic without Weave
long nondet_time(void) {
    return time(NULL);
}

// Calls rand() multiple times and returns the sum
int nondet_rand_sum(int count) {
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += rand();
    }
    return sum;
}
