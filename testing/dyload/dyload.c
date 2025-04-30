// Test program that dynamically loads libnondet and calls its functions.
// Under Weave, the non-deterministic functions should return deterministic values.
// CHECK: rand1: 834647657
// CHECK: rand2: 1836479301
// CHECK: time1: 2246484890
// CHECK: time2: 2246484890
// CHECK: rand_sum(5): 867969853

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef int (*rand_fn)(void);
typedef long (*time_fn)(void);
typedef int (*rand_sum_fn)(int);

int main(int argc, char *argv[]) {
    const char *lib_path = argc > 1 ? argv[1] : "./libnondet.dylib";

    void *handle = dlopen(lib_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    rand_fn nondet_rand = (rand_fn)dlsym(handle, "nondet_rand");
    time_fn nondet_time = (time_fn)dlsym(handle, "nondet_time");
    rand_sum_fn nondet_rand_sum = (rand_sum_fn)dlsym(handle, "nondet_rand_sum");

    if (!nondet_rand || !nondet_time || !nondet_rand_sum) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    // Call the functions multiple times - under Weave these should be deterministic
    printf("rand1: %d\n", nondet_rand());
    printf("rand2: %d\n", nondet_rand());
    printf("time1: %ld\n", nondet_time());
    printf("time2: %ld\n", nondet_time());
    printf("rand_sum(5): %d\n", nondet_rand_sum(5));

    dlclose(handle);
    return 0;
}
