// Regression test: DT_NEEDED libraries must be loaded for symbol resolution.
// Links against libz (not in the hardcoded libc/libm/libpthread list),
// verifying that load_executable() opens all DT_NEEDED dependencies.
// CHECK: zlibVersion: ok
// CHECK: done

#include <stdio.h>
#include <zlib.h>

int main(void) {
    const char *ver = zlibVersion();
    if (ver) {
        printf("zlibVersion: ok\n");
    } else {
        printf("zlibVersion: failed\n");
    }
    printf("done\n");
    return 0;
}
