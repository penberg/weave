// CHECK: PASS: ifunc
/*
 * Regression test for IFUNC (R_X86_64_IRELATIVE) relocation support.
 *
 * Dynamically linked binaries that load glibc trigger IFUNC relocations
 * for optimized function dispatch (e.g., memcpy, strlen). The supervisor
 * must set up an execution context and temporary stack before performing
 * relocations so that IFUNC resolvers can be called via translate_and_call.
 *
 * This test verifies that a dynamically linked binary with common libc
 * functions (which glibc implements via IFUNC) loads and runs correctly.
 */

#include <stdio.h>
#include <string.h>

int main(void) {
	/* These libc functions are typically IFUNC-resolved in glibc */
	const char *s = "hello";
	char buf[16];
	memcpy(buf, s, strlen(s) + 1);
	if (strcmp(buf, s) == 0) {
		printf("PASS: ifunc\n");
	} else {
		printf("FAIL: ifunc\n");
		return 1;
	}
	return 0;
}
