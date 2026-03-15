// CHECK: PASS: set_tid_address

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
	int tid_ptr = 0;
	long tid = syscall(SYS_set_tid_address, &tid_ptr);
	if (tid > 0) {
		printf("PASS: set_tid_address\n");
	} else {
		printf("FAIL: set_tid_address\n");
		return 1;
	}
	return 0;
}
