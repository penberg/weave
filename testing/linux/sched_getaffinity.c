// CHECK: PASS: sched_getaffinity

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
	unsigned long mask[16] = {0};
	long ret = syscall(SYS_sched_getaffinity, 0, sizeof(mask), mask);
	if (ret > 0 && mask[0] != 0) {
		printf("PASS: sched_getaffinity\n");
	} else {
		printf("FAIL: sched_getaffinity\n");
		return 1;
	}
	return 0;
}
