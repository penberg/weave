// CHECK: PASS: sched_yield

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
	long ret = syscall(SYS_sched_yield);
	if (ret == 0) {
		printf("PASS: sched_yield\n");
	} else {
		printf("FAIL: sched_yield\n");
		return 1;
	}
	return 0;
}
