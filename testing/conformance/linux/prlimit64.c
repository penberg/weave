// CHECK: PASS: prlimit64

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>

int main(void) {
	struct rlimit rl;
	long ret = syscall(SYS_prlimit64, 0, RLIMIT_STACK, NULL, &rl);
	if (ret == 0 && rl.rlim_cur > 0) {
		printf("PASS: prlimit64\n");
	} else {
		printf("FAIL: prlimit64\n");
		return 1;
	}
	return 0;
}
