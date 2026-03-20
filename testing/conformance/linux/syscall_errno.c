// CHECK: PASS: syscall_errno

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
	errno = 0;
	long ret = syscall(SYS_prctl, 0xdeadbeefUL, 0, 0, 0, 0);
	if (ret == -1 && errno == EINVAL) {
		printf("PASS: syscall_errno\n");
		return 0;
	}

	printf("FAIL: syscall_errno ret=%ld errno=%d\n", ret, errno);
	return 1;
}
