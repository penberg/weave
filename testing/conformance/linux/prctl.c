// CHECK: PASS: prctl_name

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

int main(void) {
	const char *name = "weavetest";
	long ret = syscall(SYS_prctl, PR_SET_NAME, name, 0, 0, 0);
	if (ret == 0) {
		char buf[16] = {0};
		syscall(SYS_prctl, PR_GET_NAME, buf, 0, 0, 0);
		if (strcmp(buf, name) == 0) {
			printf("PASS: prctl_name\n");
		} else {
			printf("FAIL: prctl_name\n");
			return 1;
		}
	} else {
		printf("FAIL: prctl_name\n");
		return 1;
	}
	return 0;
}
