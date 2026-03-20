// CHECK: PASS: sysinfo

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

int main(void) {
	struct sysinfo si;
	long ret = syscall(SYS_sysinfo, &si);
	if (ret == 0 && si.totalram > 0) {
		printf("PASS: sysinfo\n");
	} else {
		printf("FAIL: sysinfo\n");
		return 1;
	}
	return 0;
}
