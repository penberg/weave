// CHECK: PASS: arch_prctl

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/prctl.h>

int main(void) {
	unsigned long fs_base = 0;
	long ret = syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base);
	if (ret == 0 && fs_base != 0) {
		printf("PASS: arch_prctl\n");
	} else {
		printf("FAIL: arch_prctl\n");
		return 1;
	}
	return 0;
}
