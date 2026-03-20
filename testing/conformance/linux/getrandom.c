// CHECK: PASS: getrandom

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
	unsigned char buf[16] = {0};
	long ret = syscall(SYS_getrandom, buf, sizeof(buf), 0);
	if (ret == 16) {
		int nonzero = 0;
		for (int i = 0; i < 16; i++) {
			if (buf[i] != 0) nonzero++;
		}
		if (nonzero > 0) {
			printf("PASS: getrandom\n");
		} else {
			printf("FAIL: getrandom\n");
			return 1;
		}
	} else {
		printf("FAIL: getrandom\n");
		return 1;
	}
	return 0;
}
