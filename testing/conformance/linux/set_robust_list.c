// CHECK: PASS: set_robust_list

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
	struct {
		void *next;
		long futex_offset;
		void *pending;
	} head;
	memset(&head, 0, sizeof(head));
	head.next = &head;
	long ret = syscall(SYS_set_robust_list, &head, sizeof(head));
	if (ret == 0) {
		printf("PASS: set_robust_list\n");
	} else {
		printf("FAIL: set_robust_list\n");
		return 1;
	}
	return 0;
}
