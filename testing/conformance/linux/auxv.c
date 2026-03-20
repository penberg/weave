// CHECK: PASS: auxv

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/auxv.h>
#include <unistd.h>

int main(void) {
	unsigned long page_size = getauxval(AT_PAGESZ);
	unsigned long entry = getauxval(AT_ENTRY);
	unsigned long random = getauxval(AT_RANDOM);

	if (page_size == (unsigned long)getpagesize() && entry != 0 && random != 0) {
		printf("PASS: auxv\n");
		return 0;
	}

	printf("FAIL: auxv pagesz=%lu entry=%lu random=%lu\n", page_size, entry, random);
	return 1;
}
