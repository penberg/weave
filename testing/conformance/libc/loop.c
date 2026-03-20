// CHECK: 0
// CHECK: 1
// CHECK: 2
// CHECK: 3
// CHECK: 4
// CHECK: 5
// CHECK: 6
// CHECK: 7
// CHECK: 8
// CHECK: 9
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[])
{
	int i;

	for (i = 0; i < 10; i++) {
		printf("%d\n", i);
	}

	return 0;	
}
