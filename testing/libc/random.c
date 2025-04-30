// CHECK: rand = 834647657
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[])
{
	srand(time(0));
	printf("rand = %d\n", rand());
	return 0;	
}
