#include <stdio.h>
#include <time.h>

int main(int argc, char *argv[])
{
	for (int i = 0; i < 3; i++) {
		printf("time = %ld\n", time(0));
	}
	return 0;	
}
