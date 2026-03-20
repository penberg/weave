#include <stdio.h>
#include <math.h>

int main(int argc, char *argv[])
{
	// Test various math functions from libm
	double x = 2.0;
	double y = 3.0;

	printf("sqrt(%.1f) = %.6f\n", x, sqrt(x));
	printf("sin(%.1f) = %.6f\n", x, sin(x));
	printf("cos(%.1f) = %.6f\n", x, cos(x));
	printf("pow(%.1f, %.1f) = %.6f\n", x, y, pow(x, y));
	printf("log10(%.1f) = %.6f\n", x, log10(x));
	printf("atan2(%.1f, %.1f) = %.6f\n", y, x, atan2(y, x));

	return 0;
}
