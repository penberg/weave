// Regression test for R_X86_64_TPOFF64 relocation support.
// libm.so.6 uses TPOFF64 for the errno TLS variable. Without TPOFF64
// support, loading libm fails with "Unsupported relocation type: 18".
// This test verifies that libm loads and math functions work correctly.
//
// CHECK: sqrt(2.0) = 1.414214
// CHECK: pow(2.0, 10.0) = 1024.000000

#include <math.h>
#include <stdio.h>

int main(void) {
	printf("sqrt(2.0) = %f\n", sqrt(2.0));
	printf("pow(2.0, 10.0) = %f\n", pow(2.0, 10.0));
	return 0;
}
