#include <stdio.h>
#include <math.h>

int main() {
    double x = 0.5;

    printf("acos(%f) = %f\n", x, acos(x));
    printf("asin(%f) = %f\n", x, asin(x));
    printf("atan(%f) = %f\n", x, atan(x));
    printf("cos(%f) = %f\n", x, cos(x));
    printf("sin(%f) = %f\n", x, sin(x));
    printf("tan(%f) = %f\n", x, tan(x));
    printf("exp(%f) = %f\n", x, exp(x));
    printf("sqrt(%f) = %f\n", x, sqrt(x));
    printf("pow(%f, 2) = %f\n", x, pow(x, 2.0));

    return 0;
}
