// CHECK: strstr: world
// CHECK: strchr: ello
// CHECK: strrchr: ld
// CHECK: strtol: 255
// CHECK: strtol_neg: -42
// CHECK: strtol_hex: 255
// CHECK: atoi: 12345
// CHECK: atoi_neg: -678
// CHECK: toupper: HELLO
// CHECK: tolower: hello
// CHECK: isdigit: yes
// CHECK: isalpha: yes

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

int main(void) {
    // strstr
    {
        const char *s = strstr("hello world", "world");
        printf("strstr: %s\n", s ? s : "NULL");
    }

    // strchr
    {
        const char *s = strchr("hello", 'e');
        printf("strchr: %s\n", s ? s : "NULL");
    }

    // strrchr
    {
        const char *s = strrchr("hello world", 'l');
        printf("strrchr: %s\n", s ? s : "NULL");
    }

    // strtol
    {
        long v = strtol("255", NULL, 10);
        printf("strtol: %ld\n", v);
    }

    // strtol negative
    {
        long v = strtol("-42", NULL, 10);
        printf("strtol_neg: %ld\n", v);
    }

    // strtol hex
    {
        long v = strtol("0xFF", NULL, 16);
        printf("strtol_hex: %ld\n", v);
    }

    // atoi
    {
        int v = atoi("12345");
        printf("atoi: %d\n", v);
    }

    // atoi negative
    {
        int v = atoi("-678");
        printf("atoi_neg: %d\n", v);
    }

    // toupper
    {
        const char *src = "hello";
        char buf[16];
        for (int i = 0; src[i]; i++)
            buf[i] = toupper((unsigned char)src[i]);
        buf[5] = '\0';
        printf("toupper: %s\n", buf);
    }

    // tolower
    {
        const char *src = "HELLO";
        char buf[16];
        for (int i = 0; src[i]; i++)
            buf[i] = tolower((unsigned char)src[i]);
        buf[5] = '\0';
        printf("tolower: %s\n", buf);
    }

    // isdigit
    {
        if (isdigit('5') && !isdigit('a'))
            printf("isdigit: yes\n");
        else
            printf("isdigit: no\n");
    }

    // isalpha
    {
        if (isalpha('A') && isalpha('z') && !isalpha('5'))
            printf("isalpha: yes\n");
        else
            printf("isalpha: no\n");
    }

    return 0;
}
