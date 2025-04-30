#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

int main() {
    CFStringRef str = CFStringCreateWithCString(NULL, "Hello from CoreFoundation", kCFStringEncodingUTF8);
    if (str) {
        printf("Created CFString: %p\n", (void*)str);
        CFRelease(str);
        printf("Released CFString\n");
    } else {
        printf("Failed to create CFString\n");
    }
    return 0;
}
