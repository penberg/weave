#include <dlfcn.h>
#include <stdio.h>

int main() {
    void* ptr1 = dlsym(RTLD_DEFAULT, "_CFRelease");
    void* ptr2 = dlsym(RTLD_DEFAULT, "CFRelease");
    printf("_CFRelease: %p\n", ptr1);
    printf("CFRelease: %p\n", ptr2);

    // Try loading CoreFoundation explicitly
    void* cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    printf("CoreFoundation handle: %p\n", cf);
    if (cf) {
        void* ptr3 = dlsym(cf, "CFRelease");
        printf("CFRelease from CF: %p\n", ptr3);
    }
    return 0;
}
