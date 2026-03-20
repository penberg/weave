#include <pthread.h>
#include <stdio.h>

static void *thread_func(void *arg) {
    int num = *(int *)arg;
    printf("Hello from thread %d\n", num);
    return NULL;
}

int main(void) {
    pthread_t thread;
    int arg = 42;

    if (pthread_create(&thread, NULL, thread_func, &arg) != 0) {
        printf("Failed to create thread\n");
        return 1;
    }

    if (pthread_join(thread, NULL) != 0) {
        printf("Failed to join thread\n");
        return 1;
    }

    printf("Thread completed successfully\n");
    return 0;
}
