#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

void* thread_func(void* arg) {
    if (arg) {}
    // Do a syscall that is easy to spot
    pid_t tid = (pid_t)syscall(SYS_gettid);
    printf("Thread TID=%d\n", tid);
    return NULL;
}

int main() {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_func, NULL);
    pthread_join(thread, NULL);
    return 0;
}