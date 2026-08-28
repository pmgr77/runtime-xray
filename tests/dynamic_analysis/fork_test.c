#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        // Child: do a few syscalls
        printf("Child: PID=%d\n", getpid());
        sleep(1);
        return 0;
    } else {
        // Parent: wait for child
        printf("Parent: PID=%d, child=%d\n", getpid(), pid);
        wait(NULL);
        return 0;
    }
}