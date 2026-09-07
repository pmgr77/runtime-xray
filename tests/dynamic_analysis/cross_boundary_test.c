#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    const char *secret = (argc > 1) ? argv[1] : "default";
    // Print the exact secret without extra text or punctuation
    printf("%s\n", secret);          // prints "password=secret123"
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0) {
        // Child: use the same secret
        char *mem_secret = strdup(secret);
        // Also print it so we get a write syscall with same fingerprint
        printf("%s\n", mem_secret);
        fflush(stdout);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(12345);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            connect(sock, (struct sockaddr*)&addr, sizeof(addr));
            send(sock, mem_secret, strlen(mem_secret), 0);
            close(sock);
        }
        free(mem_secret);
        return 0;
    } else {
        wait(NULL);
        return 0;
    }
}