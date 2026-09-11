/*
 * Target for tests/test_sensitive_object_flow.sh
 *
 * Reads a known credential from a file, keeps a resident copy in the heap,
 * sends the same bytes over a loopback TCP socket, then sleeps so the
 * during-trace memory scan has a window to observe the secret while the
 * process is still alive.
 *
 * Usage: sensitive_object_flow <cred_file> <host> <port>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <cred_file> <host> <port>\n", argv[0]);
        return 2;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 3;
    }

    char buf[512] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        perror("read");
        return 4;
    }

    /* Second copy resident in the heap so the memory scanner finds it
       independently of the read buffer. */
    char* resident = malloc((size_t)n + 1);
    memcpy(resident, buf, (size_t)n);
    resident[n] = '\0';

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 5;
    }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)atoi(argv[3]));
    inet_pton(AF_INET, argv[2], &sa.sin_addr);

    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect"); return 6;
    }

    if (send(s, resident, (size_t)n, 0) < 0) {
        perror("send");
        return 7;
    }

    sleep(3);           /* window for the during-trace memory scan */
    close(s);
    free(resident);
    return 0;
}