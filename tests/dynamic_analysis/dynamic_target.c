/**
 * @file    dynamic_target.c
 * @brief   Test binary that performs suspicious dynamic actions.
 *
 * @author  Peter Magram
 * @date    2026-08-20
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

// Copyright 2026 Peter Magram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    // 1. Sensitive file access
    // Critical: /etc/sudoers (exists in most systems, but open can fail; path is still traced)
    int fd_sudoers = open("/etc/sudoers", O_RDONLY);
    if (fd_sudoers >= 0) close(fd_sudoers);

    // Critical also: /etc/shadow (already present)
    int fd_shadow = open("/etc/shadow", O_RDONLY);
    if (fd_shadow >= 0) close(fd_shadow);

    // High: file with "secret" in path (no need to exist)
    int fd_secret = open("/tmp/fake_secret_file", O_RDONLY);
    if (fd_secret >= 0) close(fd_secret);

    // Medium: /etc/passwd (exists)
    int fd_passwd = open("/etc/passwd", O_RDONLY);
    if (fd_passwd >= 0) close(fd_passwd);

    // Low: /etc/hosts (exists)
    int fd_hosts = open("/etc/hosts", O_RDONLY);
    if (fd_hosts >= 0) close(fd_hosts);

    // Info: /etc/hostname (exists)
    int fd_hostname = open("/etc/hostname", O_RDONLY);
    if (fd_hostname >= 0) close(fd_hostname);

    // 2. Suspicious network connection (port 22 -> Medium)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(22);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
    }

    // 3. Write data containing secrets to stdout (High) (will be captured)
    const char* sensitive_data = "password=supersecret123\n";
    write(STDOUT_FILENO, sensitive_data, strlen(sensitive_data));

    // 4. Also print another secret-like line
    const char* api_data = "api_key=abcdef0123456789\n";
    write(STDOUT_FILENO, api_data, strlen(api_data));

    return 0;
}