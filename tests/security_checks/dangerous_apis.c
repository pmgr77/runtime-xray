/**
 * @file    dangerous_apis.c
 * @brief   Test target that imports dangerous APIs for detection.
 *
 * @author  Peter Magram
 * @date    2026-08-16
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

/* Copyright 2026 Peter Magram
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

// Weak crypto (OpenSSL functions) – will be imported if linked with -lcrypto
// For this example we don't link, so they won't appear. We'll use functions
// available in libc instead, but we can also add weak crypto later.

// Just reference these functions so they appear in the symbol table
void reference_dangerous_apis(void) {
    // Unsafe string functions
    char buf[16];
    strcpy(buf, "test");
    strcat(buf, "!");
    sprintf(buf, "%s", "hello");

    // Command execution
    system("true");
    FILE* p = popen("ls", "r");
    if (p) pclose(p);

    // Weak randomness
    srand(42);
    int r = rand();

    // Insecure temporary file
    char templ[] = "/tmp/tmpXXXXXX";
    int fd = mkstemp(templ);  // safe, but we want mktemp
    char templ2[] = "/tmp/tmpXXXXXX";
    char* tmp = mktemp(templ2);

    // Network functions
    struct hostent* he = gethostbyname("localhost");
    if (he == NULL) {
        return;
    }
    char* ip = inet_ntoa(*(struct in_addr*)he->h_addr);

    // Privilege functions
    setuid(0);
    chroot("/");
    fork();

    // Avoid warnings
    (void)buf; (void)r; (void)fd; (void)tmp; (void)ip;
}

int main(void) {
    reference_dangerous_apis();
    return 0;
}