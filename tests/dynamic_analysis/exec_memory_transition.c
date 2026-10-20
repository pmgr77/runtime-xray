/**
 * @file    exec_memory_transition.c
 * @brief   Stage C.2 fixture: failed and successful execve process-image transitions.
 *
 * Copyright 2026 Peter Magram
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Run with RXRAY_EXEC_OLD=password=<32 alphanumeric characters> in the
 * environment. No credential is sent over a network or written to a file.
 *
 * Expected process behavior:
 *   - initial image: inherited old secret in environment and memory;
 *   - failed execve: remains in same process image, old secret intact;
 *   - successful execve("/proc/self/exe"): same TGID, new image;
 *   - replacement image: old environment absent, different secret present.
 *
 * The replacement secret is deterministically transformed from the old
 * value. No secret bytes or fingerprint are written to stdout/stderr.
 * The fixture verifies OS behavior; a separate RuntimeXRay test must
 * verify process_instance_id, exec_generation, and evidence attribution.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

enum { kPasswordLength = 32 };

static const char kPasswordPrefix[] = "password=";
static const char kOldEnvName[] = "RXRAY_EXEC_OLD";
static const char kNewEnvName[] = "RXRAY_EXEC_NEW";

static int valid_password(const char *value)
{
    if (value == NULL || strncmp(value, kPasswordPrefix,
                                 sizeof(kPasswordPrefix) - 1) != 0) {
        return 0;
    }

    const char *password = value + sizeof(kPasswordPrefix) - 1;
    if (strlen(password) != kPasswordLength) {
        return 0;
    }

    for (size_t i = 0; i < kPasswordLength; ++i) {
        const char ch = password[i];
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9'))) {
            return 0;
        }
    }
    return 1;
}

/* ROT13 for letters, ROT5 for digits: changes every password character. */
static char rotate_character(char ch)
{
    if (ch >= 'a' && ch <= 'z') {
        return (char)('a' + (ch - 'a' + 13) % 26);
    }
    if (ch >= 'A' && ch <= 'Z') {
        return (char)('A' + (ch - 'A' + 13) % 26);
    }
    return (char)('0' + (ch - '0' + 5) % 10);
}

static int after_exec(void)
{
    /* execve replaced the environment, not merely renamed the program. */
    if (getenv(kOldEnvName) != NULL) {
        fputs("FAIL: old environment survived successful execve\n", stderr);
        return 20;
    }

    const char *new_value = getenv(kNewEnvName);
    if (!valid_password(new_value)) {
        fputs("FAIL: replacement environment is missing or invalid\n", stderr);
        return 21;
    }

    /* Visible post-exec syscall; no read/write/sendto of the password. */
    if (syscall(SYS_getpid) <= 0) {
        fputs("FAIL: post-exec getpid syscall\n", stderr);
        return 22;
    }

    puts("PASS: failed exec preserved old image; successful exec replaced environment");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--after-exec") == 0) {
        return after_exec();
    }

    if (argc != 1) {
        fputs("Usage: exec_memory_transition [--after-exec]\n", stderr);
        return 2;
    }

    const char *old_value = getenv(kOldEnvName);
    if (!valid_password(old_value)) {
        fputs("FAIL: expected RXRAY_EXEC_OLD=password=<32 alphanumeric chars>\n",
              stderr);
        return 3;
    }

    /* A nonexistent /proc/self entry ensures execve fails with ENOENT. */
    char *const bad_argv[] = { (char *)"rxray-stage-c2-missing", NULL };
    errno = 0;
    if (execve("/proc/self/rxray-stage-c2-missing", bad_argv, environ) != -1 ||
        errno != ENOENT) {
        fputs("FAIL: expected ENOENT from deliberately invalid execve\n", stderr);
        return 4;
    }

    if (getenv(kOldEnvName) != old_value || !valid_password(old_value)) {
        fputs("FAIL: failed execve changed the original environment\n", stderr);
        return 5;
    }

    /* Visible syscall after failed exec; must still use generation zero. */
    if (syscall(SYS_getpid) <= 0) {
        fputs("FAIL: post-failure getpid syscall\n", stderr);
        return 6;
    }

    /*
     * Prepare a different synthetic password for the new image.
     * Deliberately omit RXRAY_EXEC_OLD from the replacement environment.
     * The pre-exec image may contain BOTH values during preparation; the
     * regression therefore checks that the OLD fingerprint is absent in
     * the POST-exec image, not that the new value was absent pre-exec.
     */
    static const char kEnvPrefix[] = "RXRAY_EXEC_NEW=password=";
    char replacement[sizeof(kEnvPrefix) + kPasswordLength];
    memcpy(replacement, kEnvPrefix, sizeof(kEnvPrefix) - 1);

    const char *old_password = old_value + sizeof(kPasswordPrefix) - 1;
    for (size_t i = 0; i < kPasswordLength; ++i) {
        replacement[sizeof(kEnvPrefix) - 1 + i] =
            rotate_character(old_password[i]);
    }
    replacement[sizeof(kEnvPrefix) - 1 + kPasswordLength] = '\0';

    char *const new_argv[] = { (char *)"/proc/self/exe",
                               (char *)"--after-exec", NULL };
    char *const new_envp[] = { replacement, (char *)"PATH=/usr/bin:/bin",
                               NULL };

    execve("/proc/self/exe", new_argv, new_envp);
    perror("FAIL: successful execve fixture unexpectedly returned");
    return 7;
}
