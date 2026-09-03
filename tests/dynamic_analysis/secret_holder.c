/**
 * @file    secret_holder.c
 * @brief   Test program that holds secrets in multiple memory regions.
 *
 * @author  Peter Magram
 * @date    2026-09-03
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global data secret
static char global_secret[] = "password=global456";

int main(int argc, char **argv) {
    // Stack secret
    char stack_secret[] = "password=stack789";

    // Heap secret
    char *heap_secret = malloc(64);
    if (heap_secret) {
        strcpy(heap_secret, "password=heap012");
    }

    // Environment secret (set before running)
    // The script will set ENV_SECRET

    // Command line secret (passed as argv[1])
    // The script will pass a secret as argument.

    printf("Secrets placed:\n");
    printf("  Global: %s at %p\n", global_secret, (void*)global_secret);
    printf("  Stack:  %s at %p\n", stack_secret, (void*)stack_secret);
    if (heap_secret) {
        printf("  Heap:   %s at %p\n", heap_secret, (void*)heap_secret);
    }
    printf("  Environ: ENV_SECRET (set in script)\n");
    printf("  Cmdline: %s (argv[1])\n", argc > 1 ? argv[1] : "none");
    printf("PID: %d\n", getpid());
    fflush(stdout);

    // Sleep indefinitely to allow memory scan
    while (1) {
        sleep(10);
    }

    free(heap_secret);
    return 0;
}