/**
 * @file    exec_echo_test.c
 * @brief   Test program that calls execve("/bin/echo").
 *
 * @author  Peter Magram
 * @date    2026-09-01
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

#include <unistd.h>
#include <stdio.h>

int main() {
    char *args[] = {"/bin/echo", "hello", NULL};
    execve("/bin/echo", args, NULL);
    perror("execve");
    return 1;
}