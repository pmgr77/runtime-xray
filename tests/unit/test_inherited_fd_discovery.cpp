/**
 * @file    test_inherited_fd_discovery.cpp
 * @brief   Tests discovery of pre-existing Linux file descriptors.
 *
 * @author  Peter Magram
 * @date    2026-10-31
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

#include "inherited_fd_discovery.hpp"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

using runtimexray::InheritedFd;
using runtimexray::discover_preexisting_fds;

void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/**
 * @brief Ensure the child cannot remain stopped after a test failure.
 */
class ChildGuard {
public:
    explicit ChildGuard(pid_t pid) : pid_(pid) {}

    ~ChildGuard()
    {
        if (pid_ <= 0) {
            return;
        }

        ::kill(pid_, SIGKILL);

        int status = 0;
        while (::waitpid(pid_, &status, 0) == -1 && errno == EINTR)
        { }
    }

    ChildGuard(const ChildGuard&) = delete;
    ChildGuard& operator=(const ChildGuard&) = delete;

private:
    pid_t pid_;
};

/**
 * @brief Find metadata for a specific descriptor.
 */
const InheritedFd* find_fd(const std::vector<InheritedFd>& descriptors, int fd)
{
    const auto it = std::find_if(
        descriptors.begin(),
        descriptors.end(),
        [fd](const InheritedFd& descriptor) {
            return descriptor.fd == fd;
        }
    );

    return it == descriptors.end() ? nullptr : &*it;
}

/**
 * @brief Test pipe inheritance and descriptor metadata.
 */
void test_inherited_pipe()
{
    int pipe_fds[2] = {-1, -1};

    require(::pipe(pipe_fds) == 0, "pipe() failed");

    // Mark the read end close-on-exec.
    const int flags = ::fcntl(pipe_fds[0], F_GETFD);
    require(flags >= 0, "F_GETFD failed");

    require(
        ::fcntl(pipe_fds[0], F_SETFD, flags | FD_CLOEXEC) == 0,
        "F_SETFD failed"
    );

    const pid_t child = ::fork();

    require(child >= 0, "fork() failed");

    if (child == 0) {
        // Preserve both inherited ends and stop for inspection.
        if (::raise(SIGSTOP) != 0) {
            ::_exit(1);
        }
        ::_exit(0);
    }

    ChildGuard guard(child);

    // Wait until the child is stopped and its FD table is stable.
    int status = 0;

    require(
        ::waitpid(child, &status, WUNTRACED) == child,
        "waitpid() failed"
    );

    require(WIFSTOPPED(status), "child did not stop");

    const auto descriptors = discover_preexisting_fds(child);

    const InheritedFd* reader = find_fd(descriptors, pipe_fds[0]);
    const InheritedFd* writer = find_fd(descriptors, pipe_fds[1]);

    require(reader != nullptr, "inherited read FD not found");
    require(writer != nullptr, "inherited write FD not found");

    require(reader->type == "pipe", "read FD type is not pipe");
    require(writer->type == "pipe", "write FD type is not pipe");

    require(reader->role == "read", "incorrect read FD role");
    require(writer->role == "write", "incorrect write FD role");

    require(reader->cloexec, "read FD lost FD_CLOEXEC");
    require(!writer->cloexec, "write FD unexpectedly has FD_CLOEXEC");

    require(
        std::is_sorted(
            descriptors.begin(),
            descriptors.end(),
            [](const InheritedFd& a, const InheritedFd& b) {
                return a.fd < b.fd;
            }
        ),
        "discovered FDs are not sorted"
    );

    ::close(pipe_fds[0]);
    ::close(pipe_fds[1]);

    std::cout << "PASS: inherited pipe descriptors detected\n";
    std::cout << "PASS: read/write roles\n";
    std::cout << "PASS: FD_CLOEXEC preserved\n";
    std::cout << "PASS: deterministic FD ordering\n";
}

/**
 * @brief Verify kernel-object identity for pre-existing pipes.
 *
 * Both ends of the same pipe must have the same kernel-object key.
 * Two independent, simultaneously open pipes must have different keys.
 */
void test_pipe_kernel_object_identity()
{
    int first_pipe[2] = {-1, -1};
    int second_pipe[2] = {-1, -1};

    require(::pipe(first_pipe) == 0, "first pipe() failed");
    require(::pipe(second_pipe) == 0, "second pipe() failed");

    const auto descriptors = discover_preexisting_fds(::getpid());

    const InheritedFd* first_reader = find_fd(descriptors, first_pipe[0]);
    const InheritedFd* first_writer = find_fd(descriptors, first_pipe[1]);

    const InheritedFd* second_reader = find_fd(descriptors, second_pipe[0]);
    const InheritedFd* second_writer = find_fd(descriptors, second_pipe[1]);

    require(first_reader != nullptr, "first pipe read FD not found");
    require(first_writer != nullptr, "first pipe write FD not found");
    require(second_reader != nullptr, "second pipe read FD not found");
    require(second_writer != nullptr, "second pipe write FD not found");

    require(first_reader->type == "pipe", "first read FD type is not pipe");
    require(first_writer->type == "pipe", "first write FD type is not pipe");
    require(second_reader->type == "pipe", "second read FD type is not pipe");
    require(second_writer->type == "pipe", "second write FD type is not pipe");

    require(
        !first_reader->kernel_object_key.empty(),
        "first pipe kernel object key is empty"
    );

    require(
        !second_reader->kernel_object_key.empty(),
        "second pipe kernel object key is empty"
    );

    require(
        first_reader->kernel_object_key.compare(0, 6, "pipe:[") == 0 &&
        first_reader->kernel_object_key.back() == ']',
        "first pipe kernel object key has invalid format"
    );

    require(
        second_reader->kernel_object_key.compare(0, 6, "pipe:[") == 0 &&
        second_reader->kernel_object_key.back() == ']',
        "second pipe kernel object key has invalid format"
    );

    require(
        first_reader->kernel_object_key == first_writer->kernel_object_key,
        "first pipe ends have different kernel object keys"
    );

    require(
        second_reader->kernel_object_key == second_writer->kernel_object_key,
        "second pipe ends have different kernel object keys"
    );

    require(
        first_reader->kernel_object_key != second_reader->kernel_object_key,
        "independent pipes share the same kernel object key"
    );

    ::close(first_pipe[0]);
    ::close(first_pipe[1]);
    ::close(second_pipe[0]);
    ::close(second_pipe[1]);

    std::cout << "PASS: kernel object keys detected\n";
    std::cout << "PASS: same pipe shares kernel object identity\n";
    std::cout << "PASS: independent pipes have distinct identities\n";
}

/**
 * @brief Invalid process IDs must not produce descriptors.
 */
void test_invalid_pid()
{
    require(
        discover_preexisting_fds(-1).empty(),
        "invalid PID returned descriptors"
    );

    std::cout << "PASS: invalid PID handling\n";
}

} // anonymous namespace

int main()
{
    try {
        test_invalid_pid();
        test_inherited_pipe();
        test_pipe_kernel_object_identity();

        std::cout << "PASS: inherited FD discovery tests\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
