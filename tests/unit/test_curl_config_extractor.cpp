/**
 * @file    test_curl_config_extractor.cpp
 * @brief   Unit tests for curl config password extraction and byte offsets.
 *
 * @author  Peter Magram
 * @date    2026-10-26
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

#include "curl_config_extractor.hpp"

#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void expect_one(
    const std::string& name,
    const std::string& input,
    const std::string& expected_password,
    std::size_t expected_offset)
{
    const auto matches =
        runtimexray::extract_curl_config_passwords(input);

    if (matches.size() != 1) {
        throw std::runtime_error(
            name + ": expected exactly one password");
    }

    const auto& match = matches.front();

    if (match.value != expected_password) {
        throw std::runtime_error(
            name + ": incorrect password value");
    }

    if (match.offset != expected_offset) {
        throw std::runtime_error(
            name + ": incorrect password offset");
    }

    // The reported password must occur at precisely this position
    // in the original input. No reconstructed or decoded bytes.
    if (input.compare(
            match.offset,
            match.value.size(),
            match.value) != 0) {
        throw std::runtime_error(
            name + ": password bytes do not match original input");
    }
}

void expect_none(
    const std::string& name,
    const std::string& input)
{
    const auto matches =
        runtimexray::extract_curl_config_passwords(input);

    if (!matches.empty()) {
        throw std::runtime_error(
            name + ": unexpected password detection");
    }
}

void test_supported_syntax()
{
    expect_one(
        "quoted user",
        "user = \"alice:secret\"\n",
        "secret",
        14);

    expect_one(
        "colon separator and CRLF",
        "\tuser: bob:abc:def\r\n",
        "abc:def",
        11);

    expect_one(
        "long option",
        "--user carol:s3cr3t\n",
        "s3cr3t",
        13);

    expect_one(
        "short option",
        "-u dave:pass\n",
        "pass",
        8);

    expect_one(
        "equals without spaces",
        "user=eve:p\n",
        "p",
        9);

    expect_one(
        "whitespace separator",
        "user\tfrank:pw\n",
        "pw",
        11);

    expect_one(
        "colon inside password",
        "user = \"alice:abc:def\"\n",
        "abc:def",
        14);
}

void test_negative_cases()
{
    expect_none(
        "comment",
        "# user = \"alice:secret\"\n");

    expect_none(
        "indented comment",
        "  # user = \"alice:secret\"\n");

    expect_none(
        "unrelated option",
        "username = \"alice:secret\"\n");

    expect_none(
        "missing password",
        "user = \"alice:\"\n");

    expect_none(
        "missing username",
        "user = \":secret\"\n");

    expect_none(
        "missing separator",
        "user = \"alicesecret\"\n");

    expect_none(
        "unterminated quote",
        "user = \"alice:secret\n");

    expect_none(
        "escaped quoted value",
        R"(user = "alice:sec\"ret")"
        "\n");

    expect_none(
        "extra tokens",
        "user = \"alice:secret\" extra\n");

    expect_none(
        "invalid dashed equals separator",
        "--user=alice:secret\n");

    expect_none(
        "invalid short colon separator",
        "-u:alice:secret\n");

    expect_none(
        "incomplete read buffer",
        "user = \"alice:secret\"");

    expect_none(
        "unrelated source code",
        "printf(\"user = alice:secret\");\n");
}

void test_multiple_directives()
{
    const std::string input =
        "# curl configuration\n"
        "user = \"alice:first\"\n"
        "output = /dev/null\n"
        "--user bob:second\n";

    const auto matches =
        runtimexray::extract_curl_config_passwords(input);

    if (matches.size() != 2) {
        throw std::runtime_error(
            "multiple directives: expected two passwords");
    }

    if (matches[0].value != "first" ||
        matches[1].value != "second") {
        throw std::runtime_error(
            "multiple directives: incorrect password values");
    }

    for (const auto& match : matches) {
        if (match.offset > input.size() ||
            match.value.size() > input.size() - match.offset ||
            input.compare(
                match.offset,
                match.value.size(),
                match.value) != 0) {
            throw std::runtime_error(
                "multiple directives: incorrect byte offset");
        }
    }
}

} // anonymous namespace

int main()
{
    try {
        test_supported_syntax();
        test_negative_cases();
        test_multiple_directives();

        std::cout
            << "PASS: curl config password extraction\n"
            << "PASS: exact plaintext offsets\n"
            << "PASS: supported directive syntax\n"
            << "PASS: negative and incomplete-input cases\n"
            << "PASS: multiple credential directives\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr
            << "FAIL: curl config extractor: "
            << e.what() << '\n';

        return 1;
    }
}