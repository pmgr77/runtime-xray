
/**
 * @file    test_netrc_extractor.cpp
 * @brief   Unit tests for .netrc password extraction and byte offsets.
 *
 * @author  Peter Magram
 * @date    2026-10-17
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

#include "netrc_extractor.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using runtimexray::NetrcPassword;
using runtimexray::extract_netrc_passwords;

/**
 * @brief Fail the current test if a condition is false.
 *
 * Unlike assert(), this remains active in Release builds.
 *
 * @param condition Condition that must hold.
 * @param message Diagnostic message identifying the failed check.
 */
void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/**
 * @brief Verify that a password references exact input bytes.
 *
 * @param input Original buffer.
 * @param password Extracted password and byte offset.
 */
void require_exact_offset(
    const std::string& input,
    const NetrcPassword& password)
{
    require(
        password.offset <= input.size(),
        "Password offset exceeds input size");

    require(
        password.value.size() <= input.size() - password.offset,
        "Password extends beyond input buffer");

    require(
        input.compare(
            password.offset,
            password.value.size(),
            password.value) == 0,
        "Password offset does not reference exact source bytes");
}

/**
 * @brief Verify extraction from a normal machine stanza.
 */
void test_basic_machine()
{
    const std::string input =
        "machine 127.0.0.1\n"
        "login rxray_user\n"
        "password RXRAY_TEST_PASSWORD_123456\n";

    const auto matches = extract_netrc_passwords(input);

    require(matches.size() == 1, "Expected one machine password");
    require(
        matches[0].value == "RXRAY_TEST_PASSWORD_123456",
        "Incorrect machine password");

    require_exact_offset(input, matches[0]);
}

/**
 * @brief Verify quoted passwords and offset preservation.
 */
void test_quoted_password()
{
    const std::string input =
        "machine example.org\n"
        "login alice\n"
        "password \"quoted password 789\"\n";

    const auto matches = extract_netrc_passwords(input);

    require(matches.size() == 1, "Expected one quoted password");
    require(
        matches[0].value == "quoted password 789",
        "Incorrect quoted password");

    require_exact_offset(input, matches[0]);
}

/**
 * @brief Verify default stanza extraction.
 */
void test_default_stanza()
{
    const std::string input =
        "default login bob password DEFAULT_SECRET_987654\n";

    const auto matches = extract_netrc_passwords(input);

    require(matches.size() == 1, "Expected one default password");
    require(
        matches[0].value == "DEFAULT_SECRET_987654",
        "Incorrect default password");

    require_exact_offset(input, matches[0]);
}

/**
 * @brief Verify multiple independent machine stanzas.
 */
void test_multiple_machines()
{
    const std::string input =
        "machine first.example\n"
        "login alice\n"
        "password FIRST_SECRET_123456\n"
        "machine second.example\n"
        "login bob\n"
        "password SECOND_SECRET_987654\n";

    const auto matches = extract_netrc_passwords(input);

    require(matches.size() == 2, "Expected two passwords");

    require(
        matches[0].value == "FIRST_SECRET_123456",
        "Incorrect first password");

    require(
        matches[1].value == "SECOND_SECRET_987654",
        "Incorrect second password");

    for (const auto& match : matches) {
        require_exact_offset(input, match);
    }
}

/**
 * @brief Verify that comments do not generate credentials.
 */
void test_comments()
{
    const std::string input =
        "# machine fake login fake password COMMENT_SECRET_123\n"
        "machine example.org\n"
        "login alice\n"
        "# password IGNORED_SECRET_123\n"
        "password REAL_SECRET_456789\n";

    const auto matches = extract_netrc_passwords(input);

    require(matches.size() == 1, "Comments must be ignored");
    require(
        matches[0].value == "REAL_SECRET_456789",
        "Incorrect password after comments");

    require_exact_offset(input, matches[0]);
}

/**
 * @brief Verify that a password without login is not extracted.
 */
void test_missing_login()
{
    const std::string input =
        "machine example.org\n"
        "password SECRET_WITHOUT_LOGIN_123\n";

    const auto matches = extract_netrc_passwords(input);

    require(matches.empty(), "Password without login was accepted");
}

/**
 * @brief Verify minimum password length enforcement.
 */
void test_short_password()
{
    const std::string input =
        "machine example.org login alice password short\n";

    const auto matches = extract_netrc_passwords(input);

    require(matches.empty(), "Short password was accepted");
}

/**
 * @brief Verify unsupported escaped passwords are rejected.
 */
void test_escaped_password()
{
    const std::string input =
        R"(machine example.org login alice password "escaped\ password")";

    const auto matches = extract_netrc_passwords(input);

    require(matches.empty(), "Unsupported escaped password was accepted");
}

/**
 * @brief Verify binary input is rejected.
 */
void test_binary_input()
{
    std::string input =
        "machine example.org login alice password SECRET_123456";

    input.push_back('\0');
    input += "binary suffix";

    const auto matches = extract_netrc_passwords(input);

    require(matches.empty(), "Binary input was accepted");
}

/**
 * @brief Verify ordinary text does not masquerade as .netrc.
 */
void test_unrelated_text()
{
    const std::string input =
        "application started\n"
        "login alice\n"
        "password SECRET_123456\n";

    const auto matches = extract_netrc_passwords(input);

    require(matches.empty(), "Unrelated text was accepted as .netrc");
}

} // anonymous namespace

/**
 * @brief Execute the .netrc extractor regression tests.
 *
 * @return 0 if every test passes, 1 otherwise.
 */
int main()
{
    try {
        test_basic_machine();
        test_quoted_password();
        test_default_stanza();
        test_multiple_machines();
        test_comments();
        test_missing_login();
        test_short_password();
        test_escaped_password();
        test_binary_input();
        test_unrelated_text();

        std::cout
            << "PASS: all 10 netrc extractor tests\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr
            << "FAIL: " << e.what() << '\n';

        return 1;
    }
}
