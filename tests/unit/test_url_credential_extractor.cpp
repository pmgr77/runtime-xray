
/**
 * @file    test_url_credential_extractor.cpp
 * @brief   Unit tests for HTTP(S) URL credential extraction.
 *
 * @author  Peter Magram
 * @date    2026-10-31
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 *
 * Copyright 2026 Peter Magram
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

#include "url_credential_extractor.hpp"

#include <iostream>
#include <string>

using runtimexray::extract_http_url_password;

namespace {

int failures = 0;
int checks = 0;

/**
 * @brief Verify successful extraction and exact password value.
 */
void expect_password(const char* name, const std::string& url, const std::string& expected)
{
    ++checks;

    std::string password;

    const bool found = extract_http_url_password(url, password);

    if (!found || password != expected) {
        std::cerr << "FAIL: " << name << '\n';
        ++failures;
    }
}

/**
 * @brief Verify that no password is extracted.
 */
void expect_no_password(const char* name, const std::string& url)
{
    ++checks;

    std::string password;

    if (extract_http_url_password(url, password)) {
        std::cerr << "FAIL: " << name << '\n';
        ++failures;
    }
}

void test_plain_urls()
{
    expect_password(
        "E1 plain HTTP password",
        "http://user:password123@127.0.0.1:5000/v2/",
        "password123");

    expect_password(
        "HTTPS password",
        "https://user:secret456@example.com/path",
        "secret456");

    expect_password(
        "URL without path",
        "http://user:secret789@example.com",
        "secret789");

    expect_password(
        "URL with query",
        "https://user:secret123@example.com?key=value",
        "secret123");

    expect_password(
        "URL with fragment",
        "https://user:secret123@example.com#fragment",
        "secret123");
}

void test_percent_decoding()
{
    expect_password(
        "E2 encoded at sign",
        "http://user:p%40ssword@localhost/",
        "p@ssword");

    expect_password(
        "Encoded colon",
        "http://user:p%3Assword@localhost/",
        "p:ssword");

    expect_password(
        "Encoded percent",
        "http://user:p%25ssword@localhost/",
        "p%ssword");

    expect_password(
        "Lowercase hex digits",
        "http://user:p%3assword@localhost/",
        "p:ssword");

    expect_password(
        "Multiple encoded characters",
        "https://user:p%40ss%3Aword%25@localhost/",
        "p@ss:word%");

    expect_password(
        "Encoded URL delimiters",
        "https://user:p%2Fss%3Fword%23@localhost/",
        "p/ss?word#");

    expect_password(
        "Literal plus sign remains plus",
        "http://user:pass+word@localhost/",
        "pass+word");

    expect_password(
        "Encoded plus sign",
        "http://user:pass%2Bword@localhost/",
        "pass+word");
}

void test_invalid_percent_encoding()
{
    expect_no_password(
        "Incomplete percent escape",
        "http://user:pass%2@localhost/");

    expect_no_password(
        "Bare percent sign",
        "http://user:pass%@localhost/");

    expect_no_password(
        "Invalid hex digit",
        "http://user:pass%GG@localhost/");

    expect_no_password(
        "Encoded NUL",
        "http://user:pass%00word@localhost/");

    expect_no_password(
        "Encoded newline",
        "http://user:pass%0Aword@localhost/");

    expect_no_password(
        "Encoded DEL",
        "http://user:pass%7Fword@localhost/");
}

void test_authority_boundaries()
{
    expect_no_password(
        "No credentials",
        "http://localhost:5000/v2/");

    expect_no_password(
        "Username without password",
        "http://user@localhost/");

    expect_no_password(
        "Empty password",
        "http://user:@localhost/");

    expect_no_password(
        "Credentials in path only",
        "http://localhost/path/user:password@host");

    expect_no_password(
        "Credentials in query only",
        "http://localhost/?url=user:password@host");

    expect_no_password(
        "Credentials in fragment only",
        "http://localhost/#user:password@host");

    expect_no_password(
        "Unsupported FTP scheme",
        "ftp://user:password@localhost/");

    expect_no_password(
        "Unsupported file scheme",
        "file://user:password@localhost/");

    expect_no_password(
        "Plain text is not a URL",
        "user:password@localhost");
}

} // anonymous namespace

int main()
{
    test_plain_urls();
    test_percent_decoding();
    test_invalid_percent_encoding();
    test_authority_boundaries();

    if (failures != 0) {
        std::cerr
            << "FAIL: "
            << failures
            << " of "
            << checks
            << " URL credential tests failed\n";

        return 1;
    }

    std::cout
        << "PASS: "
        << checks
        << " URL credential tests\n";

    return 0;
}
