/**
 * @file    cli_common.hpp
 * @brief   Common CLI options and global argument parsing.
 *
 * @author  Peter Magram
 * @date    2026-08-22
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */
#ifndef RUNTIMEXRAY_COMMON_CLI_HPP
#define RUNTIMEXRAY_COMMON_CLI_HPP

#include "finding.hpp"

#include <string>
#include <vector>

namespace runtimexray {

/**
 * @brief Options shared by all subcommands.
 */
struct CommonOptions {
    bool verbose = false; 
    FindingSeverity min_severity = FindingSeverity::Medium;
    std::string output_format = "text"; // future extension: "json", "xml", etc.
};

/**
 * @brief Parses global options from the given arguments.
 *
 * Removes recognised global flags and stores their values in `opts`.
 * All unrecognised arguments are returned in `remaining`.
 *
 * @param args Input arguments (after the subcommand name).
 * @param opts Output common options.
 * @param remaining Arguments not recognised as global options.
 * @return true on success, false on invalid global option.
 */
bool parse_global_options(const std::vector<std::string>& args, CommonOptions& opts, std::vector<std::string>& remaining);

} // namespace runtimexray

#endif // RUNTIMEXRAY_COMMON_CLI_HPP