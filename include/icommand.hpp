/**
 * @file    icommand.hpp
 * @brief   Command interface for the unified RuntimeXRay CLI.
 *
 * @author  Peter Magram
 * @date    2026-08-22
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

#ifndef RUNTIMEXRAY_ICOMMAND_HPP
#define RUNTIMEXRAY_ICOMMAND_HPP

#include "common_cli.hpp"
#include <string>
#include <vector>

namespace runtimexray {
    
/**
 * @brief Abstract base class for all subcommands.
 */
class ICommand {
public:
    virtual ~ICommand() = default;

    /** @return Unique command name (e.g., "analyze"). */
    virtual std::string name() const = 0;

    /** @return Short description shown in main help. */
    virtual std::string description() const = 0;

    /**
     * @brief Parses command‑specific arguments.
     *
     * The args vector contains only the arguments remaining after global
     * options were removed by parse_global_options.
     *
     * @param args Command‑specific arguments.
     * @return true if parsing succeeded, false on error or if help was requested.
     */
    virtual bool parse_specific_args(const std::vector<std::string>& args) = 0;

    /**
     * @brief Executes the command using common and specific options.
     * @param common CommonOptions already filled.
     * @return Exit code.
     */
    virtual int execute(const CommonOptions& common) = 0;

    /** @brief Prints command‑specific help. */
    virtual void print_help() const = 0;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_ICOMMAND_HPP