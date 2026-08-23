#ifndef RUNTIMEXRAY_REPORTER_HPP
#define RUNTIMEXRAY_REPORTER_HPP

#include "finding.hpp"
#include <string>

namespace runtimexray {
    
struct ReportContext {
    std::string tool_name = "runtimexray";
    std::string tool_version = "0.1.0";
    std::string command;      // "analyze", "trace", "mem"
    std::string target;       // binary path, program, or pid
    std::string started_at;   // ISO 8601
    int duration_ms = 0;
};

std::string current_iso8601_utc();

class Reporter {
public:
    // Generates a human-readable text report
    static std::string to_text(const FindingList& findings, bool verbose);

    // Generates a JSON report
    static std::string to_json(const FindingList& findings, const ReportContext& context);

private:
    static std::string severity_to_string(FindingSeverity severity);
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_REPORTER_HPP