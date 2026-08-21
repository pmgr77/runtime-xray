#ifndef RUNTIMEXRAY_MEMORY_SCANNER_HPP
#define RUNTIMEXRAY_MEMORY_SCANNER_HPP


#include "finding.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace runtimexray {

    struct MemoryRegion {
        uint64_t start;
        uint64_t end;
        std::string perms;
        std::string path; // may be empty
    };

    /**
     * @brief Returns readable memory regions of a process.
     * @param pid Process ID.
     * @return Vector of readable regions (empty if error).
     */
    std::vector<MemoryRegion> get_readable_regions(pid_t pid);

    /**
     * @brief Scans readable memory of a process for secrets.
     * @param pid Process ID.
     * @param findings Output list to append findings to.
     * @param max_findings Max number of findings to detect.
     */
    void scan_memory_for_secrets(pid_t pid, FindingList& findings, size_t max_findings = 50);
} // namespace runtimexray

#endif // RUNTIMEXRAY_MEMORY_SCANNER_HPP