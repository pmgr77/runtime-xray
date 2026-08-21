
#include "memory_scanner.hpp"
#include "memory_secret_detector.hpp"

#include <fstream>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <sys/uio.h>
#include <unistd.h>
#include <algorithm>

namespace runtimexray {

    std::vector<MemoryRegion> get_readable_regions(pid_t pid) {
        std::vector<MemoryRegion> regions;
        std::string path = "/proc/" + std::to_string(pid) + "/maps";

        std::ifstream maps(path);
        if (!maps) {
            return regions;
        }

        std::string line;
        while (std::getline(maps, line)) {
            std::istringstream iss(line);
            uint64_t start, end;
            char dash;
            char perms[5] = {0};
            uint64_t offset;
            std::string rest;

            // Read main fields: start-end perms offset
            if (!(iss >> std::hex >> start >> dash >> end >> perms >> offset)) {
                continue;
            }

            // read the rest of the line - dev, inode, pathname
            std::getline(iss, rest);

            // remove leading whitespaces
            rest.erase(0, rest.find_first_not_of(" \t"));
            std::string pathname = rest;

            // check that reagion is readable ('r' in perms)
            if (perms[0] == 'r') {
                regions.push_back({start, end, perms, pathname});
            }
        }
        return regions;
    }
   
    void scan_memory_for_secrets(pid_t pid, FindingList& findings, size_t max_findings) {
        auto regions = get_readable_regions(pid);
        if (regions.empty()) {
            return;
        }
        constexpr size_t chunk_size = 4096;
        std::vector<std::byte> buffer(chunk_size);

        size_t found_count = 0;

        for (const auto& region : regions) {
            uint64_t address = region.start;
            while (address < region.end) {
                size_t to_read = std::min<size_t>(chunk_size, region.end - address);

                struct iovec local;
                local.iov_base = buffer.data();
                local.iov_len = to_read;

                struct iovec remote;
                remote.iov_base = reinterpret_cast<void*>(address);
                remote.iov_len = to_read;

                ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
                if (n <= 0) {
                    // page unavailable, read error - skip rest of region and continue
                    address += 4096;
                    continue;
                }
                
                // transform into searchable string (binary data may contain zeros)
                std::string chunk(reinterpret_cast<char*>(buffer.data()), static_cast<size_t>(n));
                auto matches = detect_secrets_in_chunk(chunk);

                for (const auto& match : matches) {
                    findings.emplace_back(
                        FindingSeverity::High,
                        "Sensitive data found in memory",
                        "Process memory contains potential secrets.",
                        SensitiveDataWriteDetails{match.snippet, match.description}
                    );
                    if (++found_count >= max_findings) {
                        return;
                    }
                }

                address += static_cast<uint64_t>(n);    
            }
        }
    }

} // namespace runtimexray