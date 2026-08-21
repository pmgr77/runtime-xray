#include "memory_scanner.hpp"
#include <iostream>
#include <unistd.h>

int main() {
    auto regions = runtimexray::get_readable_regions(getpid());
    if (regions.empty()) {
        std::cerr << "No readable regions found\n";
        return 1;
    }
    // Check that there are readable regions
    bool found = false;
    for (const auto& r : regions) {
        if (r.perms[0] == 'r') {
            found = true;
            break;
        }
    }
    if (!found) {
        std::cerr << "No readable region\n";
        return 1;
    }
    return 0;
}