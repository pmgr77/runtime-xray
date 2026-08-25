#ifndef RUNTIMEXRAY_ITRACE_BACKEND_HPP
#define RUNTIMEXRAY_ITRACE_BACKEND_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <memory>

#include "tachikoma.hpp"   // for SyscallEvent

namespace runtimexray {

/**
 * @brief Callback type for trace events.
 */
using TraceEventCallback = std::function<void(const SyscallEvent&)>;

/**
 * @brief Configuration for a tracing session.
 */
struct TraceConfig {
    std::string program;
    std::vector<std::string> args;
    std::chrono::seconds timeout{0};
    TraceEventCallback callback;
};

/**
 * @brief Abstract interface for tracing backends.
 *
 * Implementations may use ptrace, eBPF, or other mechanisms.
 * This allows RuntimeXRay to switch tracing strategies without changing
 * the core analysis logic.
 */
class ITraceBackend {
public:
    virtual ~ITraceBackend() = default;

    /** @return Unique backend name, e.g., "ptrace", "ebpf". */
    virtual std::string name() const = 0;
    
    /** @return True if this backend can attach to an already-running process. */
    virtual bool supports_attach() const = 0;

    /** @return True if this backend can trace specific functions (uprobes). */
    virtual bool supports_function_tracing() const = 0;

    virtual bool is_timed_out() const = 0;

    virtual std::string child_output_path() const = 0;

    /**
     * @brief Reads a null-terminated string from the traced process memory.
     * @param address Virtual address of the string in the traced process.
     * @param max_len Maximum number of bytes to read.
     * @return String contents (without the null terminator).
     */
    virtual std::string read_string(uint64_t address, size_t max_len = 256) const = 0;
    
    /**
     * @brief Reads arbitrary bytes from the traced process memory.
     * @param address Virtual address in the traced process.
     * @param size Number of bytes to read.
     * @return Vector of bytes (empty on error).
     */
    virtual std::vector<std::byte> read_memory(uint64_t address, size_t size) const = 0;
    
    /**
     * @brief Starts a tracing session.
     *
     * @param config Trace configuration.
     * @return Exit status of the traced process, or -1 if killed by signal,
     *         -2 if timed out.
     * @throws std::runtime_error on failure.
     */
    virtual int trace(const TraceConfig& config) = 0;
};

std::unique_ptr<ITraceBackend> create_default_tracer_backend();

} // namespace runtimexray

#endif // RUNTIMEXRAY_ITRACE_BACKEND_HPP