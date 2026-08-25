#include "itrace_backend.hpp"
#include "tachikoma.hpp"

#include <memory>

namespace runtimexray {

class PTraceBackend : public ITraceBackend {
public:
    std::string name() const override { return "ptrace"; }
    bool supports_attach() const override { return false; }
    bool supports_function_tracing() const override { return false; }

    bool is_timed_out() const { return tracer_ ? tracer_->is_timed_out() : false; }
    
    std::string child_output_path() const { 
        return tracer_ ? tracer_->child_output_path() : ""; 
    }

    std::string read_string(uint64_t address, size_t size) const override {
        if (!tracer_) return {};
        return tracer_->read_string(address, size);
    }

    std::vector<std::byte> read_memory(uint64_t address, size_t size) const override {
        if (!tracer_) return std::vector<std::byte>{};
        return tracer_->read_memory(address, size);
    }

    int trace(const TraceConfig& config) override {
        tracer_ = std::make_unique<Tachikoma>(config.program, config.args);
        tracer_->set_timeout(config.timeout);
        return tracer_->run(config.callback);
    }

private:
    std::unique_ptr<Tachikoma> tracer_; // created in trace(), used by read methods
};

std::unique_ptr<ITraceBackend> create_default_tracer_backend() {
    return std::make_unique<PTraceBackend>();
}

} // namespace runtimexray