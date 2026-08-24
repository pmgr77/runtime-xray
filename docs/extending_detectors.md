# Extending RuntimeXRay Analyzers

RuntimeXRay uses a registry of analyzers. You can add your own custom analyzers, remove built‑in ones, or temporarily disable them without modifying the core code.

## Built-in analyzers

The following analyzers are registered automatically:

| Analyzer name         | Category | Description |
|-----------------------|----------|-------------|
| `hardening`           | Static   | Evaluates binary hardening features (NX, PIE, RELRO, Canary) |
| `dangerous_api`       | Static   | Detects known dangerous imports |
| `sensitive_file`      | Dynamic  | Flags access to sensitive files |
| `network`             | Dynamic  | Flags suspicious network connections |
| `memory_password`     | Memory   | Detects password‑like strings in memory |
| `memory_private_key`  | Memory   | Detects private key blocks in memory |

## Adding a custom analyzer

Create a class that inherits from `runtimexray::IAnalyzer`. Implement the four pure virtual methods:
`name()`, `description()`, `category()`, and `analyze(const Evidence&)`.

### Example: AWS Access Key analyzer

```cpp
#include <ianalyzer.hpp>
#include <evidence.hpp>
#include <finding.hpp>

class AwsAccessKeyAnalyzer : public runtimexray::IAnalyzer {
public:
    std::string name() const override { return "aws_access_key"; }
    std::string description() const override {
        return "Detects AWS Access Key IDs (AKIA...)";
    }
    runtimexray::AnalyzerCategory category() const override {
        return runtimexray::AnalyzerCategory::Memory;
    }

    runtimexray::FindingList analyze(const runtimexray::Evidence& evidence) const override {
        runtimexray::FindingList findings;
        if (auto* mem = std::get_if<runtimexray::MemoryChunkEvidence>(&evidence)) {
            const std::string& chunk = mem->chunk;
            size_t pos = 0;
            while ((pos = chunk.find("AKIA", pos)) != std::string::npos) {
                if (pos + 20 <= chunk.size()) {
                    std::string key = chunk.substr(pos, 20);
                    findings.emplace_back(
                        runtimexray::FindingSeverity::High,
                        "AWS Access Key found",
                        "Potential AWS Access Key ID detected.",
                        runtimexray::MemorySecretFindingDetails{key, "aws_access_key", mem->location}
                    );
                }
                pos += 4;
            }
        }
        return findings;
    }
};
```

To register it, call `register_analyzer` before running any scan:

```cpp
#include <analyzer_registry.hpp>

int main() {
    auto& reg = runtimexray::AnalyzerRegistry::instance();
    reg.register_analyzer(std::make_unique<AwsAccessKeyAnalyzer>());

    // Now run your scan...
}
```

Alternatively, use a macro for automatic registration:

```cpp
#define REGISTER_ANALYZER(Type) \
    static struct Type##_registrar { \
        Type##_registrar() { \
            runtimexray::AnalyzerRegistry::instance().register_analyzer(std::make_unique<Type>()); \
        } \
    } Type##_registrar_instance;

REGISTER_ANALYZER(AwsAccessKeyAnalyzer)
```

## Removing or disabling a built-in analyzer

### Disable (skip execution but keep registered)

```cpp
runtimexray::AnalyzerRegistry::instance().disable_analyzer("memory_password");
```

### Re-enable

```cpp
runtimexray::AnalyzerRegistry::instance().enable_analyzer("memory_password");
```

### Remove entirely

```cpp
runtimexray::AnalyzerRegistry::instance().unregister_analyzer("memory_password");
```

## Listing active analyzers

```cpp
auto names = runtimexray::AnalyzerRegistry::instance().list_analyzers();
for (const auto& n : names) {
    std::cout << n << "\n";
}
```

## Notes

- Analyzer names must be unique.
- The registry is a singleton; thread safety is not yet guaranteed, but it is safe for single‑threaded CLI use.
- If you disable an analyzer, it will not be called for any evidence.
- Each analyzer is responsible for checking the evidence type it supports (using `std::get_if`).

This design allows RuntimeXRay to be extended without modifying the core library.