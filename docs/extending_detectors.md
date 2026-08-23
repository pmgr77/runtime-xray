# Extending RuntimeXRay Detectors

RuntimeXRay uses a simple registry for memory secret detectors. You can add your own custom detectors, remove built‑in ones, or temporarily disable them without modifying the core code.

## Built-in detectors

The following detectors are registered automatically:

| Detector name   | Description                                       |
|-----------------|---------------------------------------------------|
| `password`      | Detects sensitive keywords in `key=value` or `key: value` pairs (e.g., `password=secret`, `api_key: abc`) |
| `private_key`   | Detects PEM private key blocks (`BEGIN RSA PRIVATE KEY`, etc.) |

## Adding a custom detector

Create a class that inherits from `runtimexray::MemorySecretDetector`. Implement the three pure virtual methods: `name()`, `description()`, and `detect()`.

### Example: AWS Access Key detector

```cpp
#include <memory_secret_detector.hpp>

class AwsAccessKeyDetector : public runtimexray::MemorySecretDetector {
public:
    std::string name() const override { return "aws_access_key"; }
    std::string description() const override {
        return "Detects AWS Access Key IDs (AKIA...)";
    }

    std::vector<runtimexray::SecretMatch> detect(const std::string& chunk) const override {
        std::vector<runtimexray::SecretMatch> results;
        size_t pos = 0;
        while ((pos = chunk.find("AKIA", pos)) != std::string::npos) {
            if (pos + 20 <= chunk.size()) {
                std::string key = chunk.substr(pos, 20);
                results.push_back({"aws_access_key", key, "AWS Access Key ID"});
            }
            pos += 4;
        }
        return results;
    }
};
```

To register it, call `register_detector` before scanning:

```cpp
#include <memory_secret_detector.hpp>

int main() {
    auto& reg = runtimexray::DetectorRegistry::instance();
    reg.register_detector(std::make_unique<AwsAccessKeyDetector>());

    // Now run your scan...
}
```

Alternatively, use a simple macro to make registration easy:

```cpp
#define REGISTER_DETECTOR(Type) \
    static struct Type##_registrar { \
        Type##_registrar() { \
            runtimexray::DetectorRegistry::instance().register_detector(std::make_unique<Type>()); \
        } \
    } Type##_registrar_instance;
```

Then use:

```cpp
REGISTER_DETECTOR(AwsAccessKeyDetector)
```

## Removing or disabling a built-in detector

### Disable (skip scanning but keep registered)

```cpp
runtimexray::DetectorRegistry::instance().disable_detector("password");
```

### Re-enable

```cpp
runtimexray::DetectorRegistry::instance().enable_detector("password");
```

### Remove entirely

```cpp
runtimexray::DetectorRegistry::instance().unregister_detector("password");
```

## Listing active detectors

```cpp
auto names = runtimexray::DetectorRegistry::instance().list_detectors();
for (const auto& n : names) {
    std::cout << n << "\n";
}
```

## Notes

- Detector names must be unique.
- The registry is a singleton; thread safety is not yet guaranteed, but it is safe for single‑threaded CLI use.
- If you disable a detector, it will not be called by `detect_secrets_in_chunk`.

This design allows RuntimeXRay to be extended without modifying the core library.