<!--
  RuntimeXRay Custom Analyzer Examples

  Copyright 2026 Peter Magram.
  Licensed under the Apache License, Version 2.0.
-->

# examples/custom_analyzers

This directory contains example implementations of custom RuntimeXRay analyzers.
Each example is self-contained and demonstrates how to extend RuntimeXRay with your own detection logic.

## How to use

These analyzers are **not built by default**. They are provided as reference code that you can copy into your own project after you have RuntimeXRay available as a library or source.

Once RuntimeXRay core is built or installed, you can add these files to your project and register the analyzers as shown in the `main` example below.

## Examples included

- `credit_card_analyzer` – detects credit card numbers in memory
- `cloud_credential_analyzer` – detects AWS / GCP / Azure credential patterns
- `ioc_analyzer` – detects custom indicators of compromise

Each analyzer is implemented as a class deriving from `runtimexray::IAnalyzer`.

## Registration example

```cpp
#include <analyzer_registry.hpp>
#include "credit_card_analyzer.hpp"
#include "cloud_credential_analyzer.hpp"
#include "ioc_analyzer.hpp"

int main() {
    auto& reg = runtimexray::AnalyzerRegistry::instance();
    reg.register_analyzer(std::make_unique<CreditCardAnalyzer>());
    reg.register_analyzer(std::make_unique<CloudCredentialAnalyzer>());
    reg.register_analyzer(std::make_unique<IocAnalyzer>());

    // Now feed evidence through the registry.
    runtimexray::MemoryChunkEvidence ev("some text 4111-1111-1111-1111 more text", "memory", getpid());
    auto findings = reg.analyze_evidence(ev);

    for (const auto& f : findings) {
        std::cout << f.description << "\n";
    }
    return 0;
}
```

## Building

From the main project build directory, run:

```bash
cmake .. -DBUILD_EXAMPLES=ON
cmake --build .
./examples/custom_analyzers/custom_analyzer_demo
```

## Notes

- All code is licensed under Apache 2.0, same as RuntimeXRay.
- These examples focus on memory evidence, but the same pattern applies to `FileAccessEvidence`, `NetworkEvidence`, `SymbolEvidence`, and `HardeningEvidence`.