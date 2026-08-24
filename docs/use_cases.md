# Use Cases

This document demonstrates practical scenarios where custom analyzers add significant value to RuntimeXRay. Each example follows the same pattern:

- **Problem:** A real‑world security or compliance need.
- **Solution:** A custom `IAnalyzer` implementation.
- **Value:** The business or security outcome.

---

## 1. Financial Compliance: Credit Card Number Detector

**Problem:** A payment processing application must never expose card numbers in memory. Regulatory requirements (e.g., PCI DSS) demand automated checks.

**Solution:** Register a custom analyzer that scans memory chunks for 16‑digit sequences matching common card formats.

{% raw %}
```cpp
#include <ianalyzer.hpp>
#include <evidence.hpp>
#include <finding.hpp>

class CreditCardAnalyzer : public runtimexray::IAnalyzer {
public:
    std::string name() const override { return "credit_card"; }
    std::string description() const override {
        return "Detects potential credit card numbers in memory";
    }
    runtimexray::AnalyzerCategory category() const override {
        return runtimexray::AnalyzerCategory::Memory;
    }

    runtimexray::FindingList analyze(const runtimexray::Evidence& evidence) const override {
        runtimexray::FindingList findings;
        if (auto* mem = std::get_if<runtimexray::MemoryChunkEvidence>(&evidence)) {
            const std::string& chunk = mem->chunk;
            size_t pos = 0;
            while ((pos = chunk.find_first_of("0123456789", pos)) != std::string::npos) {
                size_t end = pos;
                int digits = 0;
                while (end < chunk.size() && digits < 19 && std::isdigit(chunk[end])) {
                    ++digits;
                    ++end;
                }
                if (digits >= 13 && digits <= 19) {
                    std::string card = chunk.substr(pos, digits);
                    findings.emplace_back(
                        runtimexray::FindingSeverity::High,
                        "Credit card number found in memory",
                        "Potential PAN data detected.",
                        runtimexray::MemorySecretFindingDetails{card, "credit_card", mem->location}
                    );
                    pos = end;
                } else {
                    pos = end;
                }
            }
        }
        return findings;
    }
};
```
{% endraw %}

**Value:** Automated PCI DSS compliance, reduced risk of cardholder data exposure.

---

## 2. Cloud Secret Scanner: AWS Access Key Detector

**Problem:** Developers sometimes hardcode cloud credentials (AWS, GCP, Azure) in configuration files or binary strings. These secrets can be exposed at runtime.

**Solution:** Implement an analyzer that recognizes known cloud credential prefixes and patterns.

{% raw %}
```cpp
#include <ianalyzer.hpp>
#include <evidence.hpp>
#include <finding.hpp>

class CloudCredentialAnalyzer : public runtimexray::IAnalyzer {
public:
    std::string name() const override { return "cloud_credentials"; }
    std::string description() const override {
        return "Detects AWS, GCP, and Azure credential patterns";
    }
    runtimexray::AnalyzerCategory category() const override {
        return runtimexray::AnalyzerCategory::Memory;
    }

    runtimexray::FindingList analyze(const runtimexray::Evidence& evidence) const override {
        runtimexray::FindingList findings;
        if (auto* mem = std::get_if<runtimexray::MemoryChunkEvidence>(&evidence)) {
            const std::string& chunk = mem->chunk;
            // Example: AWS Access Key ID pattern AKIA followed by 16 alphanumeric characters.
            size_t pos = 0;
            while ((pos = chunk.find("AKIA", pos)) != std::string::npos) {
                if (pos + 20 <= chunk.size()) {
                    std::string key = chunk.substr(pos, 20);
                    findings.emplace_back(
                        runtimexray::FindingSeverity::Critical,
                        "Cloud credential found",
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
{% endraw %}

**Value:** Prevents accidental cloud credential leaks, protects infrastructure.

---

## 3. Corporate Policy Enforcement: Banned Library Detector

**Problem:** A company policy prohibits the use of certain legacy or vulnerable libraries (e.g., old SSL versions). The security team needs automated enforcement.

**Solution:** Add a custom analyzer that flags any imported symbol from a banned list.

{% raw %}
```cpp
#include <ianalyzer.hpp>
#include <evidence.hpp>
#include <finding.hpp>

class PolicyAnalyzer : public runtimexray::IAnalyzer {
public:
    std::string name() const override { return "policy_enforcer"; }
    std::string description() const override {
        return "Detects banned imports according to internal policy";
    }
    runtimexray::AnalyzerCategory category() const override {
        return runtimexray::AnalyzerCategory::Static;
    }

    runtimexray::FindingList analyze(const runtimexray::Evidence& evidence) const override {
        runtimexray::FindingList findings;
        if (auto* sym = std::get_if<runtimexray::SymbolEvidence>(&evidence)) {
            static const std::vector<std::string> banned = {
                "SSLv3_client_method", "TLSv1_client_method", "MD5_Init", "RC4_set_key"
            };
            for (const auto& banned_sym : banned) {
                if (sym->symbol_name == banned_sym) {
                    findings.emplace_back(
                        runtimexray::FindingSeverity::High,
                        "Banned symbol imported: " + sym->symbol_name,
                        "Violates corporate security policy.",
                        runtimexray::DangerousApiFindingDetails{
                            sym->symbol_name,
                            "Forbidden by internal policy",
                            "Upgrade to approved alternative",
                            "POLICY-001"
                        }
                    );
                }
            }
        }
        return findings;
    }
};
```
{% endraw %}

**Value:** Continuous compliance with internal security policies.

---

## 4. Malware Analysis: IoC Scanner

**Problem:** Incident responders need to quickly identify indicators of compromise (IoCs) in running processes without recompiling the tool.

**Solution:** Register a temporary analyzer that scans for specific strings or patterns associated with a threat campaign.

{% raw %}
```cpp
#include <ianalyzer.hpp>
#include <evidence.hpp>
#include <finding.hpp>

class IocAnalyzer : public runtimexray::IAnalyzer {
public:
    std::string name() const override { return "ioc_scanner"; }
    std::string description() const override {
        return "Scans for specific indicators of compromise";
    }
    runtimexray::AnalyzerCategory category() const override {
        return runtimexray::AnalyzerCategory::Memory;
    }

    runtimexray::FindingList analyze(const runtimexray::Evidence& evidence) const override {
        runtimexray::FindingList findings;
        if (auto* mem = std::get_if<runtimexray::MemoryChunkEvidence>(&evidence)) {
            if (mem->chunk.find("malicious.command") != std::string::npos ||
                mem->chunk.find("cnc.example.com") != std::string::npos) {
                findings.emplace_back(
                    runtimexray::FindingSeverity::Critical,
                    "IoC detected in process memory",
                    "Known malicious indicator found.",
                    runtimexray::MemorySecretFindingDetails{
                        mem->chunk, "ioc", mem->location
                    }
                );
            }
        }
        return findings;
    }
};
```
{% endraw %}

**Value:** Accelerates incident response and threat hunting.

---

## 5. AI‑Assisted Explanation Post‑Processor

**Problem:** Security reports are often too technical for non‑expert stakeholders. An AI layer can translate findings into plain language.

**Solution:** Implement an analyzer that sends suspicious memory snippets to an LLM and returns a new Finding with the AI‑generated explanation.

{% raw %}
```cpp
#include <ianalyzer.hpp>
#include <evidence.hpp>
#include <finding.hpp>

#include <string>

// External HTTP client. In this example we use cpr, but you can replace it with
// libcurl, Boost.Beast, or any other library of your choice.
#include <cpr/cpr.h>

namespace {

/**
 * @brief Sends a snippet to an LLM API and returns the explanation text.
 *
 * Replace the URL, model name, and API key with your own values.
 * In production, store the API key in an environment variable or secure config.
 */
std::string call_ai_explainer(const std::string& snippet) {
    // Build the request body as JSON.
    nlohmann::json request_body = {
        {"model", "deepseek-chat"},
        {"messages", nlohmann::json::array({
            {{"role", "system"}, {"content", "Explain the security risk of this memory content in one sentence."}},
            {{"role", "user"}, {"content", snippet}}
        })},
        {"temperature", 0.2}
    };

    // Send the request to the LLM API.
    cpr::Response response = cpr::Post(
        cpr::Url{"https://api.deepseek.com/v1/chat/completions"},
        cpr::Header{{"Authorization", "Bearer " + std::getenv("DEEPSEEK_API_KEY")}},
        cpr::Body{request_body.dump()}
    );

    if (response.status_code == 200) {
        // Parse the JSON response and extract the assistant's message.
        nlohmann::json response_json = nlohmann::json::parse(response.text);
        if (response_json.contains("choices") && !response_json["choices"].empty()) {
            return response_json["choices"][0]["message"]["content"];
        }
    }
    return "AI explanation unavailable.";
}

} // anonymous namespace

class AiExplanationPostProcessor : public runtimexray::IAnalyzer {
public:
    std::string name() const override { return "ai_explainer"; }
    std::string description() const override {
        return "Uses an LLM to add human-readable explanations for memory secrets";
    }
    runtimexray::AnalyzerCategory category() const override {
        return runtimexray::AnalyzerCategory::Memory;
    }

    runtimexray::FindingList analyze(const runtimexray::Evidence& evidence) const override {
        runtimexray::FindingList findings;
        if (auto* mem = std::get_if<runtimexray::MemoryChunkEvidence>(&evidence)) {
            // Only process chunks that are likely to contain a secret.
            if (mem->chunk.find("password") != std::string::npos ||
                mem->chunk.find("secret") != std::string::npos) {
                std::string explanation = call_ai_explainer(mem->chunk);
                findings.emplace_back(
                    runtimexray::FindingSeverity::Info,
                    "AI-assisted analysis",
                    explanation,
                    runtimexray::MemorySecretFindingDetails{
                        mem->chunk,
                        "ai_explanation",
                        mem->location
                    }
                );
            }
        }
        return findings;
    }
};
```
{% endraw %}

**Value:** Makes findings accessible to developers, managers, and auditors.

---

## Summary

These use cases illustrate how the open analyzer interface turns RuntimeXRay into a flexible platform rather than a fixed tool. Users can address specific industry, regulatory, or organisational needs without waiting for upstream changes.

For more examples, see the [Extending Detectors](extending_detectors.md) document.