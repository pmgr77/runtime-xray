#include "reporter.hpp"
#include "narrative_builder.hpp"

#include <cassert>
#include <set>
#include <nlohmann/json.hpp>

using namespace runtimexray;

int main()
{
    Report report;

    report.context.command = "trace";
    report.context.target = "./test-app";

    NarrativeStory story;
    story.finding_index = 0;
    story.title = "Sensitive object observed from file to socket";
    story.fingerprint = "fp-password";

    NarrativeSessionContext session;
    session.id.process_instance_id = 1;
    session.id.exec_generation = 0;
    session.program_name = "./test-app";

    story.sessions.push_back(session);

    NarrativeStatement read_statement;
    read_statement.text = "A password value was observed in data returned by read().";
    read_statement.evidence_observation_seqs = { 3, 2 };

    NarrativeStatement memory_statement;
    memory_statement.text = "The same fingerprinted value was also found in process memory.";
    memory_statement.evidence_observation_seqs = { 4 };

    NarrativeStatement send_statement;
    send_statement.text = "The same fingerprinted value was observed in data supplied to sendto().";
    send_statement.evidence_observation_seqs = { 6, 5 };

    story.statements.push_back(std::move(read_statement));
    story.statements.push_back(std::move(memory_statement));
    story.statements.push_back(std::move(send_statement));
    report.narratives.push_back(std::move(story));

    LineageGraph graph;

    Observation process;
    process.type = ObservationType::Event;
    process.seq = 1;
    process.pid = 100;
    process.tid = 100;
    process.tgid = 100;
    process.process_instance_id = 1;
    process.exec_generation = 0;
    process.syscall_name = "process";
    process.program_name = "./test-app";

    graph.observations.push_back(process);

    Observation open;
    open.type = ObservationType::Event;
    open.seq = 2;
    open.pid = 100;
    open.tid = 100;
    open.tgid = 100;
    open.process_instance_id = 1;
    open.exec_generation = 0;
    open.syscall_name = "openat";
    open.return_value = 3;
    open.source = "/tmp/cred.txt";

    graph.observations.push_back(open);

    Observation read;
    read.type = ObservationType::Event;
    read.seq = 3;
    read.pid = 100;
    read.tid = 100;
    read.tgid = 100;
    read.process_instance_id = 1;
    read.exec_generation = 0;
    read.syscall_name = "read";
    read.arg0 = 3;
    read.return_value = 20;
    read.fingerprint = "fp-password";

    graph.observations.push_back(read);

    Observation memory;
    memory.type = ObservationType::Data;
    memory.seq = 4;
    memory.pid = 100;
    memory.tid = 100;
    memory.tgid = 100;
    memory.process_instance_id = 1;
    memory.exec_generation = 0;
    memory.data_type = "memory";
    memory.secret_type = "password";
    memory.fingerprint = "fp-password";
    memory.address = 0x12345000;

    graph.observations.push_back(memory);

    Observation connect;
    connect.type = ObservationType::Event;
    connect.seq = 5;
    connect.pid = 100;
    connect.tid = 100;
    connect.tgid = 100;
    connect.process_instance_id = 1;
    connect.exec_generation = 0;
    connect.syscall_name = "connect";
    connect.arg0 = 7;
    connect.return_value = 0;
    connect.source = "127.0.0.1:4444";

    graph.observations.push_back(connect);

    Observation send;
    send.type = ObservationType::Event;
    send.seq = 6;
    send.pid = 100;
    send.tid = 100;
    send.tgid = 100;
    send.process_instance_id = 1;
    send.exec_generation = 0;
    send.syscall_name = "sendto";
    send.arg0 = 7;
    send.return_value = 20;
    send.fingerprint = "fp-password";

    graph.observations.push_back(send);

    report.lineage_graph = graph;

    Finding finding;

    finding.finding_id = 1;
    finding.rule_id = "test.sensitive_data_flow";
    finding.kind = "sensitive_data_flow";
    finding.severity = FindingSeverity::High;
    finding.title = "Sensitive object observed from file to socket";
    finding.summary = "test evidence";

    finding.attributes["secret_type"] =
        std::string("password");

    finding.attributes["fingerprint"] =
        std::string("fp-password");

    finding.evidence_observation_seqs = {
        3,
        4,
        6
    };

    report.findings.push_back(std::move(finding));

    const auto json_text = Reporter::to_json(report);

    const auto j = nlohmann::json::parse(json_text);

    assert(j["schema_version"] == "2.0");

    assert(j["narratives"].is_array());

    assert(j["narratives"].size() == 1);

    const auto& narrative = j["narratives"][0];

    assert(narrative["title"] == "Sensitive object observed from file to socket");

    assert(narrative["sessions"][0]["program"] == "./test-app");

    assert(narrative["statements"].size() == 3);

    assert(narrative["statements"][0]["evidence_observation_seqs"][0] == 3);

    assert(narrative["statements"][0]["evidence_observation_seqs"][1] == 2);

    assert(j["lineage"].is_object());
    assert(j["lineage"]["observations"].is_array());
    assert(j["lineage"]["observations"].size() == 6);
    assert(j["lineage"]["edges"].is_array());

    // Verify one observation:
    assert(j["lineage"]["observations"][1]["seq"] == 2);
    assert(j["lineage"]["observations"][1]["syscall"] == "openat");
    assert(j["lineage"]["observations"][1]["source"] == "/tmp/cred.txt");
    
    // Build the stable-seq set:
    std::set<uint64_t> observation_seqs;
    for (const auto& obs : j["lineage"]["observations"]) {
        observation_seqs.insert(obs["seq"].get<uint64_t>());
    }

    // Check all finding refs:
    for (const auto& finding_json : j["findings"]) {
        for (const auto& seq_json : finding_json["evidence_observation_seqs"]) {
            const uint64_t seq = seq_json.get<uint64_t>();
            assert(observation_seqs.count(seq) == 1);
        }
    }
    
    // Check all narrative refs:
    for (const auto& narrative_json : j["narratives"]) {
        for (const auto& statement_json : narrative_json["statements"]) {
            for (const auto& seq_json : statement_json["evidence_observation_seqs"]) {
                const uint64_t seq = seq_json.get<uint64_t>();
                assert(observation_seqs.count(seq) == 1);
            }
        }
    }

    return 0;
}
