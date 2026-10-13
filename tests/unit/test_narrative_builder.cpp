#include "narrative.hpp"
#include "narrative_builder.hpp"
#include "../test_check.hpp"

#include <iostream>

using namespace runtimexray;

int main()
{
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
    read.arg0 = 3;
    read.pid = 100;
    read.tid = 100;
    read.tgid = 100;
    read.process_instance_id = 1;
    read.exec_generation = 0;
    read.syscall_name = "read";
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
    memory.address = 0x12345000;
    memory.data_type = "memory";
    memory.secret_type = "password";
    memory.fingerprint = "fp-password";

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
    send.arg0 = 7;
    send.pid = 100;
    send.tid = 100;
    send.tgid = 100;
    send.process_instance_id = 1;
    send.exec_generation = 0;
    send.syscall_name = "sendto";
    send.fingerprint = "fp-password";

    graph.observations.push_back(send);

    Finding finding;

    finding.finding_id = 1;
    finding.rule_id = "test.sensitive_data_flow";
    finding.kind = "sensitive_data_flow";
    finding.severity = FindingSeverity::High;
    finding.title = "Sensitive object observed from file to socket";
    finding.summary = "test evidence";

    finding.attributes["secret_type"] = std::string("password");

    finding.attributes["fingerprint"] = std::string("fp-password");

    finding.evidence_observation_seqs = {
        3,
        4,
        6
    };

    FindingList findings;
    findings.push_back(
        std::move(finding));

    NarrativeBuilder builder;
    const auto stories = builder.build(graph, findings);

    CHECK(stories.size() == 1);

    const auto& story = stories[0];

    CHECK(story.finding_index == 0);
    CHECK(story.title == "Sensitive object observed from file to socket");
    CHECK(story.fingerprint == "fp-password");
    CHECK(story.sessions.size() == 1);

    CHECK(story.sessions[0].id.process_instance_id == 1);
    CHECK(story.sessions[0].id.exec_generation == 0);
    CHECK(story.sessions[0].program_name == "./test-app");

    CHECK(story.statements.size() == 3);

    CHECK(story.statements[0].evidence_observation_seqs.size() == 2);
    CHECK(story.statements[0].evidence_observation_seqs[0] == 3);
    CHECK(story.statements[0].evidence_observation_seqs[1] == 2);
    CHECK(story.statements[0].text.find("read") != std::string::npos);
    CHECK(story.statements[0].text.find("/tmp/cred.txt") != std::string::npos);

    CHECK(story.statements[1].evidence_observation_seqs.size() == 1);
    CHECK(story.statements[1].evidence_observation_seqs[0] == 4);
    CHECK(story.statements[1].text.find("memory") != std::string::npos);
    CHECK(story.statements[1].text.find("12345000") != std::string::npos);

    CHECK(story.statements[2].text.find("sendto") != std::string::npos);
    CHECK(story.statements[2].text.find("127.0.0.1:4444") != std::string::npos);
    CHECK(story.statements[2].evidence_observation_seqs.size() == 2);
    CHECK(story.statements[2].evidence_observation_seqs[0] == 6);
    CHECK(story.statements[2].evidence_observation_seqs[1] == 5);

    return 0;
}