#include "narrative.hpp"
#include "narrative_builder.hpp"

#include <cassert>
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

    Observation read;
    read.type = ObservationType::Event;
    read.seq = 2;
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
    memory.seq = 3;
    memory.pid = 100;
    memory.tid = 100;
    memory.tgid = 100;
    memory.process_instance_id = 1;
    memory.exec_generation = 0;
    memory.data_type = "memory";
    memory.secret_type = "password";
    memory.fingerprint = "fp-password";

    graph.observations.push_back(memory);

    Observation send;
    send.type = ObservationType::Event;
    send.seq = 4;
    send.pid = 100;
    send.tid = 100;
    send.tgid = 100;
    send.process_instance_id = 1;
    send.exec_generation = 0;
    send.syscall_name = "sendto";
    send.fingerprint = "fp-password";

    graph.observations.push_back(send);

    MemorySecretFindingDetails details;
    details.secret_type = "password";
    details.location = "correlated";
    details.fingerprint = "fp-password";

    Finding finding(
        FindingSeverity::High,
        "Sensitive object observed from file to socket",
        "test evidence",
        details,
        100);

    finding.evidence_observation_seqs = {
        2,
        3,
        4
    };

    FindingList findings;
    findings.push_back(
        std::move(finding));

    NarrativeBuilder builder;
    const auto stories = builder.build(graph, findings);

    assert(stories.size() == 1);

    const auto& story = stories[0];

    assert(story.finding_index == 0);
    assert(story.title == "Sensitive object observed from file to socket");
    assert(story.fingerprint == "fp-password");
    assert(story.session_ids.size() == 1);
    assert(story.session_ids[0].process_instance_id == 1);
    assert(story.session_ids[0].exec_generation == 0);
    assert(story.statements.size() == 3);

    assert(story.statements[0].evidence_observation_seqs[0] == 2);
    assert(story.statements[1].evidence_observation_seqs[0] == 3);
    assert(story.statements[2].evidence_observation_seqs[0] == 4);

    assert(story.statements[0].text.find("read") != std::string::npos);
    assert(story.statements[1].text.find("memory") != std::string::npos);
    assert(story.statements[2].text.find("sendto") != std::string::npos);
    
    return 0;
}