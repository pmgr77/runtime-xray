#include "narrative.hpp"
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
    process.program_name = "./original";

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

    Observation exec;
    exec.type = ObservationType::Event;
    exec.seq = 3;
    exec.pid = 100;
    exec.tid = 100;
    exec.tgid = 100;
    exec.process_instance_id = 1;
    exec.exec_generation = 0;
    exec.syscall_name = "execve";
    exec.program_name = "/bin/echo";
    exec.return_value = 0;

    graph.observations.push_back(exec);

    Observation memory;
    memory.type = ObservationType::Data;
    memory.seq = 4;
    memory.pid = 100;
    memory.tid = 100;
    memory.tgid = 100;
    memory.process_instance_id = 1;
    memory.exec_generation = 1;
    memory.data_type = "memory";
    memory.secret_type = "password";
    memory.fingerprint = "fp-password";

    graph.observations.push_back(memory);

    Observation brk;
    brk.type = ObservationType::Event;
    brk.seq = 5;
    brk.pid = 100;
    brk.tid = 100;
    brk.tgid = 100;
    brk.process_instance_id = 1;
    brk.exec_generation = 1;
    brk.syscall_name = "brk";

    graph.observations.push_back(brk);

    Observation token_memory;
    token_memory.type = ObservationType::Data;
    token_memory.seq = 6;
    token_memory.pid = 100;
    token_memory.tid = 100;
    token_memory.tgid = 100;
    token_memory.process_instance_id = 1;
    token_memory.exec_generation = 1;
    token_memory.data_type = "memory";
    token_memory.secret_type = "token";
    token_memory.fingerprint = "fp-token";

    graph.observations.push_back(token_memory);

    auto sessions = build_narrative_sessions(graph);
    CHECK(sessions.size() == 2);
    const auto& s0 = sessions[0];
    CHECK(s0.id.process_instance_id == 1);
    CHECK(s0.id.exec_generation == 0);
    CHECK(s0.program_name == "./original");
    CHECK(s0.observation_seqs.size() == 2);
    CHECK(s0.observation_seqs[0] == 2);
    CHECK(s0.observation_seqs[1] == 3);
    CHECK(s0.first_seq == 2);
    CHECK(s0.last_seq == 3);
    CHECK(s0.tgid == 100);

    const auto& s1 = sessions[1];
    CHECK(s1.id.process_instance_id == 1);
    CHECK(s1.id.exec_generation == 1);
    CHECK(s1.program_name == "/bin/echo");
    CHECK(s1.observation_seqs.size() == 3);
    CHECK(s1.observation_seqs[0] == 4);
    CHECK(s1.observation_seqs[1] == 5);
    CHECK(s1.observation_seqs[2] == 6);
    CHECK(s1.first_seq == 4);
    CHECK(s1.last_seq == 6);
    CHECK(s1.tgid == 100);

    Finding single_session_finding;

    single_session_finding.finding_id = 1;
    single_session_finding.rule_id = "test.single_session";
    single_session_finding.kind = "test_finding";
    single_session_finding.severity = FindingSeverity::High;
    single_session_finding.title = "Single-session finding";
    single_session_finding.summary = "test";
    single_session_finding.attributes["secret_type"] =
        std::string("password");

    single_session_finding.evidence_observation_seqs = {
        2
    };

    Finding cross_session_finding;

    cross_session_finding.finding_id = 2;
    cross_session_finding.rule_id = "test.cross_session";
    cross_session_finding.kind = "test_finding";
    cross_session_finding.severity = FindingSeverity::High;
    cross_session_finding.title = "Cross-session finding";
    cross_session_finding.summary = "test";
    cross_session_finding.attributes["secret_type"] =
        std::string("password");

    cross_session_finding.evidence_observation_seqs = {
        2,
        3,
        4
    };

    FindingList findings;
    findings.push_back(std::move(single_session_finding));
    findings.push_back(std::move(cross_session_finding));

    associate_findings_with_sessions(findings, sessions);

    const auto& session0 = sessions[0];
    const auto& session1 = sessions[1];

    CHECK(session0.finding_refs.size() == 2);
    CHECK(session0.finding_refs[0].finding_index == 0);
    CHECK(session0.finding_refs[0].evidence_observation_seqs.size() == 1);
    CHECK(session0.finding_refs[0].evidence_observation_seqs[0] == 2);

    CHECK(session0.finding_refs[1].finding_index == 1);
    CHECK(session0.finding_refs[1].evidence_observation_seqs.size() == 2);
    CHECK(session0.finding_refs[1].evidence_observation_seqs[0] == 2);
    CHECK(session0.finding_refs[1].evidence_observation_seqs[1] == 3);

    CHECK(session1.finding_refs.size() == 1);
    CHECK(session1.finding_refs[0].finding_index == 1);
    CHECK(session1.finding_refs[0].evidence_observation_seqs.size() == 1);
    CHECK(session1.finding_refs[0].evidence_observation_seqs[0] == 4);

    const auto histories = build_value_histories(graph);
    CHECK(histories.size() == 2);
    const auto& password_history = histories[0];
    CHECK(password_history.fingerprint == "fp-password");
    CHECK(password_history.secret_type == "password");
    CHECK(password_history.first_seq == 2);
    CHECK(password_history.last_seq == 4);
    CHECK(password_history.occurrences.size() == 2);

    const auto& password_read = password_history.occurrences[0];
    CHECK(password_read.observation_seq == 2);
    CHECK(password_read.process_instance_id == 1);
    CHECK(password_read.exec_generation == 0);
    CHECK(password_read.observation_type == ObservationType::Event);
    CHECK(password_read.syscall_name == "read");

    const auto& password_memory = password_history.occurrences[1];
    CHECK(password_memory.observation_seq == 4);
    CHECK(password_memory.process_instance_id == 1);
    CHECK(password_memory.exec_generation == 1);
    CHECK(password_memory.observation_type == ObservationType::Data);
    CHECK(password_memory.data_type == "memory");

    const auto& token_history = histories[1];
    CHECK(token_history.fingerprint == "fp-token");
    CHECK(token_history.secret_type == "token");
    CHECK(token_history.first_seq == 6);
    CHECK(token_history.last_seq == 6);
    CHECK(token_history.occurrences.size() == 1);

    const auto& token_occurrence = token_history.occurrences[0];
    CHECK(token_occurrence.observation_seq == 6);
    CHECK(token_occurrence.process_instance_id == 1);
    CHECK(token_occurrence.exec_generation == 1);
    CHECK(token_occurrence.observation_type == ObservationType::Data);
    CHECK(token_occurrence.data_type == "memory");

    associate_findings_with_sessions(findings, sessions);
    CHECK(sessions[0].finding_refs.size() == 2);
    CHECK(sessions[1].finding_refs.size() == 1);

    std::cout << "Narrative model tests passed\n";

    return 0;
}