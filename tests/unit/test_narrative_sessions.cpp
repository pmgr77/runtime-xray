#include "narrative.hpp"

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

    Observation brk;
    brk.type = ObservationType::Event;
    brk.seq = 4;
    brk.pid = 100;
    brk.tid = 100;
    brk.tgid = 100;
    brk.process_instance_id = 1;
    brk.exec_generation = 1;
    brk.syscall_name = "brk";

    graph.observations.push_back(brk);

    const auto sessions = build_narrative_sessions(graph);
    assert(sessions.size() == 2);
    const auto& s0 = sessions[0];
    assert(s0.id.process_instance_id == 1);
    assert(s0.id.exec_generation == 0);
    assert(s0.program_name == "./original");
    assert(s0.observation_seqs.size() == 2);
    assert(s0.observation_seqs[0] == 2);
    assert(s0.observation_seqs[1] == 3);
    assert(s0.first_seq == 2);
    assert(s0.last_seq == 3);
    assert(s0.tgid == 100);

    const auto& s1 = sessions[1];
    assert(s1.id.process_instance_id == 1);
    assert(s1.id.exec_generation == 1);
    assert(s1.program_name == "/bin/echo");
    assert(s1.observation_seqs.size() == 1);
    assert(s1.observation_seqs[0] == 4);
    assert(s1.first_seq == 4);
    assert(s1.last_seq == 4);
    assert(s1.tgid == 100);

    std::cout << "Narrative session tests passed\n";

    return 0;
}