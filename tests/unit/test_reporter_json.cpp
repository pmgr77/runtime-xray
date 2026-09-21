#include "reporter.hpp"
#include "narrative_builder.hpp"

#include <cassert>
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

    const auto json_text = Reporter::to_json(report);

    const auto j = nlohmann::json::parse(json_text);

    assert(j["schema_version"] == "1.2");

    assert(j["narratives"].is_array());

    assert(j["narratives"].size() == 1);

    const auto& narrative = j["narratives"][0];

    assert(narrative["title"] == "Sensitive object observed from file to socket");

    assert(narrative["sessions"][0]["program"] == "./test-app");

    assert(narrative["statements"].size() == 3);

    assert(narrative["statements"][0]["evidence_observation_seqs"][0] == 3);

    assert(narrative["statements"][0]["evidence_observation_seqs"][1] == 2);

    return 0;
}
