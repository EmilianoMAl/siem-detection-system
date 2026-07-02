from engine.agents import Agent
from engine.pipeline import ingest_lines


def test_ingest_lines_tags_agent_and_counts_unparsed():
    agent = Agent(
        agent_id="agent-001", hostname="prod-server-01", ip_address="10.0.0.5",
        os="Ubuntu 22.04 LTS", log_sources=["ssh"],
    )
    lines = [
        "Apr 03 10:23:45 prod-server-01 sshd[4521]: Failed password for root from 94.102.49.190 port 52341 ssh2",
        "this is not a valid auth.log line",
    ]

    events, unparsed = ingest_lines(agent, "ssh", lines)

    assert len(events) == 1
    assert unparsed == 1
    assert events[0].agent_id == "agent-001"
    assert events[0].source_ip == "94.102.49.190"


def test_ingest_lines_web_source():
    agent = Agent(
        agent_id="agent-002", hostname="web-server-02", ip_address="10.0.0.12",
        os="Ubuntu 22.04 LTS", log_sources=["web"],
    )
    lines = [
        '203.0.113.5 - - [03/Apr/2026:10:23:45 +0000] "GET / HTTP/1.1" 200 512 "-" "curl/8.0"',
    ]

    events, unparsed = ingest_lines(agent, "web", lines)

    assert len(events) == 1
    assert unparsed == 0
    assert events[0].agent_id == "agent-002"
    assert events[0].log_source == "web"
