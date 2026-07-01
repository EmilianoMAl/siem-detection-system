import pytest

from engine import storage
from engine.agents import Agent
from engine.parsers.auth_parser import LogEvent
from engine.detectors.rules import Alert


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Redirige storage.DB_PATH a un archivo temporal para no tocar data/siem.db."""
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "test_siem.db")
    storage.initialize_db()
    yield


def make_event(**overrides) -> LogEvent:
    defaults = dict(
        raw_line="raw", timestamp="Apr 03 10:23:45", hostname="prod-server-01",
        service="sshd", pid=1234, event_type="failed_password", username="root",
        source_ip="94.102.49.190", source_port=52341, command=None,
        agent_id="agent-001", log_source="ssh", metadata={"foo": "bar"},
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


def test_insert_and_query_events_summary():
    events = [make_event(), make_event(event_type="accepted_password")]
    storage.insert_events(events)

    summary = storage.query_events_summary()

    assert summary["total_events"] == 2
    assert summary["failed_logins"] == 1
    assert summary["successful_logins"] == 1


def test_insert_alerts_deduplicates_by_alert_id():
    alert = Alert(
        alert_id="ALERT-0001", rule_name="SSH_BRUTE_FORCE", severity="HIGH",
        description="test", source_ip="1.2.3.4", username="root",
        hostname="prod-server-01", evidence=["line1"],
        recommendation="block ip", mitre_technique="T1110",
    )

    inserted_first = storage.insert_alerts([alert])
    inserted_second = storage.insert_alerts([alert])

    assert inserted_first == 1
    assert inserted_second == 0


def test_register_agents_and_touch_agent():
    agent = Agent(
        agent_id="agent-001", hostname="prod-server-01", ip_address="10.0.0.5",
        os="Ubuntu 22.04 LTS", log_sources=["ssh", "fim"],
    )
    storage.register_agents([agent])
    storage.touch_agent("agent-001")

    agents = storage.query_agents()

    assert len(agents) == 1
    assert agents[0]["agent_id"] == "agent-001"
    assert agents[0]["status"] == "ACTIVE"
    assert agents[0]["log_sources"] == ["ssh", "fim"]


def test_query_agents_reports_never_connected():
    agent = Agent(
        agent_id="agent-002", hostname="web-server-02", ip_address="10.0.0.12",
        os="Ubuntu 22.04 LTS", log_sources=["ssh", "web"],
    )
    storage.register_agents([agent])

    agents = storage.query_agents()

    assert agents[0]["status"] == "NEVER_CONNECTED"
