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


def test_query_generic_groups_events_by_source_ip():
    storage.insert_events([
        make_event(source_ip="1.1.1.1"),
        make_event(source_ip="1.1.1.1"),
        make_event(source_ip="2.2.2.2"),
    ])

    rows = storage.query_generic("events", "source_ip")

    assert rows[0] == {"label": "1.1.1.1", "value": 2}
    assert rows[1] == {"label": "2.2.2.2", "value": 1}


def test_query_generic_filters_events_by_log_source():
    storage.insert_events([
        make_event(source_ip="1.1.1.1", log_source="ssh"),
        make_event(source_ip="2.2.2.2", log_source="web", event_type="http_request"),
    ])

    rows = storage.query_generic("events", "source_ip", log_source="WEB")

    assert rows == [{"label": "2.2.2.2", "value": 1}]


def test_query_generic_groups_alerts_by_severity():
    alert = Alert(
        alert_id="ALERT-0001", rule_name="SSH_BRUTE_FORCE", severity="HIGH",
        description="test", source_ip="1.2.3.4", username="root",
        hostname="prod-server-01", evidence=["line1"],
        recommendation="block ip", mitre_technique="T1110",
    )
    storage.insert_alerts([alert])

    rows = storage.query_generic("alerts", "severity")

    assert rows == [{"label": "HIGH", "value": 1}]


def test_query_generic_rejects_unknown_dataset():
    with pytest.raises(ValueError):
        storage.query_generic("not_a_dataset", "source_ip")


def test_query_generic_rejects_unknown_group_by():
    with pytest.raises(ValueError):
        storage.query_generic("events", "not_a_column")


def test_dashboard_crud_roundtrip():
    layout = [{"id": "w1", "x": 0, "y": 0, "w": 4, "h": 4, "config": {"chartType": "bar"}}]

    dashboard_id = storage.save_dashboard("My dashboard", layout)
    saved = storage.get_dashboard(dashboard_id)

    assert saved["name"] == "My dashboard"
    assert saved["layout"] == layout

    assert storage.update_dashboard(dashboard_id, "Renamed", layout) is True
    assert storage.get_dashboard(dashboard_id)["name"] == "Renamed"

    listed = storage.list_dashboards()
    assert len(listed) == 1
    assert listed[0]["name"] == "Renamed"

    assert storage.delete_dashboard(dashboard_id) is True
    assert storage.get_dashboard(dashboard_id) is None


def test_update_and_delete_missing_dashboard_return_false():
    assert storage.update_dashboard(999, "x", []) is False
    assert storage.delete_dashboard(999) is False


def make_alert(alert_id: str) -> Alert:
    return Alert(
        alert_id=alert_id, rule_name="SSH_BRUTE_FORCE", severity="HIGH",
        description="test", source_ip="1.2.3.4", username="root",
        hostname="prod-server-01", evidence=["line1"],
        recommendation="block ip", mitre_technique="T1110",
    )


def test_get_max_alert_counter_empty_db_returns_zero():
    assert storage.get_max_alert_counter() == 0


def test_get_max_alert_counter_reads_highest_suffix():
    storage.insert_alerts([make_alert("ALERT-0001"), make_alert("ALERT-0042")])

    assert storage.get_max_alert_counter() == 42


def test_new_alert_defaults_to_open_status():
    storage.insert_alerts([make_alert("ALERT-0001")])

    alerts = storage.query_alerts()

    assert alerts[0]["status"] == "OPEN"
    assert alerts[0]["resolved_at"] is None


def test_update_alert_status_to_acknowledged():
    storage.insert_alerts([make_alert("ALERT-0001")])

    updated = storage.update_alert_status("ALERT-0001", "ACKNOWLEDGED", note="looking into it")

    assert updated["status"] == "ACKNOWLEDGED"
    assert updated["note"] == "looking into it"
    assert updated["resolved_at"] is None


def test_update_alert_status_to_closed_sets_resolved_at():
    storage.insert_alerts([make_alert("ALERT-0001")])

    updated = storage.update_alert_status("ALERT-0001", "CLOSED")

    assert updated["status"] == "CLOSED"
    assert updated["resolved_at"] is not None


def test_update_alert_status_unknown_id_returns_none():
    assert storage.update_alert_status("ALERT-9999", "CLOSED") is None


def test_query_alerts_filters_by_status():
    storage.insert_alerts([make_alert("ALERT-0001"), make_alert("ALERT-0002")])
    storage.update_alert_status("ALERT-0002", "CLOSED")

    open_alerts = storage.query_alerts(status="OPEN")
    closed_alerts = storage.query_alerts(status="CLOSED")

    assert [a["alert_id"] for a in open_alerts] == ["ALERT-0001"]
    assert [a["alert_id"] for a in closed_alerts] == ["ALERT-0002"]


def test_additive_migration_preserves_existing_alerts(tmp_path, monkeypatch):
    """
    A diferencia de la migración destructiva de 'events', 'alerts' con
    datos reales no se puede recrear -- initialize_db() debe agregar las
    columnas nuevas sin perder filas existentes.
    """
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "legacy.db")
    conn = storage.get_connection()
    conn.executescript("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT, source_ip TEXT, username TEXT, hostname TEXT,
            evidence TEXT, recommendation TEXT, mitre_technique TEXT,
            detected_at TEXT, created_at TEXT DEFAULT (datetime('now'))
        );
        INSERT INTO alerts (alert_id, rule_name, severity)
            VALUES ('ALERT-0001', 'SSH_BRUTE_FORCE', 'HIGH');
    """)
    conn.commit()
    conn.close()

    storage.initialize_db()

    alerts = storage.query_alerts()
    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "ALERT-0001"
    assert alerts[0]["status"] == "OPEN"
