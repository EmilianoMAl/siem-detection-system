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


def test_query_mitre_coverage_groups_by_technique_id():
    storage.insert_alerts([
        make_alert("ALERT-0001"),  # mitre_technique="T1110" por default de make_alert
        make_alert("ALERT-0002"),
    ])

    coverage = storage.query_mitre_coverage()

    assert coverage == [{"technique_id": "T1110", "count": 2}]


def test_query_mitre_coverage_ignores_missing_technique():
    alert = make_alert("ALERT-0001")
    alert.mitre_technique = ""
    storage.insert_alerts([alert])

    assert storage.query_mitre_coverage() == []


def test_geo_cache_roundtrip():
    assert storage.get_cached_geo(["45.33.32.156"]) == {}

    storage.save_geo("45.33.32.156", "Germany", "DE", "Berlin", 52.52, 13.4)
    cached = storage.get_cached_geo(["45.33.32.156", "1.2.3.4"])

    assert cached["45.33.32.156"]["country"] == "Germany"
    assert cached["45.33.32.156"]["lat"] == 52.52
    assert "1.2.3.4" not in cached


def test_get_attacker_geo_skips_private_ips_and_uses_cache(monkeypatch):
    storage.insert_events([
        make_event(source_ip="10.0.0.5"),               # privada -- se descarta
        make_event(source_ip="45.33.32.156"),
        make_event(source_ip="45.33.32.156"),
        make_event(source_ip="185.220.101.45"),
    ])
    storage.save_geo("45.33.32.156", "Germany", "DE", "Berlin", 52.52, 13.4)

    lookups = []
    def fake_lookup_ip(ip):
        lookups.append(ip)
        return {"country": "US", "country_code": "US", "city": "Ashburn", "lat": 39.0, "lon": -77.5}

    monkeypatch.setattr(storage, "lookup_ip", fake_lookup_ip)

    results = storage.get_attacker_geo()

    # 45.33.32.156 ya estaba en cache -> no debió volver a consultarse.
    assert lookups == ["185.220.101.45"]

    by_ip = {r["source_ip"]: r for r in results}
    assert by_ip["45.33.32.156"]["attempts"] == 2
    assert by_ip["45.33.32.156"]["country"] == "Germany"
    assert by_ip["185.220.101.45"]["country"] == "US"
    assert "10.0.0.5" not in by_ip


def test_get_attacker_geo_omits_ip_when_lookup_fails(monkeypatch):
    storage.insert_events([make_event(source_ip="162.142.125.0")])
    monkeypatch.setattr(storage, "lookup_ip", lambda ip: None)

    assert storage.get_attacker_geo() == []


def _age_row(table: str, column: str, value: str, days_ago: float) -> None:
    """Retrasa el created_at de una fila para simular que se insertó hace N días."""
    conn = storage.get_connection()
    conn.execute(
        f"UPDATE {table} SET created_at = datetime('now', ?) WHERE {column} = ?",
        (f"-{days_ago} days", value),
    )
    conn.commit()
    conn.close()


def test_time_range_clause_all_has_no_filter():
    clause, params = storage._time_range_clause("all")

    assert clause == ""
    assert params == ()


@pytest.mark.parametrize("time_range,modifier", [
    ("1h", "-1 hours"),
    ("24h", "-24 hours"),
    ("7d", "-7 days"),
    ("30d", "-30 days"),
    ("365d", "-365 days"),
])
def test_time_range_clause_builds_datetime_modifier(time_range, modifier):
    clause, params = storage._time_range_clause(time_range)

    assert clause == "AND created_at >= datetime('now', ?)"
    assert params == (modifier,)


def test_query_summary_excludes_old_events_by_time_range():
    storage.insert_events([
        make_event(source_ip="1.1.1.1"),
        make_event(source_ip="2.2.2.2"),
    ])
    _age_row("events", "source_ip", "2.2.2.2", days_ago=2)

    assert storage.query_summary(time_range="24h")["total_events"] == 1
    assert storage.query_summary(time_range="all")["total_events"] == 2


def test_query_top_ips_excludes_old_events_by_time_range():
    storage.insert_events([
        make_event(source_ip="1.1.1.1", event_type="failed_password"),
        make_event(source_ip="2.2.2.2", event_type="failed_password"),
    ])
    _age_row("events", "source_ip", "2.2.2.2", days_ago=2)

    recent_ips = {row["source_ip"] for row in storage.query_top_ips(time_range="24h")}
    all_ips = {row["source_ip"] for row in storage.query_top_ips(time_range="all")}

    assert recent_ips == {"1.1.1.1"}
    assert all_ips == {"1.1.1.1", "2.2.2.2"}


def test_query_event_types_excludes_old_events_by_time_range():
    storage.insert_events([
        make_event(event_type="failed_password"),
        make_event(event_type="sudo_command"),
    ])
    _age_row("events", "event_type", "sudo_command", days_ago=2)

    recent_types = {row["event_type"] for row in storage.query_event_types(time_range="24h")}
    all_types = {row["event_type"] for row in storage.query_event_types(time_range="all")}

    assert recent_types == {"failed_password"}
    assert all_types == {"failed_password", "sudo_command"}


def test_query_timeline_excludes_old_events_by_time_range():
    storage.insert_events([make_event(), make_event()])
    conn = storage.get_connection()
    conn.execute("UPDATE events SET created_at = datetime('now', '-2 days')")
    conn.commit()
    conn.close()

    assert storage.query_timeline(time_range="24h") == []
    assert len(storage.query_timeline(time_range="all")) > 0


def test_query_alerts_excludes_old_alerts_by_time_range():
    storage.insert_alerts([make_alert("ALERT-0001"), make_alert("ALERT-0002")])
    _age_row("alerts", "alert_id", "ALERT-0002", days_ago=2)

    recent_ids = {row["alert_id"] for row in storage.query_alerts(time_range="24h")}
    all_ids = {row["alert_id"] for row in storage.query_alerts(time_range="all")}

    assert recent_ids == {"ALERT-0001"}
    assert all_ids == {"ALERT-0001", "ALERT-0002"}
