import asyncio
import json

import pytest

from engine import storage
from engine.syslog_listener import process_syslog_batch

LINE_LOGIN_DENIED = (
    'id=firewall sn=18C24173CD98 time="2026-06-30 15:29:31 UTC" fw=201.151.192.156 '
    'pri=4 c=16 m=986 msg="User login denied - not allowed by Policy rule" dur=0 '
    'n=42640 src=172.16.140.73:50590:X0 '
    'dst=100.50.144.145:443:X1:ec2-100-50-144-145.compute-1.amazonaws.com '
    'proto=tcp/https note="Unknown user, authentication by SSO Agent" fw_action="NA"'
)

# Línea real como la que manda un rsyslog estándar (`*.* @@host:514`)
# reenviando el auth.log de una VM Linux cliente -- con <PRI> incluido.
LINE_SSH_FAILED_PASSWORD = (
    "<38>Jul  3 18:30:01 client-vm sshd[2049]: "
    "Failed password for invalid user admin from 203.0.113.9 port 4444 ssh2"
)

LINE_GENERIC_SYSLOG = "<86>Jul  3 18:31:00 client-vm CRON[9001]: (root) CMD (run-backup.sh)"

TEST_SENDER_IP = "198.51.100.7"
TEST_SENDER_AGENT_ID = "agent-syslog-198-51-100-7"  # autogenerado por resolve_syslog_agent, IP no configurada

OTHER_SENDER_IP = "203.0.113.200"
OTHER_SENDER_AGENT_ID = "agent-syslog-203-0-113-200"


def _pkts(lines: list[str], sender_ip: str = TEST_SENDER_IP) -> list[tuple[str, str]]:
    return [(line, sender_ip) for line in lines]


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "test_siem.db")
    monkeypatch.delenv("SENTINEL_SYSLOG_CLIENTS", raising=False)
    monkeypatch.delenv("SENTINEL_WAZUH_AGENTS", raising=False)
    storage.initialize_db()
    yield


def test_process_syslog_batch_inserts_event_tagged_real_vm():
    asyncio.run(process_syslog_batch(_pkts([LINE_LOGIN_DENIED])))

    assert storage.query_summary(environment="real_vm")["total_events"] == 1
    assert storage.query_summary(environment="simulated")["total_events"] == 0


def test_process_syslog_batch_auto_registers_agent_by_sender_ip():
    asyncio.run(process_syslog_batch(_pkts([LINE_LOGIN_DENIED])))

    agents = storage.query_agents(environment="real_vm")
    assert TEST_SENDER_AGENT_ID in [a["agent_id"] for a in agents]


def test_process_syslog_batch_triggers_alert_above_threshold():
    asyncio.run(process_syslog_batch(_pkts([LINE_LOGIN_DENIED] * 6)))

    alerts = storage.query_alerts(environment="real_vm")
    assert any(a["rule_name"] == "SONICWALL_REPEATED_DENIALS" for a in alerts)


def test_process_syslog_batch_below_threshold_does_not_alert():
    asyncio.run(process_syslog_batch(_pkts([LINE_LOGIN_DENIED] * 2)))

    alerts = storage.query_alerts(environment="real_vm")
    assert not any(a["rule_name"] == "SONICWALL_REPEATED_DENIALS" for a in alerts)


def test_process_syslog_batch_ignores_unparseable_lines():
    asyncio.run(process_syslog_batch(_pkts(["not a syslog line at all"])))

    assert storage.query_summary(environment="ALL")["total_events"] == 0


def test_process_syslog_batch_empty_list_is_noop():
    asyncio.run(process_syslog_batch([]))

    assert storage.query_summary(environment="ALL")["total_events"] == 0


def test_process_syslog_batch_recognizes_forwarded_ssh_line():
    asyncio.run(process_syslog_batch(_pkts([LINE_SSH_FAILED_PASSWORD])))

    events = storage.query_event_types(environment="real_vm")
    assert {e["event_type"] for e in events} == {"failed_password"}


def test_process_syslog_batch_triggers_ssh_brute_force_on_forwarded_auth_log():
    asyncio.run(process_syslog_batch(_pkts([LINE_SSH_FAILED_PASSWORD] * 6)))

    alerts = storage.query_alerts(environment="real_vm")
    assert any(a["rule_name"] == "SSH_BRUTE_FORCE" for a in alerts)


def test_process_syslog_batch_falls_back_to_generic_syslog():
    asyncio.run(process_syslog_batch(_pkts([LINE_GENERIC_SYSLOG])))

    events = storage.query_event_types(environment="real_vm")
    assert {e["event_type"] for e in events} == {"syslog_message"}


def test_process_syslog_batch_handles_mixed_formats_in_one_batch():
    asyncio.run(process_syslog_batch(_pkts([
        LINE_SSH_FAILED_PASSWORD, LINE_LOGIN_DENIED, LINE_GENERIC_SYSLOG,
    ])))

    summary = storage.query_summary(environment="real_vm")
    assert summary["total_events"] == 3


def test_process_syslog_batch_records_real_sender_ip_in_metadata():
    asyncio.run(process_syslog_batch([(LINE_GENERIC_SYSLOG, "203.0.113.55")]))

    conn = storage.get_connection()
    row = conn.execute(
        "SELECT metadata FROM events WHERE agent_id = 'agent-syslog-203-0-113-55'"
    ).fetchone()
    conn.close()

    assert json.loads(row["metadata"])["sender_ip"] == "203.0.113.55"


def test_process_syslog_batch_sender_ip_does_not_override_parsed_source_ip():
    # source_ip (la IP atacante que trae el propio log) y sender_ip (quién
    # mandó el paquete UDP) son cosas distintas -- una no debe pisar la otra.
    asyncio.run(process_syslog_batch([(LINE_SSH_FAILED_PASSWORD, "10.0.0.99")]))

    conn = storage.get_connection()
    row = conn.execute(
        "SELECT source_ip, metadata FROM events WHERE agent_id = 'agent-syslog-10-0-0-99'"
    ).fetchone()
    conn.close()

    assert row["source_ip"] == "203.0.113.9"
    assert json.loads(row["metadata"])["sender_ip"] == "10.0.0.99"


def test_process_syslog_batch_splits_two_senders_into_two_agents_without_mixing():
    # Un mismo lote de 15s puede traer líneas de dos clientes distintos a
    # la vez (ej. la VM Linux y una VM de Windows) -- no deben mezclarse
    # bajo un solo agente.
    packets = _pkts([LINE_SSH_FAILED_PASSWORD], TEST_SENDER_IP) + _pkts([LINE_GENERIC_SYSLOG], OTHER_SENDER_IP)

    asyncio.run(process_syslog_batch(packets))

    agents = {a["agent_id"]: a for a in storage.query_agents(environment="real_vm")}
    assert agents[TEST_SENDER_AGENT_ID]["event_count"] == 1
    assert agents[OTHER_SENDER_AGENT_ID]["event_count"] == 1


def test_process_syslog_batch_autogenerated_agent_uses_claimed_hostname():
    # Sin SENTINEL_SYSLOG_CLIENTS configurado, el agente autogenerado
    # debe usar el hostname que el propio mensaje trae (ej. "client-vm"
    # extraído por auth_parser) en vez de solo la IP -- se resuelve
    # DESPUÉS de parsear, no antes.
    asyncio.run(process_syslog_batch(_pkts([LINE_SSH_FAILED_PASSWORD])))

    agents = {a["agent_id"]: a for a in storage.query_agents(environment="real_vm")}
    assert agents[TEST_SENDER_AGENT_ID]["hostname"] == "client-vm"


def test_process_syslog_batch_uses_configured_client_name(monkeypatch):
    monkeypatch.setenv(
        "SENTINEL_SYSLOG_CLIENTS",
        json.dumps({TEST_SENDER_IP: {"agent_id": "agent-linux-wazuh", "hostname": "wazuh-srv", "os": "Ubuntu Linux"}}),
    )

    asyncio.run(process_syslog_batch(_pkts([LINE_GENERIC_SYSLOG])))

    agents = storage.query_agents(environment="real_vm")
    by_id = {a["agent_id"]: a for a in agents}
    assert "agent-linux-wazuh" in by_id
    assert by_id["agent-linux-wazuh"]["hostname"] == "wazuh-srv"


def _wazuh_line(agent_id: str, agent_name: str, agent_ip: str, description: str) -> str:
    alert = {
        "timestamp": "2026-07-08T09:00:00.000-0600",
        "rule": {"level": 5, "description": description, "id": "61138", "groups": ["windows"]},
        "agent": {"id": agent_id, "name": agent_name, "ip": agent_ip},
        "manager": {"name": "wazuh-srv-Virtual-Machine"},
        "full_log": description,
    }
    return f"<132>Jul  8 09:00:00 wazuh-srv-Virtual-Machine ossec: {json.dumps(alert)}"


def test_process_syslog_batch_attributes_remote_wazuh_agent_separately_from_manager():
    # Un manager de Wazuh reenvía por syslog tanto sus propias alertas
    # (agent.id "000") como las de cualquier endpoint remoto que tenga
    # enrolado (ej. un Windows) -- ambas llegan del mismo remitente UDP
    # (el manager), no deben mezclarse bajo un solo agente SENTINEL.
    packets = _pkts([
        _wazuh_line("000", "wazuh-srv-Virtual-Machine", "127.0.0.1", "Dpkg installed"),
        _wazuh_line("005", "DESKTOP-GULVC64", "172.16.134.150", "New Windows Service Created"),
        _wazuh_line("005", "DESKTOP-GULVC64", "172.16.134.150", "Inconsistent system shutdown"),
    ])

    asyncio.run(process_syslog_batch(packets))

    agents = {a["agent_id"]: a for a in storage.query_agents(environment="real_vm")}
    assert agents[TEST_SENDER_AGENT_ID]["event_count"] == 1  # el manager, agente autogenerado por IP
    assert agents["agent-wazuh-005"]["event_count"] == 2
    assert agents["agent-wazuh-005"]["hostname"] == "DESKTOP-GULVC64"


def test_process_syslog_batch_uses_configured_wazuh_agent_identity(monkeypatch):
    monkeypatch.setenv(
        "SENTINEL_WAZUH_AGENTS",
        json.dumps({"005": {"agent_id": "agent-windows-wazuh", "hostname": "DESKTOP-GULVC64", "os": "Windows 11"}}),
    )

    asyncio.run(process_syslog_batch(_pkts([
        _wazuh_line("005", "DESKTOP-GULVC64", "172.16.134.150", "New Windows Service Created"),
    ])))

    agents = {a["agent_id"]: a for a in storage.query_agents(environment="real_vm")}
    assert "agent-windows-wazuh" in agents
    assert agents["agent-windows-wazuh"]["os"] == "Windows 11"


def test_process_syslog_batch_wazuh_fim_alert_triggers_critical_alert():
    # Extremo a extremo: una alerta de syscheck de Wazuh sobre /usr/bin
    # llega por syslog, se parsea como evento FIM y dispara
    # FIM_CRITICAL_FILE_CHANGE -- sin ninguna regla de detección nueva.
    syscheck_alert = {
        "timestamp": "2026-07-08T10:00:00.000-0600",
        "rule": {"level": 7, "description": "File added to the system.", "id": "550", "groups": ["ossec", "syscheck"]},
        "agent": {"id": "001", "name": "wazuh-srv-Virtual-Machine"},
        "syscheck": {"path": "/usr/bin/evil", "event": "added", "md5_before": None, "md5_after": "abc123"},
        "full_log": "File '/usr/bin/evil' added",
    }
    line = f"<38>Jul  8 10:00:00 wazuh-srv-Virtual-Machine ossec: {json.dumps(syscheck_alert)}"

    asyncio.run(process_syslog_batch(_pkts([line])))

    events = storage.query_event_types(environment="real_vm")
    assert {e["event_type"] for e in events} == {"fim_created"}

    alerts = storage.query_alerts(environment="real_vm")
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "FIM_CRITICAL_FILE_CHANGE"
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["mitre_technique"] == "T1554 - Compromise Client Software Binary"
