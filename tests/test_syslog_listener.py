import asyncio

import pytest

from engine import storage
from engine.agents import get_syslog_agent
from engine.syslog_listener import process_syslog_batch

LINE_LOGIN_DENIED = (
    'id=firewall sn=18C24173CD98 time="2026-06-30 15:29:31 UTC" fw=201.151.192.156 '
    'pri=4 c=16 m=986 msg="User login denied - not allowed by Policy rule" dur=0 '
    'n=42640 src=172.16.140.73:50590:X0 '
    'dst=100.50.144.145:443:X1:ec2-100-50-144-145.compute-1.amazonaws.com '
    'proto=tcp/https note="Unknown user, authentication by SSO Agent" fw_action="NA"'
)


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "test_siem.db")
    storage.initialize_db()
    # bootstrap_data() ya registra el agente de syslog al arrancar la API
    # antes de que el listener reciba ningún paquete -- se replica aquí.
    storage.register_agents([get_syslog_agent()])
    yield


def test_process_syslog_batch_inserts_event_tagged_real_vm():
    asyncio.run(process_syslog_batch([LINE_LOGIN_DENIED]))

    assert storage.query_summary(environment="real_vm")["total_events"] == 1
    assert storage.query_summary(environment="simulated")["total_events"] == 0


def test_process_syslog_batch_shows_syslog_agent_as_real_vm():
    from engine.agents import SYSLOG_AGENT_ID

    asyncio.run(process_syslog_batch([LINE_LOGIN_DENIED]))

    agents = storage.query_agents(environment="real_vm")
    assert SYSLOG_AGENT_ID in [a["agent_id"] for a in agents]


def test_process_syslog_batch_triggers_alert_above_threshold():
    asyncio.run(process_syslog_batch([LINE_LOGIN_DENIED] * 6))

    alerts = storage.query_alerts(environment="real_vm")
    assert any(a["rule_name"] == "SONICWALL_REPEATED_DENIALS" for a in alerts)


def test_process_syslog_batch_below_threshold_does_not_alert():
    asyncio.run(process_syslog_batch([LINE_LOGIN_DENIED] * 2))

    alerts = storage.query_alerts(environment="real_vm")
    assert not any(a["rule_name"] == "SONICWALL_REPEATED_DENIALS" for a in alerts)


def test_process_syslog_batch_ignores_unparseable_lines():
    asyncio.run(process_syslog_batch(["not a syslog line at all"]))

    assert storage.query_summary(environment="ALL")["total_events"] == 0


def test_process_syslog_batch_empty_list_is_noop():
    asyncio.run(process_syslog_batch([]))

    assert storage.query_summary(environment="ALL")["total_events"] == 0
