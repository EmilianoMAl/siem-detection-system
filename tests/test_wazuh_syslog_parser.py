import json

from engine.parsers import wazuh_syslog_parser

# Alerta real de Wazuh capturada en producción (systemd, no es de FIM) --
# confirma que el parser reconoce el formato "<PRI>TIMESTAMP HOSTNAME
# ossec: {JSON}" tal como Wazuh lo manda de verdad.
LINE_REAL_NON_FIM = (
    '<132>Jul  6 15:37:37 wazuh-srv-Virtual-Machine ossec: '
    '{"timestamp":"2026-07-06T15:37:37.945-0600","rule":{"level":5,'
    '"description":"Systemd: Service exited due to a failure.","id":"40704",'
    '"firedtimes":1,"mail":false,"groups":["local","systemd"],"gpg13":["4.3"],'
    '"gdpr":["IV_35.7.d"]},"agent":{"id":"000","name":"wazuh-srv-Virtual-Machine"},'
    '"manager":{"name":"wazuh-srv-Virtual-Machine"},"id":"1783373857.438692",'
    '"full_log":"Jul 06 21:37:37 wazuh-srv-Virtual-Machine systemd[1]: '
    'gdm.service: Main process exited, code=exited, status=1/FAILURE",'
    '"predecoder":{"program_name":"systemd","timestamp":"Jul 06 21:37:37",'
    '"hostname":"wazuh-srv-Virtual-Machine"},"decoder":{"name":"systemd"},'
    '"location":"journald"}'
)

# Alerta de syscheck (FIM) -- construida siguiendo el schema documentado
# de Wazuh (no tengo una capturada en vivo todavía), simulando un cambio
# en /usr/bin.
SYSCHECK_ALERT = {
    "timestamp": "2026-07-08T10:00:00.000-0600",
    "rule": {"level": 7, "description": "File added to the system.", "id": "550", "groups": ["ossec", "syscheck"]},
    "agent": {"id": "001", "name": "wazuh-srv-Virtual-Machine"},
    "syscheck": {"path": "/usr/bin/evil", "event": "added", "md5_before": None, "md5_after": "abc123"},
    "full_log": "File '/usr/bin/evil' added",
}
LINE_SYSCHECK = f"<38>Jul  8 10:00:00 wazuh-srv-Virtual-Machine ossec: {json.dumps(SYSCHECK_ALERT)}"


def test_parse_line_returns_none_for_non_wazuh_lines():
    assert wazuh_syslog_parser.parse_line("") is None
    assert wazuh_syslog_parser.parse_line("<38>Jul  8 10:00:00 host sshd[1]: Failed password") is None


def test_parse_line_returns_none_for_malformed_json():
    line = "<38>Jul  8 10:00:00 host ossec: {not valid json"
    assert wazuh_syslog_parser.parse_line(line) is None


def test_parse_real_non_fim_alert_uses_wazuh_log_source():
    event = wazuh_syslog_parser.parse_line(LINE_REAL_NON_FIM)

    assert event is not None
    assert event.log_source == "wazuh"
    assert event.event_type == "wazuh_alert"
    assert event.hostname == "wazuh-srv-Virtual-Machine"
    assert event.metadata["rule_id"] == "40704"
    assert event.metadata["rule_level"] == 5
    assert event.metadata["rule_description"] == "Systemd: Service exited due to a failure."
    assert event.raw_line == LINE_REAL_NON_FIM


def test_parse_syscheck_alert_uses_fim_log_source():
    event = wazuh_syslog_parser.parse_line(LINE_SYSCHECK)

    assert event is not None
    assert event.log_source == "fim"
    assert event.event_type == "fim_created"  # "added" (Wazuh) -> "created" (convención de SENTINEL)
    assert event.metadata["file_path"] == "/usr/bin/evil"
    assert event.metadata["action"] == "created"
    assert event.metadata["hash_after"] == "abc123"
