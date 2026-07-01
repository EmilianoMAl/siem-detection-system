from engine.parsers.auth_parser import LogEvent
from engine.detectors.rules import DetectionEngine


def make_event(**overrides) -> LogEvent:
    defaults = dict(
        raw_line="raw", timestamp="Apr 03 10:23:45", hostname="prod-server-01",
        service="sshd", pid=1234, event_type="failed_password", username="root",
        source_ip="94.102.49.190", source_port=52341, command=None,
        log_source="ssh", metadata={},
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


def test_ssh_brute_force_triggers_above_threshold():
    events = [make_event() for _ in range(6)]
    engine = DetectionEngine()

    alerts = engine.detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "SSH_BRUTE_FORCE"
    assert alerts[0].severity == "HIGH"


def test_ssh_brute_force_below_threshold_does_not_trigger():
    events = [make_event() for _ in range(2)]
    engine = DetectionEngine()

    assert engine.detect_brute_force(events) == []


def test_ssh_brute_force_critical_severity_above_critical_threshold():
    events = [make_event() for _ in range(25)]
    engine = DetectionEngine()

    alerts = engine.detect_brute_force(events)

    assert alerts[0].severity == "CRITICAL"


def test_suspicious_sudo_command_triggers():
    event = make_event(
        event_type="sudo_command", username="deploy",
        command="/bin/sh -c 'cat /etc/shadow'",
    )
    engine = DetectionEngine()

    alerts = engine.detect_suspicious_commands([event])

    assert len(alerts) == 1
    assert alerts[0].rule_name == "SUSPICIOUS_SUDO_COMMAND"


def test_suspicious_sudo_command_ignores_benign_commands():
    event = make_event(
        event_type="sudo_command", username="deploy",
        command="/usr/bin/apt update",
    )
    engine = DetectionEngine()

    assert engine.detect_suspicious_commands([event]) == []


def test_login_after_failures_triggers():
    ip = "94.102.49.190"
    events = [
        make_event(event_type="failed_password", source_ip=ip),
        make_event(event_type="accepted_password", source_ip=ip, username="root"),
    ]
    engine = DetectionEngine()

    alerts = engine.detect_successful_login_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "LOGIN_AFTER_FAILURES"
    assert alerts[0].severity == "CRITICAL"


def test_web_attack_detects_sqli_payload():
    event = make_event(
        log_source="web", event_type="http_request", username=None,
        command=None, metadata={"path": "/login?user=admin' OR '1'='1", "status_code": 200},
    )
    engine = DetectionEngine()

    alerts = engine.detect_web_attacks([event])

    assert len(alerts) == 1
    assert alerts[0].rule_name == "WEB_ATTACK_PAYLOAD"


def test_web_attack_ignores_normal_request():
    event = make_event(
        log_source="web", event_type="http_request", username=None,
        command=None, metadata={"path": "/dashboard", "status_code": 200},
    )
    engine = DetectionEngine()

    assert engine.detect_web_attacks([event]) == []


def test_recon_scan_triggers_on_many_distinct_paths():
    ip = "45.33.32.156"
    events = [
        make_event(
            log_source="web", event_type="http_request", username=None,
            command=None, source_ip=ip,
            metadata={"path": f"/admin{i}", "status_code": 404},
        )
        for i in range(12)
    ]
    engine = DetectionEngine()

    alerts = engine.detect_recon_scan(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "WEB_RECON_SCAN"


def test_fim_critical_change_triggers_on_etc_passwd():
    event = make_event(
        log_source="fim", event_type="fim_modified", username="root",
        command=None, source_ip=None,
        metadata={"file_path": "/etc/passwd", "action": "modified"},
    )
    engine = DetectionEngine()

    alerts = engine.detect_fim_critical_change([event])

    assert len(alerts) == 1
    assert alerts[0].rule_name == "FIM_CRITICAL_FILE_CHANGE"
    assert alerts[0].severity == "CRITICAL"


def test_fim_critical_change_ignores_benign_path():
    event = make_event(
        log_source="fim", event_type="fim_modified", username="root",
        command=None, source_ip=None,
        metadata={"file_path": "/var/log/syslog", "action": "modified"},
    )
    engine = DetectionEngine()

    assert engine.detect_fim_critical_change([event]) == []


def test_run_all_rules_combines_every_source():
    events = [
        make_event(event_type="failed_password"),
        make_event(
            log_source="web", event_type="http_request", username=None,
            command=None, metadata={"path": "/login?x=<script>", "status_code": 200},
        ),
        make_event(
            log_source="fim", event_type="fim_modified", username="root",
            command=None, source_ip=None,
            metadata={"file_path": "/etc/shadow", "action": "modified"},
        ),
    ]
    engine = DetectionEngine()

    alerts = engine.run_all_rules(events)
    rule_names = {a.rule_name for a in alerts}

    assert "WEB_ATTACK_PAYLOAD" in rule_names
    assert "FIM_CRITICAL_FILE_CHANGE" in rule_names
