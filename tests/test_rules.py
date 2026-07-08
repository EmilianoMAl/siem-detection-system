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


def test_alert_ids_continue_from_start_counter():
    events = [make_event() for _ in range(6)]
    engine = DetectionEngine(start_counter=41)

    alerts = engine.detect_brute_force(events)

    assert alerts[0].alert_id == "ALERT-0042"


def test_default_start_counter_is_zero():
    events = [make_event() for _ in range(6)]
    engine = DetectionEngine()

    alerts = engine.detect_brute_force(events)

    assert alerts[0].alert_id == "ALERT-0001"


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


def test_fim_critical_change_triggers_on_usr_bin_with_compromise_binary_technique():
    event = make_event(
        log_source="fim", event_type="fim_created", username=None,
        command=None, source_ip=None,
        metadata={"file_path": "/usr/bin/evil", "action": "created"},
    )
    engine = DetectionEngine()

    alerts = engine.detect_fim_critical_change([event])

    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].mitre_technique == "T1554 - Compromise Client Software Binary"


def test_fim_critical_change_authorized_keys_still_uses_account_manipulation_technique():
    event = make_event(
        log_source="fim", event_type="fim_modified", username="root",
        command=None, source_ip=None,
        metadata={"file_path": "/root/.ssh/authorized_keys", "action": "modified"},
    )
    engine = DetectionEngine()

    alerts = engine.detect_fim_critical_change([event])

    assert alerts[0].mitre_technique == "T1098 - Account Manipulation"


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


def test_sonicwall_repeated_denials_triggers_above_threshold():
    events = [
        make_event(
            log_source="sonicwall", event_type="login_denied", username=None,
            source_ip="172.16.140.73", environment="real_vm",
        )
        for _ in range(6)
    ]
    engine = DetectionEngine()

    alerts = engine.detect_sonicwall_repeated_denials(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "SONICWALL_REPEATED_DENIALS"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].environment == "real_vm"


def test_sonicwall_repeated_denials_ignores_other_log_sources():
    events = [make_event(event_type="failed_password") for _ in range(10)]
    engine = DetectionEngine()

    assert engine.detect_sonicwall_repeated_denials(events) == []


def test_sonicwall_repeated_denials_below_threshold_does_not_trigger():
    events = [
        make_event(log_source="sonicwall", event_type="connection_denied", source_ip="1.2.3.4")
        for _ in range(2)
    ]
    engine = DetectionEngine()

    assert engine.detect_sonicwall_repeated_denials(events) == []


def test_password_spraying_triggers_on_many_distinct_usernames():
    events = [
        make_event(event_type="failed_password", username=f"user{i}", source_ip="1.2.3.4")
        for i in range(5)
    ]
    engine = DetectionEngine()

    alerts = engine.detect_password_spraying(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "PASSWORD_SPRAYING"
    assert alerts[0].mitre_technique == "T1110.003 - Password Spraying"


def test_password_spraying_ignores_same_username_repeated():
    events = [make_event(event_type="failed_password", username="root") for _ in range(10)]
    engine = DetectionEngine()

    assert engine.detect_password_spraying(events) == []


def test_account_creation_via_sudo_triggers():
    event = make_event(
        event_type="sudo_command", username="deploy",
        command="useradd -m backdoor",
    )
    engine = DetectionEngine()

    alerts = engine.detect_account_creation(events=[event])

    assert len(alerts) == 1
    assert alerts[0].rule_name == "ACCOUNT_CREATION_VIA_SUDO"
    assert alerts[0].mitre_technique == "T1136 - Create Account"


def test_account_creation_ignores_benign_sudo_command():
    event = make_event(
        event_type="sudo_command", username="deploy",
        command="/usr/bin/apt update",
    )
    engine = DetectionEngine()

    assert engine.detect_account_creation(events=[event]) == []


def test_wazuh_promoted_alert_ignores_events_without_mitre_mapping():
    # Ruido rutinario (ej. dpkg) -- Wazuh no lo tagea con mitre, no debe
    # generar una alerta de SENTINEL, solo queda como evento.
    event = make_event(
        log_source="wazuh", event_type="wazuh_alert", username=None,
        command=None, source_ip=None, hostname="wazuh-srv-Virtual-Machine",
        metadata={"rule_id": "2904", "rule_level": 7, "rule_description": "Dpkg installed", "mitre": None},
    )
    engine = DetectionEngine()

    assert engine.detect_wazuh_promoted_alert([event]) == []


def test_wazuh_promoted_alert_triggers_on_windows_service_alert():
    event = make_event(
        log_source="wazuh", event_type="wazuh_alert", username=None,
        command=None, source_ip=None, hostname="DESKTOP-GULVC64",
        metadata={
            "rule_id": "61138", "rule_level": 5,
            "rule_description": "New Windows Service Created",
            "mitre": {"id": ["T1543.003"], "tactic": ["Persistence"], "technique": ["Windows Service"]},
        },
    )
    engine = DetectionEngine()

    alerts = engine.detect_wazuh_promoted_alert([event])

    assert len(alerts) == 1
    assert alerts[0].rule_name == "WAZUH_MITRE_ALERT"
    assert alerts[0].severity == "MEDIUM"  # nivel 5, debajo de high_level (8)
    assert alerts[0].mitre_technique == "T1543.003 - Windows Service"


def test_wazuh_promoted_alert_severity_scales_with_level():
    event = make_event(
        log_source="wazuh", event_type="wazuh_alert", username=None,
        command=None, source_ip=None, hostname="wazuh-srv-Virtual-Machine",
        metadata={
            "rule_id": "5710", "rule_level": 12,
            "rule_description": "Multiple authentication failures",
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
        },
    )
    engine = DetectionEngine()

    alerts = engine.detect_wazuh_promoted_alert([event])

    assert alerts[0].severity == "CRITICAL"


def test_windows_brute_force_triggers_above_threshold_grouped_by_ip():
    events = [
        make_event(
            log_source="windows", event_type="logon_failed", username="admin",
            command=None, source_ip="203.0.113.9",
        )
        for _ in range(6)
    ]
    engine = DetectionEngine()

    alerts = engine.detect_windows_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "WINDOWS_BRUTE_FORCE"
    assert alerts[0].mitre_technique == "T1110 - Brute Force"


def test_windows_brute_force_local_logon_groups_by_username_not_ip():
    # Sin IP (logon local en consola) -- se agrupa por usuario en vez de
    # colapsar todos los logons locales bajo una "IP" compartida.
    events = [
        make_event(
            log_source="windows", event_type="logon_failed", username="root",
            command=None, source_ip=None,
        )
        for _ in range(6)
    ]
    engine = DetectionEngine()

    alerts = engine.detect_windows_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].source_ip is None
    assert alerts[0].username == "root"


def test_windows_brute_force_below_threshold_does_not_trigger():
    events = [
        make_event(log_source="windows", event_type="logon_failed", username="admin", source_ip="1.2.3.4")
        for _ in range(2)
    ]
    engine = DetectionEngine()

    assert engine.detect_windows_brute_force(events) == []


def test_windows_login_after_failures_triggers():
    ip = "203.0.113.9"
    events = [
        make_event(log_source="windows", event_type="logon_failed", username="admin", source_ip=ip),
        make_event(log_source="windows", event_type="logon_success", username="admin", source_ip=ip),
    ]
    engine = DetectionEngine()

    alerts = engine.detect_windows_login_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "WINDOWS_LOGIN_AFTER_FAILURES"
    assert alerts[0].mitre_technique == "T1078 - Valid Accounts"


def test_windows_account_created_triggers():
    event = make_event(
        log_source="windows", event_type="user_created", username="backdoor",
        command=None, source_ip=None, metadata={"message": "A user account was created."},
    )
    engine = DetectionEngine()

    alerts = engine.detect_windows_account_events([event])

    assert len(alerts) == 1
    assert alerts[0].rule_name == "WINDOWS_ACCOUNT_CREATED"
    assert alerts[0].mitre_technique == "T1136 - Create Account"


def test_windows_privileged_group_change_triggers_critical():
    event = make_event(
        log_source="windows", event_type="user_added_to_privileged_group", username="deploy",
        command=None, source_ip=None, metadata={"message": "Member added to Administrators."},
    )
    engine = DetectionEngine()

    alerts = engine.detect_windows_account_events([event])

    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].mitre_technique == "T1098 - Account Manipulation"


def test_windows_service_created_triggers():
    event = make_event(
        log_source="windows", event_type="service_created", username=None,
        command=None, source_ip=None, metadata={"message": "A service was installed.", "service_name": "EvilSvc"},
    )
    engine = DetectionEngine()

    alerts = engine.detect_windows_account_events([event])

    assert alerts[0].rule_name == "WINDOWS_SUSPICIOUS_SERVICE"
    assert alerts[0].mitre_technique == "T1543.003 - Windows Service"


def test_windows_scheduled_task_created_triggers():
    event = make_event(
        log_source="windows", event_type="scheduled_task_created", username=None,
        command=None, source_ip=None, metadata={"message": "A scheduled task was created.", "task_name": "Evil"},
    )
    engine = DetectionEngine()

    alerts = engine.detect_windows_account_events([event])

    assert alerts[0].rule_name == "WINDOWS_SCHEDULED_TASK_CREATED"
    assert alerts[0].mitre_technique == "T1053.005 - Scheduled Task"


def test_windows_account_events_ignores_unrelated_event_types():
    event = make_event(
        log_source="windows", event_type="windows_event", username=None,
        command=None, source_ip=None, metadata={"message": "noise"},
    )
    engine = DetectionEngine()

    assert engine.detect_windows_account_events([event]) == []
