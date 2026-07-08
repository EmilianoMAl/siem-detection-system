import json

from engine.parsers import windows_eventlog_parser as parser


def _line(record: dict, hostname: str = "DESKTOP-GULVC64") -> str:
    return f"<134>Jul  8 12:00:00 {hostname} sentinel_winlog: {json.dumps(record)}"


def test_parse_line_ignores_non_matching_lines():
    assert parser.parse_line("not a syslog line at all") is None
    assert parser.parse_line("<38>Jul  8 12:00:00 host sshd[1]: Failed password") is None


def test_parse_line_returns_none_on_invalid_json():
    line = "<134>Jul  8 12:00:00 DESKTOP-GULVC64 sentinel_winlog: {not json}"
    assert parser.parse_line(line) is None


def test_parse_line_logon_failed_extracts_user_and_ip():
    record = {
        "EventID": 4625, "Channel": "Security", "Hostname": "DESKTOP-GULVC64",
        "TargetUserName": "admin", "IpAddress": "203.0.113.9",
        "LogonType": "3", "Message": "An account failed to log on.",
    }
    event = parser.parse_line(_line(record))

    assert event.log_source == "windows"
    assert event.event_type == "logon_failed"
    assert event.username == "admin"
    assert event.source_ip == "203.0.113.9"
    assert event.hostname == "DESKTOP-GULVC64"
    assert event.metadata["event_id"] == 4625


def test_parse_line_local_logon_has_no_source_ip():
    # NXLog reporta "-" para logons locales/en consola, no de red -- no
    # es una IP real, no debe guardarse como tal.
    record = {"EventID": 4625, "Channel": "Security", "TargetUserName": "root", "IpAddress": "-"}
    event = parser.parse_line(_line(record))

    assert event.source_ip is None
    assert event.username == "root"


def test_parse_line_service_created():
    record = {
        "EventID": 7045, "Channel": "System", "ServiceName": "EvilSvc",
        "ImagePath": "C:\\evil.exe", "Message": "A service was installed.",
    }
    event = parser.parse_line(_line(record))

    assert event.event_type == "service_created"
    assert event.metadata["service_name"] == "EvilSvc"


def test_parse_line_unknown_event_id_falls_back_to_generic():
    record = {"EventID": 9999, "Channel": "Application", "Message": "Something happened"}
    event = parser.parse_line(_line(record))

    assert event.event_type == "windows_event"
    assert event.log_source == "windows"


def test_parse_line_handles_pri_prefix_and_without():
    record = {"EventID": 4624, "Channel": "Security", "TargetUserName": "deploy"}
    with_pri = parser.parse_line(_line(record))
    without_pri = parser.parse_line(f"Jul  8 12:00:00 DESKTOP-GULVC64 sentinel_winlog: {json.dumps(record)}")

    assert with_pri.event_type == without_pri.event_type == "logon_success"
