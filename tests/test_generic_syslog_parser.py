from engine.parsers import generic_syslog_parser

LINE_WITH_PRI = "<38>Jul  3 18:30:01 client-vm CRON[12345]: (root) CMD (some command)"
LINE_WITHOUT_PRI = "Jul  3 18:30:05 client-vm systemd[1]: Started Session 7 of user root."
LINE_NO_TAG = "Jul  3 18:30:10 client-vm this is a message with no tag prefix"


def test_parse_line_returns_none_for_empty_line():
    assert generic_syslog_parser.parse_line("") is None
    assert generic_syslog_parser.parse_line("   ") is None


def test_parse_line_with_pri_prefix():
    event = generic_syslog_parser.parse_line(LINE_WITH_PRI)

    assert event is not None
    assert event.log_source == "syslog"
    assert event.event_type == "syslog_message"
    assert event.timestamp == "Jul  3 18:30:01"
    assert event.hostname == "client-vm"
    assert event.service == "CRON"
    assert event.pid == 12345
    assert event.metadata["message"] == "(root) CMD (some command)"
    assert event.raw_line == LINE_WITH_PRI


def test_parse_line_without_pri_prefix():
    event = generic_syslog_parser.parse_line(LINE_WITHOUT_PRI)

    assert event is not None
    assert event.hostname == "client-vm"
    assert event.service == "systemd"
    assert event.pid == 1
    assert event.metadata["message"] == "Started Session 7 of user root."


def test_parse_line_without_tag_still_captures_message():
    event = generic_syslog_parser.parse_line(LINE_NO_TAG)

    assert event is not None
    assert event.hostname == "client-vm"
    assert event.service is None
    assert "this is a message" in event.metadata["message"]


def test_parse_line_returns_none_for_unrecognized_format():
    assert generic_syslog_parser.parse_line("this is not syslog at all") is None
