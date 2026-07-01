from engine.parsers.fim_parser import parse_line


def test_parse_critical_file_modified():
    line = ("Apr 03 10:23:45 prod-server-01 syscheck: File '/etc/passwd' modified "
             "(user=root, hash_before=abc123, hash_after=def456)")
    event = parse_line(line)

    assert event is not None
    assert event.log_source == "fim"
    assert event.event_type == "fim_modified"
    assert event.hostname == "prod-server-01"
    assert event.username == "root"
    assert event.metadata["file_path"] == "/etc/passwd"
    assert event.metadata["action"] == "modified"
    assert event.metadata["hash_before"] == "abc123"
    assert event.metadata["hash_after"] == "def456"


def test_parse_file_created():
    line = ("Apr 03 10:23:45 web-server-02 syscheck: File '/root/.ssh/authorized_keys' created "
             "(user=root, hash_before=none, hash_after=aaa111)")
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "fim_created"
    assert event.metadata["file_path"] == "/root/.ssh/authorized_keys"


def test_parse_malformed_line_returns_none():
    assert parse_line("not a valid fim line") is None
