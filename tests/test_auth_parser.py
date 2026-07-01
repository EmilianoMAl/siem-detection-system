from engine.parsers.auth_parser import parse_line


def test_parse_accepted_password():
    line = "Apr 03 10:23:45 prod-server-01 sshd[4521]: Accepted password for emiliano from 10.0.0.5 port 52341 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "accepted_password"
    assert event.username == "emiliano"
    assert event.source_ip == "10.0.0.5"
    assert event.source_port == 52341
    assert event.hostname == "prod-server-01"
    assert event.log_source == "ssh"


def test_parse_failed_password():
    line = "Apr 03 10:23:45 prod-server-01 sshd[4521]: Failed password for root from 94.102.49.190 port 52341 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "failed_password"
    assert event.username == "root"
    assert event.source_ip == "94.102.49.190"


def test_parse_invalid_user():
    line = "Apr 03 10:23:45 prod-server-01 sshd[4521]: Invalid user guest from 45.33.32.156 port 52341"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "invalid_user"
    assert event.username == "guest"


def test_parse_sudo_command():
    line = "Apr 03 10:23:45 prod-server-01 sudo[1234]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt update"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "sudo_command"
    assert event.username == "deploy"
    assert event.command == "/usr/bin/apt update"


def test_parse_malformed_line_returns_none():
    assert parse_line("this is not a valid auth.log line") is None


def test_parse_empty_line_returns_none():
    assert parse_line("   ") is None
