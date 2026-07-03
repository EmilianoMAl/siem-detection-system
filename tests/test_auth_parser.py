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


def test_parse_failed_password_for_invalid_user():
    # Variante real de OpenSSH cuando el usuario no existe -- distinta
    # del "Invalid user X ..." (que es una línea separada).
    line = "Apr 03 10:23:45 prod-server-01 sshd[4521]: Failed password for invalid user admin from 203.0.113.9 port 4444 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "failed_password"
    assert event.username == "admin"
    assert event.source_ip == "203.0.113.9"
    assert event.source_port == 4444


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


def test_parse_accepted_password_with_iso_timestamp():
    # Formato real de /var/log/auth.log en Ubuntu 24.04+ (rsyslog moderno),
    # distinto al syslog clásico que usa nuestro generador sintético.
    line = "2026-07-02T18:17:49.548734+00:00 sentinel-vm sshd[3336]: Accepted password for ubuntu from 200.66.80.91 port 47141 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "accepted_password"
    assert event.username == "ubuntu"
    assert event.hostname == "sentinel-vm"


def test_parse_accepted_publickey():
    line = ("2026-07-02T18:17:49.548734+00:00 sentinel-vm sshd[3336]: "
            "Accepted publickey for ubuntu from 200.66.80.91 port 47141 ssh2: ED25519 SHA256:abc")
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "accepted_publickey"
    assert event.username == "ubuntu"
    assert event.source_ip == "200.66.80.91"


def test_parse_ssh_preauth_disconnect():
    # Este es el patrón más común de bots escaneando el puerto 22 sin
    # siquiera llegar a un intento de password.
    line = ("2026-07-02T18:20:10.128633+00:00 sentinel-vm sshd[3828]: "
            "Connection closed by authenticating user root 140.84.190.45 port 53534 [preauth]")
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "ssh_preauth_disconnect"
    assert event.username == "root"
    assert event.source_ip == "140.84.190.45"


def test_parse_real_sudo_format_without_pid():
    # El sudo real de Ubuntu 24.04 no trae [PID] y puede omitir TTY=.
    line = "2026-07-02T03:50:37.029127+00:00 sentinel-vm sudo:     root : PWD=/ ; USER=root ; COMMAND=/usr/bin/apt-get update"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "sudo_command"
    assert event.username == "root"
    assert event.command == "/usr/bin/apt-get update"
