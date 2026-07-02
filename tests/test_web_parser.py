from engine.parsers.web_parser import parse_line


def test_parse_normal_request():
    line = '10.0.0.12 - - [03/Apr/2026:10:23:45 +0000] "GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    event = parse_line(line)

    assert event is not None
    assert event.log_source == "web"
    assert event.event_type == "http_request"
    assert event.source_ip == "10.0.0.12"
    assert event.metadata["method"] == "GET"
    assert event.metadata["path"] == "/login"
    assert event.metadata["status_code"] == 200
    assert event.metadata["user_agent"] == "Mozilla/5.0"


def test_parse_sqli_payload_in_path():
    # Los espacios del payload van codificados como %20 — igual que un
    # navegador/curl real, y como hace engine/generators/web_generator.py.
    line = ('45.33.32.156 - - [03/Apr/2026:10:23:45 +0000] '
            '"GET /login?user=admin\'%20OR%20\'1\'=\'1 HTTP/1.1" 200 512 "-" "sqlmap/1.7"')
    event = parse_line(line)

    assert event is not None
    assert "OR" in event.metadata["path"]
    assert event.source_ip == "45.33.32.156"


def test_parse_malformed_line_returns_none():
    assert parse_line("not a valid access log line") is None


def test_parse_accepts_real_referrer_not_just_dash():
    # Trafico real (no sintetico) puede traer un referrer de verdad en vez
    # del placeholder "-" que generan nuestros logs de demo.
    line = ('203.0.113.5 - - [03/Apr/2026:10:23:45 +0000] '
            '"GET /dashboard HTTP/1.1" 200 900 "https://google.com/search" "Mozilla/5.0"')
    event = parse_line(line)

    assert event is not None
    assert event.metadata["referrer"] == "https://google.com/search"
    assert event.metadata["user_agent"] == "Mozilla/5.0"
