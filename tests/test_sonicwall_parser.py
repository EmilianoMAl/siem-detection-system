from engine.parsers import sonicwall_parser

LINE_WEB_ACCESS_DENIED = (
    'id=firewall sn=18C2412D2DAC time="2026-06-04 23:22:23 UTC" fw=200.52.94.98 '
    'pri=3 c=4 m=14 msg="Web site access denied" app=49177 appName=\'General'
)

LINE_LOGIN_DENIED = (
    'id=firewall sn=18C24173CD98 time="2026-06-30 15:29:31 UTC" fw=201.151.192.156 '
    'pri=4 c=16 m=986 msg="User login denied - not allowed by Policy rule" dur=0 '
    'n=42640 src=172.16.140.73:50590:X0 '
    'dst=100.50.144.145:443:X1:ec2-100-50-144-145.compute-1.amazonaws.com '
    'proto=tcp/https note="Unknown user, authentication by SSO Agent" fw_action="NA"'
)


def test_parse_line_returns_none_for_non_firewall_lines():
    assert sonicwall_parser.parse_line("") is None
    assert sonicwall_parser.parse_line("id=other sn=123") is None


def test_parse_login_denied_line_extracts_src_and_dst():
    event = sonicwall_parser.parse_line(LINE_LOGIN_DENIED)

    assert event is not None
    assert event.log_source == "sonicwall"
    assert event.timestamp == "2026-06-30 15:29:31 UTC"
    assert event.event_type == "login_denied"
    assert event.source_ip == "172.16.140.73"
    assert event.source_port == 50590
    assert event.metadata["dst_ip"] == "100.50.144.145"
    assert event.metadata["dst_port"] == 443
    assert event.metadata["dst_hostname"] == "ec2-100-50-144-145.compute-1.amazonaws.com"
    assert event.metadata["proto"] == "tcp/https"
    assert event.metadata["action"] == "NA"
    assert event.metadata["note"] == "Unknown user, authentication by SSO Agent"
    assert event.metadata["msg"] == "User login denied - not allowed by Policy rule"
    assert event.raw_line == LINE_LOGIN_DENIED


def test_parse_web_access_denied_line_classifies_as_connection_denied():
    event = sonicwall_parser.parse_line(LINE_WEB_ACCESS_DENIED)

    assert event is not None
    assert event.event_type == "connection_denied"
    assert event.metadata["sn"] == "18C2412D2DAC"
    assert event.metadata["msg"] == "Web site access denied"
    # Sin src=, cae de vuelta a la IP del propio firewall.
    assert event.source_ip == "200.52.94.98"


def test_parse_line_defaults_to_simulated_environment():
    event = sonicwall_parser.parse_line(LINE_LOGIN_DENIED)

    assert event.environment == "simulated"  # pipeline._tag_events lo sobreescribe con el del agente
