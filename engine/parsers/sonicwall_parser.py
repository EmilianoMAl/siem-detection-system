import re
import logging
from pathlib import Path

from engine.parsers.auth_parser import LogEvent

logger = logging.getLogger(__name__)

# Formato real de syslog de un firewall SonicWall (confirmado con líneas
# capturadas del trabajo del usuario) -- pares key=value separados por
# espacio, valores con espacios entre comillas dobles, y endpoints
# compuestos "IP:PUERTO:ZONA[:HOSTNAME]" en src/dst:
# id=firewall sn=18C24173CD98 time="2026-06-30 15:29:31 UTC" fw=201.151.192.156
# pri=4 c=16 m=986 msg="User login denied - not allowed by Policy rule" dur=0
# n=42640 src=172.16.140.73:50590:X0 dst=100.50.144.145:443:X1:ec2-...com
# proto=tcp/https note="Unknown user, authentication by SSO Agent" fw_action="NA"
FIELD_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _parse_fields(line: str) -> dict:
    return {key: value.strip('"') for key, value in FIELD_RE.findall(line)}


def _classify(msg: str) -> str:
    lowered = msg.lower()
    if "login denied" in lowered:
        return "login_denied"
    if "denied" in lowered:
        return "connection_denied"
    return "firewall_event"


def _split_endpoint(value: str | None) -> tuple[str | None, int | None, str | None, str | None]:
    """"172.16.140.73:50590:X0" -> (ip, port, zona, hostname opcional)."""
    if not value:
        return None, None, None, None
    parts = value.split(":")
    ip = parts[0] or None
    port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    zone = parts[2] if len(parts) > 2 else None
    hostname = parts[3] if len(parts) > 3 else None
    return ip, port, zone, hostname


def parse_line(line: str) -> LogEvent | None:
    """
    Parsea una línea de syslog crudo de SonicWall y retorna un LogEvent
    con log_source="sonicwall". Retorna None si no es un log de firewall
    reconocible (id != "firewall").
    """
    line = line.strip()
    if not line:
        return None

    fields = _parse_fields(line)
    if fields.get("id") != "firewall":
        return None

    src_ip, src_port, _, _ = _split_endpoint(fields.get("src"))
    dst_ip, dst_port, dst_zone, dst_hostname = _split_endpoint(fields.get("dst"))
    msg = fields.get("msg", "")

    return LogEvent(
        raw_line=line,
        timestamp=fields.get("time"),
        hostname=None,
        service="sonicwall",
        pid=None,
        event_type=_classify(msg),
        username=None,
        source_ip=src_ip or fields.get("fw"),
        source_port=src_port,
        command=None,
        log_source="sonicwall",
        metadata={
            "sn": fields.get("sn"),
            "fw": fields.get("fw"),
            "msg": msg,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "dst_zone": dst_zone,
            "dst_hostname": dst_hostname,
            "proto": fields.get("proto"),
            "action": fields.get("fw_action"),
            "note": fields.get("note"),
            "pri": fields.get("pri"),
        },
    )


def parse_log_file(filepath: Path) -> tuple[list[LogEvent], int]:
    """Parsea un archivo de syslog de SonicWall completo. Misma forma que auth_parser.parse_log_file."""
    events = []
    unparsed = 0

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    logger.info(f"Parseando {len(lines)} líneas SonicWall de {filepath.name}")

    for line in lines:
        event = parse_line(line)
        if event:
            events.append(event)
        else:
            unparsed += 1

    return events, unparsed
