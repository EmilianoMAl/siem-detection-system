import re
import logging
from pathlib import Path

from engine.parsers.auth_parser import LogEvent

logger = logging.getLogger(__name__)

# Formato estilo nginx/apache "combined log" (sin el campo referrer):
# 10.0.0.12 - - [03/Apr/2026:10:23:45 +0000] "GET /login?user=admin HTTP/1.1" 200 512 "-" "Mozilla/5.0"
PATTERN = re.compile(
    r"(?P<source_ip>[\d.]+)\s-\s-\s"
    r"\[(?P<timestamp>[^\]]+)\]\s"
    r'"(?P<method>[A-Z]+)\s(?P<path>\S+)\sHTTP/\d\.\d"\s'
    r"(?P<status_code>\d{3})\s(?P<size>\d+)\s"
    r'"-"\s"(?P<user_agent>[^"]*)"'
)


def parse_line(line: str) -> LogEvent | None:
    """
    Parsea una línea de access log (nginx/apache) y retorna un LogEvent
    con log_source="web". Retorna None si la línea no coincide.
    """
    line = line.strip()
    if not line:
        return None

    match = PATTERN.match(line)
    if not match:
        return None

    groups = match.groupdict()
    status_code = int(groups["status_code"])

    return LogEvent(
        raw_line=line,
        timestamp=groups.get("timestamp"),
        hostname=None,
        service="nginx",
        pid=None,
        event_type="http_request",
        username=None,
        source_ip=groups.get("source_ip"),
        source_port=None,
        command=None,
        log_source="web",
        metadata={
            "method": groups.get("method"),
            "path": groups.get("path"),
            "status_code": status_code,
            "user_agent": groups.get("user_agent"),
        },
    )


def parse_log_file(filepath: Path) -> tuple[list[LogEvent], int]:
    """Parsea un archivo de access log completo. Misma forma que auth_parser.parse_log_file."""
    events = []
    unparsed = 0

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    logger.info(f"Parseando {len(lines)} líneas web de {filepath.name}")

    for line in lines:
        event = parse_line(line)
        if event:
            events.append(event)
        else:
            unparsed += 1

    return events, unparsed
