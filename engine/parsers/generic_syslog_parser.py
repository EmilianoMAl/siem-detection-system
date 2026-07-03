import re
import logging
from pathlib import Path

from engine.parsers.auth_parser import LogEvent

logger = logging.getLogger(__name__)

# Syslog RFC3164 estándar (lo que manda rsyslog por default al reenviar
# con `*.* @@host:514`): "<PRI>TIMESTAMP HOSTNAME TAG[PID]: MENSAJE".
# El <PRI> es opcional acá porque puede llegar ya despojado de él (ver
# engine/syslog_listener.py, que intenta primero parsers más específicos
# sobre la línea sin <PRI> antes de caer a este catch-all).
SYSLOG_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<hostname>\S+)\s"
    r"(?:(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*)?"
    r"(?P<message>.*)$"
)


def parse_line(line: str) -> LogEvent | None:
    """
    Catch-all para cualquier mensaje de syslog estándar que no matcheó
    ningún parser más específico (ssh/web/sonicwall) -- se guarda igual
    (visible en el dashboard como fuente "syslog"), aunque no dispare
    ninguna regla de detección puntual todavía.
    """
    stripped = line.strip()
    if not stripped:
        return None

    match = SYSLOG_RE.match(stripped)
    if not match:
        return None

    groups = match.groupdict()
    return LogEvent(
        raw_line=line,
        timestamp=groups.get("timestamp"),
        hostname=groups.get("hostname"),
        service=groups.get("tag"),
        pid=int(groups["pid"]) if groups.get("pid") else None,
        event_type="syslog_message",
        username=None,
        source_ip=None,
        source_port=None,
        command=None,
        log_source="syslog",
        metadata={"message": groups.get("message", "")},
    )


def parse_log_file(filepath: Path) -> tuple[list[LogEvent], int]:
    """Parsea un archivo de syslog genérico completo. Misma forma que auth_parser.parse_log_file."""
    events = []
    unparsed = 0

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    logger.info(f"Parseando {len(lines)} líneas de syslog genérico de {filepath.name}")

    for line in lines:
        event = parse_line(line)
        if event:
            events.append(event)
        else:
            unparsed += 1

    return events, unparsed
