import re
import logging
from pathlib import Path

from engine.parsers.auth_parser import LogEvent

logger = logging.getLogger(__name__)

# Formato inspirado en el módulo syscheck (FIM) de Wazuh:
# Apr 03 10:23:45 prod-server-01 syscheck: File '/etc/passwd' modified (user=root, hash_before=abc123, hash_after=def456)
PATTERN = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s[\d:]+)\s"
    r"(?P<hostname>\S+)\s"
    r"syscheck:\sFile\s'(?P<file_path>[^']+)'\s(?P<action>\w+)\s"
    r"\(user=(?P<username>\S+),\shash_before=(?P<hash_before>\w+),\shash_after=(?P<hash_after>\w+)\)"
)


def parse_line(line: str) -> LogEvent | None:
    """
    Parsea una línea de evento FIM (integridad de archivos) y retorna
    un LogEvent con log_source="fim". Retorna None si no coincide.
    """
    line = line.strip()
    if not line:
        return None

    match = PATTERN.match(line)
    if not match:
        return None

    groups = match.groupdict()
    action = groups["action"]

    return LogEvent(
        raw_line=line,
        timestamp=groups.get("timestamp"),
        hostname=groups.get("hostname"),
        service="syscheck",
        pid=None,
        event_type=f"fim_{action}",
        username=groups.get("username"),
        source_ip=None,
        source_port=None,
        command=None,
        log_source="fim",
        metadata={
            "file_path": groups.get("file_path"),
            "action": action,
            "hash_before": groups.get("hash_before"),
            "hash_after": groups.get("hash_after"),
        },
    )


def parse_log_file(filepath: Path) -> tuple[list[LogEvent], int]:
    """Parsea un archivo de eventos FIM completo. Misma forma que auth_parser.parse_log_file."""
    events = []
    unparsed = 0

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    logger.info(f"Parseando {len(lines)} líneas FIM de {filepath.name}")

    for line in lines:
        event = parse_line(line)
        if event:
            events.append(event)
        else:
            unparsed += 1

    return events, unparsed
