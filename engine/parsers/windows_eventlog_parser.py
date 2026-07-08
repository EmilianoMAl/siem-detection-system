import re
import json
import logging
from pathlib import Path

from engine.parsers.auth_parser import LogEvent

logger = logging.getLogger(__name__)

# Formato: un forwarder de Windows (NXLog Community Edition u otro) manda
# el Event Log nativo como JSON envuelto en una línea de syslog --
# "<PRI>TIMESTAMP HOSTNAME sentinel_winlog: {JSON}". Mismo patrón que
# wazuh_syslog_parser.py (tag propio en vez de "ossec:") pero
# DELIBERADAMENTE independiente de Wazuh -- funciona con cualquier
# Windows que mande su Event Log, tenga o no un manager de Wazuh
# enfrente. Ver DEPLOYMENT.md por la config exacta de NXLog.
HEADER_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<hostname>\S+)\s"
    r"sentinel_winlog:\s*(?P<json>\{.*\})\s*$"
)

# Event IDs de Windows Security/System más útiles para detección --
# subconjunto pequeño y deliberado (no todo el catálogo de Windows),
# elegido para que cubra los mismos casos de uso que ya existen para
# SSH (login fallido/exitoso, creación de cuenta) más los que son
# específicos de Windows (grupo privilegiado, servicio, tarea programada).
EVENT_TYPE_BY_ID = {
    4624: "logon_success",
    4625: "logon_failed",
    4720: "user_created",
    4726: "user_deleted",
    4732: "user_added_to_privileged_group",   # grupo local (ej. Administrators)
    4728: "user_added_to_privileged_group",   # grupo global (ej. Domain Admins)
    4698: "scheduled_task_created",
    7045: "service_created",
}

# NXLog reporta "-" (o vacío) cuando el logon es local/en consola, no de
# red -- no es una IP real, tratarla como tal rompería la correlación
# por IP (agruparía cualquier logon local de cualquier usuario bajo la
# misma "IP"). Se guarda como None y las reglas caen a agrupar por
# usuario en ese caso.
_NON_ROUTABLE_IPS = {"-", "", "::1", "127.0.0.1", "localhost"}


def _clean_ip(value) -> str | None:
    if not value or value in _NON_ROUTABLE_IPS:
        return None
    return value


def parse_line(line: str) -> LogEvent | None:
    """
    Parsea una línea de Event Log de Windows reenviada por un forwarder
    externo (NXLog). Eventos con un EventID reconocido (ver
    EVENT_TYPE_BY_ID) quedan tageados con su event_type específico;
    cualquier otro se guarda igual como "windows_event" (visible en
    Events, sin regla de detección todavía) en vez de descartarse.
    """
    stripped = line.strip()
    if not stripped:
        return None

    match = HEADER_RE.match(stripped)
    if not match:
        return None

    try:
        record = json.loads(match.group("json"))
    except json.JSONDecodeError:
        return None

    raw_event_id = record.get("EventID")
    try:
        event_id = int(raw_event_id)
    except (TypeError, ValueError):
        event_id = None

    event_type = EVENT_TYPE_BY_ID.get(event_id, "windows_event")
    username = record.get("TargetUserName") or record.get("MemberName")
    source_ip = _clean_ip(record.get("IpAddress"))

    metadata = {
        "event_id": event_id,
        "channel": record.get("Channel"),
        "message": record.get("Message"),
        "logon_type": record.get("LogonType"),
        "workstation_name": record.get("WorkstationName"),
        "service_name": record.get("ServiceName"),
        "image_path": record.get("ImagePath"),
        "task_name": record.get("TaskName"),
        "subject_user_name": record.get("SubjectUserName"),
    }

    return LogEvent(
        raw_line=line,
        timestamp=record.get("EventTime") or match.group("timestamp"),
        hostname=record.get("Hostname") or match.group("hostname"),
        service="eventlog",
        pid=None,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        source_port=None,
        command=None,
        log_source="windows",
        metadata=metadata,
    )


def parse_log_file(filepath: Path) -> tuple[list[LogEvent], int]:
    """Parsea un archivo de Event Log de Windows completo. Misma forma que los demás parsers."""
    events = []
    unparsed = 0

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    logger.info(f"Parseando {len(lines)} líneas de Windows Event Log de {filepath.name}")

    for line in lines:
        event = parse_line(line)
        if event:
            events.append(event)
        else:
            unparsed += 1

    return events, unparsed
