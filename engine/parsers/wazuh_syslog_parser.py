import re
import json
import logging
from pathlib import Path

from engine.parsers.auth_parser import LogEvent

logger = logging.getLogger(__name__)

# Formato real de Wazuh reenviando sus alertas por syslog (confirmado
# con alertas capturadas de un Wazuh manager real): "<PRI>TIMESTAMP
# HOSTNAME ossec: {JSON}", donde el JSON es el objeto de alerta
# completo de Wazuh -- rule/agent/manager/full_log, y para FIM un
# bloque "syscheck" con path/event/hashes.
HEADER_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<hostname>\S+)\s"
    r"ossec:\s*(?P<json>\{.*\})\s*$"
)

# Wazuh usa "added" para archivos nuevos; el resto del código (parser
# sintético de FIM, colores del dashboard) ya usa "created" -- se
# traduce acá para no tener dos vocabularios distintos para lo mismo.
SYSCHECK_EVENT_TO_ACTION = {"added": "created", "modified": "modified", "deleted": "deleted"}


def parse_line(line: str) -> LogEvent | None:
    """
    Parsea una alerta de Wazuh reenviada por syslog. Si es una alerta
    de FIM (syscheck), devuelve un LogEvent con log_source="fim" y los
    mismos campos de metadata que ya usa engine/parsers/fim_parser.py
    (file_path/action/hash_before/hash_after) -- así
    detect_fim_critical_change la reconoce sin necesitar una regla
    nueva. Cualquier otra alerta de Wazuh usa log_source="wazuh".
    """
    stripped = line.strip()
    if not stripped:
        return None

    match = HEADER_RE.match(stripped)
    if not match:
        return None

    try:
        alert = json.loads(match.group("json"))
    except json.JSONDecodeError:
        return None

    rule = alert.get("rule") or {}
    syscheck = alert.get("syscheck")
    is_fim = bool(syscheck) or "syscheck" in rule.get("groups", [])

    if is_fim:
        syscheck = syscheck or {}
        action = SYSCHECK_EVENT_TO_ACTION.get(syscheck.get("event"), "modified")
        log_source = "fim"
        event_type = f"fim_{action}"
        metadata = {
            "file_path": syscheck.get("path"),
            "action": action,
            "hash_before": syscheck.get("md5_before"),
            "hash_after": syscheck.get("md5_after"),
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
        }
    else:
        log_source = "wazuh"
        event_type = "wazuh_alert"
        metadata = {
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "rule_groups": rule.get("groups", []),
            "mitre": rule.get("mitre"),
            "full_log": alert.get("full_log"),
        }

    return LogEvent(
        raw_line=line,
        timestamp=alert.get("timestamp") or match.group("timestamp"),
        hostname=match.group("hostname"),
        service="ossec",
        pid=None,
        event_type=event_type,
        username=None,
        source_ip=None,
        source_port=None,
        command=None,
        log_source=log_source,
        metadata=metadata,
    )


def parse_log_file(filepath: Path) -> tuple[list[LogEvent], int]:
    """Parsea un archivo de alertas de Wazuh completo. Misma forma que los demás parsers."""
    events = []
    unparsed = 0

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    logger.info(f"Parseando {len(lines)} líneas de Wazuh de {filepath.name}")

    for line in lines:
        event = parse_line(line)
        if event:
            events.append(event)
        else:
            unparsed += 1

    return events, unparsed
