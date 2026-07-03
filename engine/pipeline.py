import logging
from pathlib import Path
from typing import Callable, Optional

from engine.agents import Agent
from engine.parsers import auth_parser, web_parser, fim_parser, sonicwall_parser, generic_syslog_parser
from engine.parsers.auth_parser import LogEvent

logger = logging.getLogger(__name__)

PARSERS = {
    "ssh": auth_parser.parse_log_file,
    "web": web_parser.parse_log_file,
    "fim": fim_parser.parse_log_file,
    "sonicwall": sonicwall_parser.parse_log_file,
    "syslog": generic_syslog_parser.parse_log_file,
}

LINE_PARSERS = {
    "ssh": auth_parser.parse_line,
    "web": web_parser.parse_line,
    "fim": fim_parser.parse_line,
    "sonicwall": sonicwall_parser.parse_line,
    "syslog": generic_syslog_parser.parse_line,
}


def _tag_events(agent: Agent, events: list[LogEvent]) -> None:
    for event in events:
        event.agent_id = agent.agent_id
        event.environment = agent.environment
        if not event.hostname:
            event.hostname = agent.hostname


def ingest_agent_logs(agent: Agent, log_source: str, filepath: Path) -> tuple[list[LogEvent], int]:
    """
    Parsea el archivo de log de un agente con el parser correcto para
    su fuente, y le asigna agent_id/hostname a cada evento resultante.

    Returns:
        (eventos parseados, líneas no parseadas)
    """
    parser = PARSERS[log_source]
    events, unparsed = parser(filepath)
    _tag_events(agent, events)

    logger.info(
        f"Ingesta {log_source} de {agent.hostname}: "
        f"{len(events)} eventos, {unparsed} sin parsear"
    )
    return events, unparsed


def ingest_lines(agent: Agent, log_source: str, lines: list[str]) -> tuple[list[LogEvent], int]:
    """
    Igual que ingest_agent_logs pero sobre líneas ya en memoria (no un
    archivo) — lo que manda el agente real (agent/ship_logs.py) vía
    POST /ingest, en vez de un archivo generado localmente.
    """
    parse_line = LINE_PARSERS[log_source]
    events = []
    unparsed = 0

    for line in lines:
        event = parse_line(line)
        if event:
            events.append(event)
        else:
            unparsed += 1

    _tag_events(agent, events)

    logger.info(
        f"Ingesta (líneas) {log_source} de {agent.hostname}: "
        f"{len(events)} eventos, {unparsed} sin parsear"
    )
    return events, unparsed


def ingest_lines_multi(
    agent: Agent, items: list[tuple[str, dict]],
    parsers: list[Callable[[str], Optional[LogEvent]]],
) -> tuple[list[LogEvent], int]:
    """
    Igual que ingest_lines, pero para un receptor que puede recibir más
    de un formato en el mismo puerto (el receptor de syslog: puede
    llegar auth.log real reenviado por rsyslog, un firewall SonicWall,
    o cualquier otra cosa). Prueba cada parser en orden por línea y usa
    el primero que matchee -- no hay un log_source fijo de antemano.

    Cada item es (línea, metadata_extra) -- metadata_extra (ej. la IP
    real de quién mandó el paquete UDP, distinta del `source_ip` que
    extrae el parser del contenido del log) se fusiona en el evento
    resultante si algún parser matcheó esa línea.
    """
    events = []
    unparsed = 0

    for line, extra_metadata in items:
        event = None
        for parser in parsers:
            event = parser(line)
            if event:
                break
        if event:
            if extra_metadata:
                event.metadata = {**(event.metadata or {}), **extra_metadata}
            events.append(event)
        else:
            unparsed += 1

    _tag_events(agent, events)

    logger.info(
        f"Ingesta (líneas, multi-formato) de {agent.hostname}: "
        f"{len(events)} eventos, {unparsed} sin parsear"
    )
    return events, unparsed
