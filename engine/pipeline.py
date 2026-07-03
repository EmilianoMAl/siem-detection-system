import logging
from pathlib import Path

from engine.agents import Agent
from engine.parsers import auth_parser, web_parser, fim_parser, sonicwall_parser
from engine.parsers.auth_parser import LogEvent

logger = logging.getLogger(__name__)

PARSERS = {
    "ssh": auth_parser.parse_log_file,
    "web": web_parser.parse_log_file,
    "fim": fim_parser.parse_log_file,
    "sonicwall": sonicwall_parser.parse_log_file,
}

LINE_PARSERS = {
    "ssh": auth_parser.parse_line,
    "web": web_parser.parse_line,
    "fim": fim_parser.parse_line,
    "sonicwall": sonicwall_parser.parse_line,
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
