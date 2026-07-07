import logging
from pathlib import Path
from typing import Callable, Optional

from engine.agents import Agent
from engine.parsers import auth_parser, web_parser, fim_parser, sonicwall_parser, wazuh_syslog_parser, generic_syslog_parser
from engine.parsers.auth_parser import LogEvent

logger = logging.getLogger(__name__)

PARSERS = {
    "ssh": auth_parser.parse_log_file,
    "web": web_parser.parse_log_file,
    "fim": fim_parser.parse_log_file,
    "sonicwall": sonicwall_parser.parse_log_file,
    "wazuh": wazuh_syslog_parser.parse_log_file,
    "syslog": generic_syslog_parser.parse_log_file,
}

LINE_PARSERS = {
    "ssh": auth_parser.parse_line,
    "web": web_parser.parse_line,
    "fim": fim_parser.parse_line,
    "sonicwall": sonicwall_parser.parse_line,
    "wazuh": wazuh_syslog_parser.parse_line,
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
    resolve_agent: Callable[[Optional[str], LogEvent], Agent],
    items: list[tuple[str, dict]],
    parsers: list[Callable[[str], Optional[LogEvent]]],
) -> tuple[list[LogEvent], int]:
    """
    Igual que ingest_lines, pero para un receptor que puede recibir más
    de un formato Y de más de un agente en el mismo lote (el receptor
    de syslog: en una misma ventana de 15s puede llegar auth.log real
    de una VM Linux, un firewall SonicWall, y una VM de Windows, cada
    uno con su propia identidad). Prueba cada parser en orden por línea
    y usa el primero que matchee; a cada evento resuelto se le asigna
    su agente llamando a `resolve_agent(sender_ip, event)` -- no hay un
    agente ni un log_source fijo de antemano para todo el lote.

    Cada item es (línea, metadata_extra) -- metadata_extra debe traer
    "sender_ip" (la IP real de quién mandó el paquete UDP, usada tanto
    para resolver el agente como para guardarse en el evento, distinta
    del `source_ip` que algún parser haya extraído del contenido del
    log, ej. la IP atacante en una línea SSH/SonicWall).
    """
    events = []
    unparsed = 0

    for line, extra_metadata in items:
        event = None
        for parser in parsers:
            event = parser(line)
            if event:
                break
        if not event:
            unparsed += 1
            continue

        sender_ip = (extra_metadata or {}).get("sender_ip")
        agent = resolve_agent(sender_ip, event)
        event.agent_id = agent.agent_id
        event.environment = agent.environment
        if not event.hostname:
            event.hostname = agent.hostname
        if extra_metadata:
            event.metadata = {**(event.metadata or {}), **extra_metadata}
        events.append(event)

    logger.info(
        f"Ingesta (líneas, multi-formato/multi-agente): "
        f"{len(events)} eventos, {unparsed} sin parsear"
    )
    return events, unparsed
