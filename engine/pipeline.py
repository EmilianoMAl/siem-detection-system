import logging
from pathlib import Path

from engine.agents import Agent
from engine.parsers.auth_parser import LogEvent, parse_log_file as parse_ssh
from engine.parsers.web_parser import parse_log_file as parse_web
from engine.parsers.fim_parser import parse_log_file as parse_fim

logger = logging.getLogger(__name__)

PARSERS = {
    "ssh": parse_ssh,
    "web": parse_web,
    "fim": parse_fim,
}


def ingest_agent_logs(agent: Agent, log_source: str, filepath: Path) -> tuple[list[LogEvent], int]:
    """
    Parsea el archivo de log de un agente con el parser correcto para
    su fuente, y le asigna agent_id/hostname a cada evento resultante.

    Returns:
        (eventos parseados, líneas no parseadas)
    """
    parser = PARSERS[log_source]
    events, unparsed = parser(filepath)

    for event in events:
        event.agent_id = agent.agent_id
        if not event.hostname:
            event.hostname = agent.hostname

    logger.info(
        f"Ingesta {log_source} de {agent.hostname}: "
        f"{len(events)} eventos, {unparsed} sin parsear"
    )
    return events, unparsed
