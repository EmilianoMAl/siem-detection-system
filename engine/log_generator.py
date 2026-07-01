import logging
from datetime import datetime
from pathlib import Path

from engine.agents import Agent, SIMULATED_AGENTS
from engine.generators.ssh_generator import run_ssh_stream
from engine.generators.web_generator import run_web_stream
from engine.generators.fim_generator import run_fim_stream

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

RAW_LOGS_PATH = Path("logs/raw")

STREAM_RUNNERS = {
    "ssh": lambda agent, path, **kw: run_ssh_stream(agent.hostname, path, **kw),
    "web": lambda agent, path, **kw: run_web_stream(path, **kw),
    "fim": lambda agent, path, **kw: run_fim_stream(agent.hostname, path, **kw),
}


def run_generator(
    agents: list[Agent] = None,
    duration_seconds: int = 30,
    events_per_second: float = 3.0,
    attack_probability: float = 0.2,
    realtime: bool = False,
) -> list[tuple[Agent, str, Path]]:
    """
    Orquesta la generación de logs para toda la flota de agentes.
    Cada agente genera un archivo por cada fuente que tiene habilitada
    (ssh/web/fim), en logs/raw/{agent_id}_{source}_{timestamp}.log.

    Args:
        realtime: False (default) genera todo el lote sin pausas —
            es lo que usa el bootstrap del dashboard para no tardar
            minutos con varios agentes/fuentes. True simula un stream
            en vivo (útil para `python -m engine.log_generator`).

    Returns:
        Lista de (agent, log_source, filepath) — uno por combinación
        agente/fuente generada, para que el pipeline de ingesta sepa
        qué parser usar y a qué agente atribuir los eventos.
    """
    agents = agents or SIMULATED_AGENTS
    RAW_LOGS_PATH.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    results = []
    for agent in agents:
        for source in agent.log_sources:
            runner = STREAM_RUNNERS[source]
            output_file = RAW_LOGS_PATH / f"{agent.agent_id}_{source}_{timestamp}.log"
            logger.info(f"Generando {source} para {agent.hostname} ({agent.agent_id})")
            path = runner(
                agent,
                output_file,
                duration_seconds=duration_seconds,
                events_per_second=events_per_second,
                attack_probability=attack_probability,
                realtime=realtime,
            )
            results.append((agent, source, path))

    return results


if __name__ == "__main__":
    # Demo en vivo: genera 20s de logs por fuente, con pausas reales.
    generated = run_generator(duration_seconds=20, events_per_second=3.0,
                               attack_probability=0.2, realtime=True)
    for agent, source, path in generated:
        logger.info(f"{agent.hostname} [{source}] -> {path}")
