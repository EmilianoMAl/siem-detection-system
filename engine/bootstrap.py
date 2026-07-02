import logging
from typing import Optional

from engine.agents import Agent, SIMULATED_AGENTS, get_real_agent
from engine.log_generator import run_generator
from engine.pipeline import ingest_agent_logs
from engine.detectors.rules import DetectionEngine
from engine.storage import (
    initialize_db, insert_events, insert_alerts, register_agents,
    touch_agent, get_connection, get_max_alert_counter,
)

logger = logging.getLogger(__name__)


def bootstrap_data() -> None:
    """
    Si la base de datos no existe o está vacía, genera datos de demo
    para toda la flota de agentes (ssh/web/fim según cada agente) y
    corre el motor de detección. Corre una sola vez al iniciar el manager
    (la API la llama en su startup — es lógica de negocio, no de UI).
    """
    initialize_db()
    register_agents(SIMULATED_AGENTS)

    real_agent = get_real_agent()
    if real_agent:
        register_agents([real_agent])
        logger.info(f"Agente real registrado: {real_agent.hostname} ({real_agent.agent_id})")

    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()

    if count > 0:
        logger.info(f"DB ya tiene {count} eventos — se omite el bootstrap")
        return

    logger.info("DB vacía — generando datos de demo para toda la flota de agentes")
    generated = run_generator(
        agents=SIMULATED_AGENTS,
        duration_seconds=45,
        events_per_second=4.0,
        attack_probability=0.25,
        realtime=False,
    )
    all_events = []
    for agent, source, filepath in generated:
        events, _ = ingest_agent_logs(agent, source, filepath)
        all_events.extend(events)
        touch_agent(agent.agent_id)

    engine = DetectionEngine(start_counter=get_max_alert_counter())
    alerts = engine.run_all_rules(all_events)

    insert_events(all_events)
    insert_alerts(alerts)
    logger.info(f"Bootstrap completado: {len(all_events)} eventos, {len(alerts)} alertas")


def simulate_tick(
    agents: Optional[list[Agent]] = None,
    duration_seconds: int = 15,
    events_per_second: float = 2.0,
    attack_probability: float = 0.3,
) -> None:
    """
    Genera un lote nuevo (pequeño) de actividad simulada y lo procesa
    igual que el bootstrap — pero sin tocar el histórico. Pensado para
    correr periódicamente desde un tarea de fondo de la API, así el
    dashboard no se ve "congelado" y los agentes simulados no aparecen
    DISCONNECTED solo por no tener un heartbeat reciente.
    """
    agents = agents if agents is not None else SIMULATED_AGENTS

    generated = run_generator(
        agents=agents,
        duration_seconds=duration_seconds,
        events_per_second=events_per_second,
        attack_probability=attack_probability,
        realtime=False,
    )
    new_events = []
    for agent, source, filepath in generated:
        events, _ = ingest_agent_logs(agent, source, filepath)
        new_events.extend(events)
        touch_agent(agent.agent_id)

    engine = DetectionEngine(start_counter=get_max_alert_counter())
    alerts = engine.run_all_rules(new_events)

    insert_events(new_events)
    insert_alerts(alerts)
    logger.info(f"Tick de simulación: {len(new_events)} eventos nuevos, {len(alerts)} alertas nuevas")
