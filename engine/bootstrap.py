import logging

from engine.agents import SIMULATED_AGENTS
from engine.log_generator import run_generator
from engine.pipeline import ingest_agent_logs
from engine.detectors.rules import DetectionEngine
from engine.storage import (
    initialize_db, insert_events, insert_alerts, register_agents,
    touch_agent, get_connection,
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

    engine = DetectionEngine()
    alerts = engine.run_all_rules(all_events)

    insert_events(all_events)
    insert_alerts(alerts)
    logger.info(f"Bootstrap completado: {len(all_events)} eventos, {len(alerts)} alertas")
