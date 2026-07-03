import os
from dataclasses import dataclass


REAL_AGENT_ID = "agent-real-vm"
SYSLOG_AGENT_ID = "agent-syslog-fw"

# agent_id de todo lo que representa datos REALES (no simulados) — se
# usa para backfillear la columna environment en storage.initialize_db().
REAL_AGENT_IDS = (REAL_AGENT_ID, SYSLOG_AGENT_ID)


@dataclass
class Agent:
    """
    Host monitoreado por SENTINEL — equivalente conceptual a un
    agente de Wazuh. Por ahora son hosts simulados; en el modo
    "agente real" (VM) esto pasa a ser un registro que se crea
    cuando un daemon remoto se conecta al manager.
    """
    agent_id:    str
    hostname:    str
    ip_address:  str
    os:          str
    log_sources: list[str]   # subconjunto de ("ssh", "web", "fim", "sonicwall")
    environment: str = "simulated"   # "simulated" | "real_vm"


# Flota simulada por defecto. Cada agente sólo genera/reporta
# las fuentes de log que tiene habilitadas.
SIMULATED_AGENTS: list[Agent] = [
    Agent(
        agent_id="agent-001",
        hostname="prod-server-01",
        ip_address="10.0.0.5",
        os="Ubuntu 22.04 LTS",
        log_sources=["ssh", "fim"],
    ),
    Agent(
        agent_id="agent-002",
        hostname="web-server-02",
        ip_address="10.0.0.12",
        os="Ubuntu 22.04 LTS",
        log_sources=["ssh", "web"],
    ),
    Agent(
        agent_id="agent-003",
        hostname="db-server-03",
        ip_address="192.168.1.20",
        os="Debian 12",
        log_sources=["ssh", "fim"],
    ),
    Agent(
        agent_id="agent-004",
        hostname="mail-server-04",
        ip_address="192.168.1.15",
        os="Rocky Linux 9",
        log_sources=["ssh"],
    ),
]


def get_agent(agent_id: str) -> Agent | None:
    return next((a for a in SIMULATED_AGENTS if a.agent_id == agent_id), None)


def get_real_agent() -> Agent | None:
    """
    Agente real (opcional): representa el host de verdad donde corre
    SENTINEL, reportando tráfico genuino (ver agent/ship_logs.py). Se
    arma desde variables de entorno en vez de hardcodear la IP/hostname
    de una VM específica en el código fuente — sin configurar, no hay
    agente real y el repo se comporta igual que siempre (solo demo).
    """
    hostname = os.environ.get("SENTINEL_REAL_AGENT_HOSTNAME")
    if not hostname:
        return None

    return Agent(
        agent_id=REAL_AGENT_ID,
        hostname=hostname,
        ip_address=os.environ.get("SENTINEL_REAL_AGENT_IP", ""),
        os=os.environ.get("SENTINEL_REAL_AGENT_OS", "Linux"),
        log_sources=["ssh", "web"],
        environment="real_vm",
    )


def get_syslog_agent() -> Agent:
    """
    Agente que representa al emisor de syslog externo (ej. un firewall
    SonicWall en la red del trabajo del usuario) — todo lo que llega al
    receptor de syslog (ver engine/syslog_listener.py) se atribuye a
    este agente fijo. A diferencia de get_real_agent(), siempre existe
    (con defaults razonables) porque no requiere ningún secreto — el
    puerto de syslog en sí ya está protegido por firewall (ufw/OCI),
    no por un token como /ingest.
    """
    return Agent(
        agent_id=os.environ.get("SENTINEL_SYSLOG_AGENT_ID", SYSLOG_AGENT_ID),
        hostname=os.environ.get("SENTINEL_SYSLOG_HOSTNAME", "sonicwall-fw"),
        ip_address=os.environ.get("SENTINEL_SYSLOG_IP", ""),
        os="SonicOS",
        log_sources=["sonicwall"],
        environment="real_vm",
    )


def find_known_agent(agent_id: str) -> Agent | None:
    """Busca por id entre los agentes simulados, el agente real o el de syslog."""
    agent = get_agent(agent_id)
    if agent:
        return agent
    real_agent = get_real_agent()
    if real_agent and real_agent.agent_id == agent_id:
        return real_agent
    syslog_agent = get_syslog_agent()
    if syslog_agent.agent_id == agent_id:
        return syslog_agent
    return None
