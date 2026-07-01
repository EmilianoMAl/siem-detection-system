from dataclasses import dataclass


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
    log_sources: list[str]   # subconjunto de ("ssh", "web", "fim")


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
