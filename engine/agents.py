import os
import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


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
    # "or" en vez de os.environ.get(key, default): docker-compose pasa
    # ${VAR:-} como string vacío (no como variable ausente) cuando no
    # está definida en .env, y .get() solo usa el default si la key no
    # existe -- con un valor vacío ya "existe" y pisaría el default.
    return Agent(
        agent_id=os.environ.get("SENTINEL_SYSLOG_AGENT_ID") or SYSLOG_AGENT_ID,
        hostname=os.environ.get("SENTINEL_SYSLOG_HOSTNAME") or "sonicwall-fw",
        ip_address=os.environ.get("SENTINEL_SYSLOG_IP", ""),
        os="SonicOS",
        log_sources=["sonicwall"],
        environment="real_vm",
    )


def _load_syslog_clients() -> dict:
    """
    Parsea SENTINEL_SYSLOG_CLIENTS (JSON: IP -> {agent_id, hostname, os})
    -- mapea clientes reales de syslog conocidos a una identidad legible,
    en vez de agruparlos todos bajo un solo agente fijo. Si no está
    configurada o el JSON es inválido, se devuelve vacío (no revienta
    el receptor de syslog por un typo en .env).
    """
    raw = os.environ.get("SENTINEL_SYSLOG_CLIENTS")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("SENTINEL_SYSLOG_CLIENTS no es JSON válido -- se ignora")
        return {}


def resolve_syslog_agent(sender_ip: str, claimed_hostname: str | None = None) -> Agent:
    """
    Resuelve qué agente representa a quien mandó un paquete de syslog,
    por su IP real (no por lo que el propio mensaje dice ser, que no es
    confiable). Si sender_ip está en SENTINEL_SYSLOG_CLIENTS, usa esa
    identidad configurada; si no, autogenera un agente por IP para no
    perder el dato ni mezclarlo con otros -- solo queda con un nombre
    menos amigable ("Unknown") hasta que se agregue a la configuración.
    """
    clients = _load_syslog_clients()
    cfg = clients.get(sender_ip, {})

    return Agent(
        agent_id=cfg.get("agent_id") or f"agent-syslog-{sender_ip.replace('.', '-')}",
        hostname=cfg.get("hostname") or claimed_hostname or sender_ip,
        ip_address=sender_ip,
        os=cfg.get("os") or "Unknown",
        log_sources=["syslog"],
        environment="real_vm",
    )


def _load_wazuh_agents() -> dict:
    """
    Parsea SENTINEL_WAZUH_AGENTS (JSON: wazuh_agent_id -> {agent_id,
    hostname, os}) -- mismo patrón que SENTINEL_SYSLOG_CLIENTS pero
    para endpoints enrolados en el Wazuh manager (ej. un Windows con
    el agente de Wazuh instalado), que no se pueden identificar por IP
    porque todos llegan por el mismo remitente UDP (el manager).
    """
    raw = os.environ.get("SENTINEL_WAZUH_AGENTS")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("SENTINEL_WAZUH_AGENTS no es JSON válido -- se ignora")
        return {}


def resolve_wazuh_agent(
    sender_ip: str,
    claimed_hostname: str | None,
    wazuh_agent_id: str | None,
    wazuh_agent_name: str | None,
    wazuh_agent_ip: str | None,
) -> Agent:
    """
    Resuelve a qué agente SENTINEL pertenece una alerta de Wazuh.
    wazuh_agent_id "000" (o ausente) es el propio manager -- se
    resuelve igual que cualquier otro syslog, por su IP real (mantiene
    la identidad existente, ej. agent-linux-wazuh). Cualquier otro id
    es un endpoint remoto de verdad enrolado en ese manager (ej. un
    Windows con el agente de Wazuh) -- todos comparten el mismo
    remitente UDP (el manager), así que se identifican por
    wazuh_agent_id, no por IP.
    """
    if not wazuh_agent_id or wazuh_agent_id == "000":
        return resolve_syslog_agent(sender_ip, claimed_hostname)

    cfg = _load_wazuh_agents().get(wazuh_agent_id, {})
    return Agent(
        agent_id=cfg.get("agent_id") or f"agent-wazuh-{wazuh_agent_id}",
        hostname=cfg.get("hostname") or wazuh_agent_name or f"wazuh-agent-{wazuh_agent_id}",
        ip_address=wazuh_agent_ip or "",
        os=cfg.get("os") or "Unknown",
        log_sources=["wazuh"],
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
