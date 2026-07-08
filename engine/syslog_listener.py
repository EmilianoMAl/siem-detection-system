import asyncio
import logging
import re
import time

from engine.agents import Agent, resolve_syslog_agent, resolve_wazuh_agent
from engine.parsers import (
    auth_parser, web_parser, sonicwall_parser, wazuh_syslog_parser,
    windows_eventlog_parser, generic_syslog_parser,
)
from engine.pipeline import ingest_lines_multi
from engine.detectors.rules import DetectionEngine, Alert
from engine.storage import (
    get_max_alert_counter, insert_events, insert_alerts, touch_agent, register_agents,
    query_recent_events_for_detection,
)

logger = logging.getLogger(__name__)

# Las líneas que llegan por UDP se acumulan y se procesan en lote cada
# tantos segundos, solo para agrupar eficientemente lo que haya llegado
# casi al mismo tiempo -- YA NO define la ventana de correlación de las
# reglas con estado (ver STATEFUL_RULES / query_recent_events_for_detection
# más abajo), así que se puede mantener bajo sin perder alertas por
# umbral. Antes este valor SÍ era la ventana de correlación completa
# (por eso estaba en 15s) -- se dejó así de bajo a propósito para que el
# tiempo entre "algo pasa en la VM" y "aparece en el dashboard" sea de
# unos segundos, no de hasta 15+.
SYSLOG_FLUSH_SECONDS = 2

# Ventana rodante (por created_at, el reloj propio de SENTINEL) contra
# la que se evalúan las reglas con estado -- independiente de qué tan
# seguido corre el flush de arriba. 5 minutos es suficiente para que un
# brute force / password spraying / recon scan típico se vea completo
# aunque el atacante reparta los intentos en varios lotes de 2s.
STATEFUL_WINDOW_SECONDS = 300

# Sin esto, una condición que se sigue cumpliendo (ej. un atacante que
# sigue mandando intentos fallidos) volvería a alertar en cada tick de
# SYSLOG_FLUSH_SECONDS mientras dure -- antes pasaba cada 15s, ahora con
# un flush de 2s sería 7x más ruido para el mismo ataque. Se suprime
# re-alertar la misma (regla, IP/usuario) dentro de este cooldown.
# Limitación conocida: si la misma combinación (regla, IP/usuario) ya
# alertada sigue dentro de STATEFUL_WINDOW_SECONDS cuando el cooldown
# expira, puede volver a dispararse aunque el evento que la originó ya
# no sea nuevo -- deduplicar por evento puntual (no solo por IP/usuario)
# requeriría trackear qué eventos ya contribuyeron a una alerta, fuera
# de alcance por ahora. Prioriza no perder alertas sobre no repetir
# alguna ocasional.
ALERT_COOLDOWN_SECONDS = 120
_last_alerted: dict[tuple[str, str], float] = {}


def reset_alert_cooldowns() -> None:
    """Limpia el cooldown de supresión -- usado por los tests para aislarse entre corridas."""
    _last_alerted.clear()


def _is_suppressed(alert: Alert) -> bool:
    key = (alert.rule_name, alert.source_ip or alert.username or alert.hostname or "")
    now = time.monotonic()
    last = _last_alerted.get(key)
    if last is not None and now - last < ALERT_COOLDOWN_SECONDS:
        return True
    _last_alerted[key] = now
    return False

# El emisor de syslog puede ser cualquier cosa: un cliente Linux con
# rsyslog reenviando su propio auth.log (formato RFC3164 estándar:
# "<PRI>TIMESTAMP HOSTNAME TAG[PID]: MENSAJE"), un firewall SonicWall
# real, o cualquier otro dispositivo -- no hay un log_source fijo de
# antemano. Se prueban parsers en orden de más a menos específico sobre
# la línea sin el prefijo <PRI> (auth_parser reconoce exactamente el
# formato que queda después de sacarlo: "TIMESTAMP HOSTNAME TAG[PID]:
# MENSAJE"), así un ataque SSH real reenviado por rsyslog se clasifica
# como evento ssh de verdad y puede disparar SSH_BRUTE_FORCE/etc, no
# solo quedar guardado como texto plano.
PRI_RE = re.compile(r"^<\d{1,3}>")


def _strip_pri(line: str) -> str:
    return PRI_RE.sub("", line, count=1)


def _specific(parser):
    """Envuelve un parser para que reciba la línea sin <PRI>, pero conserve la línea original en raw_line."""
    def wrapped(line: str):
        event = parser(_strip_pri(line))
        if event:
            event.raw_line = line
        return event
    return wrapped


PARSER_CHAIN = [
    _specific(wazuh_syslog_parser.parse_line),        # tag "ossec:" inconfundible, va primero
    _specific(windows_eventlog_parser.parse_line),    # tag "sentinel_winlog:" -- Windows sin Wazuh de por medio
    _specific(auth_parser.parse_line),
    _specific(web_parser.parse_line),
    _specific(sonicwall_parser.parse_line),
    generic_syslog_parser.parse_line,  # catch-all; ya maneja el <PRI> opcional
]


async def process_syslog_batch(packets: list[tuple[str, str]]) -> None:
    """
    Procesa un lote de paquetes de syslog ya recibidos: parsea (probando
    varios formatos), resuelve a qué agente pertenece cada uno POR SU IP
    REAL (un mismo lote puede traer líneas de más de un cliente a la vez
    -- ej. la VM Linux y una VM de Windows), corre el motor de
    detección, inserta. Separada de la recepción UDP para poder
    probarla directo con una lista de (línea, ip_emisor), sin sockets ni
    temporizadores de por medio.

    ip_emisor es la IP real que mandó el paquete UDP -- se usa para
    resolver el agente (ver engine.agents.resolve_syslog_agent) y
    también se guarda en event.metadata["sender_ip"], distinta del
    `source_ip` que algunos parsers ya extraen del propio contenido del
    log (ej. la IP atacante en una línea de SSH/SonicWall).
    """
    if not packets:
        return

    # Se resuelve un agente por cada IP distinta vista en el lote, la
    # primera vez que aparece (no una por línea) -- usando el hostname
    # que el propio evento ya parseado trae (ej. "wazuh-srv-Virtual-Machine"
    # extraído por auth_parser/generic_syslog_parser), para que un
    # agente autogenerado (IP sin configurar en SENTINEL_SYSLOG_CLIENTS)
    # quede con un nombre legible en vez de solo la IP.
    resolved_agents: dict[str, Agent] = {}

    def _agent_key(sender_ip: str, event) -> str:
        # Un manager de Wazuh reenvía por syslog tanto sus propias
        # alertas locales como las de cualquier endpoint remoto que
        # tenga enrolado (ej. un Windows) -- todas comparten el mismo
        # remitente UDP (el manager), así que agrupar solo por
        # sender_ip las mezclaría todas bajo un único agente. Se
        # desambigua por wazuh_agent_id cuando está presente.
        wazuh_agent_id = (event.metadata or {}).get("wazuh_agent_id")
        if event.log_source in ("wazuh", "fim") and wazuh_agent_id and wazuh_agent_id != "000":
            return f"wazuh:{wazuh_agent_id}"
        return sender_ip

    def _resolve(sender_ip, event):
        key = _agent_key(sender_ip, event)
        agent = resolved_agents.get(key)
        if agent is None:
            wazuh_agent_id = (event.metadata or {}).get("wazuh_agent_id")
            if event.log_source in ("wazuh", "fim") and wazuh_agent_id and wazuh_agent_id != "000":
                agent = resolve_wazuh_agent(
                    sender_ip, event.hostname, wazuh_agent_id,
                    event.metadata.get("wazuh_agent_name"), event.metadata.get("wazuh_agent_ip"),
                )
            else:
                agent = resolve_syslog_agent(sender_ip, claimed_hostname=event.hostname)
            resolved_agents[key] = agent
        return agent

    items = [(line, {"sender_ip": sender_ip}) for line, sender_ip in packets]
    events, unparsed = ingest_lines_multi(_resolve, items, PARSER_CHAIN)
    if not events:
        if unparsed:
            logger.debug(f"{unparsed} línea(s) de syslog no reconocidas")
        return

    register_agents(list(resolved_agents.values()))

    # Se inserta ANTES de correr las reglas con estado -- necesitan ver
    # estos eventos recién llegados también dentro de su ventana rodante
    # (query_recent_events_for_detection lee de la BD, no de `events`).
    insert_events(events)

    engine = DetectionEngine(start_counter=get_max_alert_counter())

    # Reglas sin estado: solo necesitan los eventos que acaban de llegar,
    # no dependen de historial -- se evalúan de inmediato, sin ir a la BD.
    alerts = []
    alerts.extend(engine.detect_fim_critical_change(events))
    alerts.extend(engine.detect_web_attacks(events))
    alerts.extend(engine.detect_suspicious_commands(events))
    alerts.extend(engine.detect_account_creation(events))
    alerts.extend(engine.detect_wazuh_promoted_alert(events))
    alerts.extend(engine.detect_windows_account_events(events))

    # Reglas con estado: necesitan ver un historial, no solo este lote
    # -- se re-evalúan contra una ventana rodante en la BD, solo para
    # las fuentes que de verdad llegaron en este lote (evita consultas
    # de más en cada tick de 2s cuando no llegó nada relevante).
    sources_present = {e.log_source for e in events}
    if "ssh" in sources_present:
        window = query_recent_events_for_detection(("ssh",), STATEFUL_WINDOW_SECONDS)
        alerts.extend(engine.detect_brute_force(window))
        alerts.extend(engine.detect_password_spraying(window))
        alerts.extend(engine.detect_successful_login_after_failures(window))
    if "web" in sources_present:
        window = query_recent_events_for_detection(("web",), STATEFUL_WINDOW_SECONDS)
        alerts.extend(engine.detect_recon_scan(window))
    if "sonicwall" in sources_present:
        window = query_recent_events_for_detection(("sonicwall",), STATEFUL_WINDOW_SECONDS)
        alerts.extend(engine.detect_sonicwall_repeated_denials(window))
    if "windows" in sources_present:
        window = query_recent_events_for_detection(("windows",), STATEFUL_WINDOW_SECONDS)
        alerts.extend(engine.detect_windows_brute_force(window))
        alerts.extend(engine.detect_windows_login_after_failures(window))

    alerts = [a for a in alerts if not _is_suppressed(a)]

    insert_alerts(alerts)
    for agent in resolved_agents.values():
        touch_agent(agent.agent_id)


class SyslogProtocol(asyncio.DatagramProtocol):
    """Protocolo UDP mínimo: cada datagrama es un mensaje de syslog completo (RFC3164/5424)."""

    def __init__(self, buffer: list[tuple[str, str]]):
        self._buffer = buffer

    def datagram_received(self, data: bytes, addr) -> None:
        line = data.decode("utf-8", errors="replace").strip()
        if line:
            self._buffer.append((line, addr[0]))


async def _flush_loop(buffer: list[tuple[str, str]]) -> None:
    while True:
        await asyncio.sleep(SYSLOG_FLUSH_SECONDS)
        if not buffer:
            continue
        packets, buffer[:] = list(buffer), []
        try:
            await process_syslog_batch(packets)
        except Exception:
            logger.exception("Error procesando lote de syslog — se reintenta en el siguiente ciclo")


async def start_syslog_listener(ports: list[int]) -> tuple:
    """
    Arranca el receptor de syslog en UDP en cada uno de los puertos
    dados (ej. el principal más alguno extra para separar otra fuente o
    hacer pruebas sin tocar el que ya funciona) más su tarea de flush
    periódico. Todos los puertos comparten el mismo buffer -- el lote
    que se procesa cada SYSLOG_FLUSH_SECONDS mezcla lo que haya llegado
    por cualquiera de ellos, la resolución de agente por sender_ip ya
    se encarga de no mezclar los datos entre clientes distintos.

    Retorna (transports, flush_task) para que el caller (lifespan de la
    API) los pueda cerrar/cancelar al apagar.
    """
    buffer: list[tuple[str, str]] = []
    loop = asyncio.get_running_loop()
    transports = []
    for port in ports:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(buffer), local_addr=("0.0.0.0", port)
        )
        transports.append(transport)
    flush_task = asyncio.create_task(_flush_loop(buffer))
    logger.info(f"Receptor de syslog escuchando en UDP :{ports} (lote cada {SYSLOG_FLUSH_SECONDS}s)")
    return transports, flush_task
