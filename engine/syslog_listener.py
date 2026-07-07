import asyncio
import logging
import re

from engine.agents import Agent, resolve_syslog_agent
from engine.parsers import auth_parser, web_parser, sonicwall_parser, wazuh_syslog_parser, generic_syslog_parser
from engine.pipeline import ingest_lines_multi
from engine.detectors.rules import DetectionEngine
from engine.storage import get_max_alert_counter, insert_events, insert_alerts, touch_agent, register_agents

logger = logging.getLogger(__name__)

# Las líneas que llegan por UDP se acumulan y se procesan en lote cada
# tantos segundos -- igual que agent/ship_logs.py agrupa varias líneas
# por POST cada 30s. Sin este agrupado, cada paquete se evaluaría solo
# contra sí mismo y una regla tipo "N rechazos en poco tiempo" nunca
# podría disparar (nunca habría más de 1 evento por corrida del motor
# de detección).
SYSLOG_FLUSH_SECONDS = 15

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
    _specific(wazuh_syslog_parser.parse_line),  # tag "ossec:" inconfundible, va primero
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

    def _resolve(sender_ip, event):
        agent = resolved_agents.get(sender_ip)
        if agent is None:
            agent = resolve_syslog_agent(sender_ip, claimed_hostname=event.hostname)
            resolved_agents[sender_ip] = agent
        return agent

    items = [(line, {"sender_ip": sender_ip}) for line, sender_ip in packets]
    events, unparsed = ingest_lines_multi(_resolve, items, PARSER_CHAIN)
    if not events:
        if unparsed:
            logger.debug(f"{unparsed} línea(s) de syslog no reconocidas")
        return

    register_agents(list(resolved_agents.values()))

    engine = DetectionEngine(start_counter=get_max_alert_counter())
    alerts = engine.run_all_rules(events)

    insert_events(events)
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
