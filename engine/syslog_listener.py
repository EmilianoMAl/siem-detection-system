import asyncio
import logging

from engine.agents import get_syslog_agent
from engine.pipeline import ingest_lines
from engine.detectors.rules import DetectionEngine
from engine.storage import get_max_alert_counter, insert_events, insert_alerts, touch_agent

logger = logging.getLogger(__name__)

# Las líneas que llegan por UDP se acumulan y se procesan en lote cada
# tantos segundos -- igual que agent/ship_logs.py agrupa varias líneas
# por POST cada 30s. Sin este agrupado, cada paquete se evaluaría solo
# contra sí mismo y una regla tipo "N rechazos en poco tiempo" nunca
# podría disparar (nunca habría más de 1 evento por corrida del motor
# de detección).
SYSLOG_FLUSH_SECONDS = 15


async def process_syslog_batch(lines: list[str]) -> None:
    """
    Procesa un lote de líneas de syslog ya recibidas: parsea, corre el
    motor de detección, inserta. Separada de la recepción UDP para
    poder probarla directo con una lista de strings, sin sockets ni
    temporizadores de por medio.
    """
    if not lines:
        return

    agent = get_syslog_agent()
    events, unparsed = ingest_lines(agent, "sonicwall", lines)
    if not events:
        if unparsed:
            logger.debug(f"{unparsed} línea(s) de syslog no reconocidas")
        return

    engine = DetectionEngine(start_counter=get_max_alert_counter())
    alerts = engine.run_all_rules(events)

    insert_events(events)
    insert_alerts(alerts)
    touch_agent(agent.agent_id)


class SyslogProtocol(asyncio.DatagramProtocol):
    """Protocolo UDP mínimo: cada datagrama es un mensaje de syslog completo (RFC3164/5424)."""

    def __init__(self, buffer: list[str]):
        self._buffer = buffer

    def datagram_received(self, data: bytes, addr) -> None:
        line = data.decode("utf-8", errors="replace").strip()
        if line:
            self._buffer.append(line)


async def _flush_loop(buffer: list[str]) -> None:
    while True:
        await asyncio.sleep(SYSLOG_FLUSH_SECONDS)
        if not buffer:
            continue
        lines, buffer[:] = list(buffer), []
        try:
            await process_syslog_batch(lines)
        except Exception:
            logger.exception("Error procesando lote de syslog — se reintenta en el siguiente ciclo")


async def start_syslog_listener(port: int) -> tuple:
    """
    Arranca el receptor de syslog en UDP :port más su tarea de flush
    periódico. Retorna (transport, flush_task) para que el caller
    (lifespan de la API) los pueda cerrar/cancelar al apagar.
    """
    buffer: list[str] = []
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(buffer), local_addr=("0.0.0.0", port)
    )
    flush_task = asyncio.create_task(_flush_loop(buffer))
    logger.info(f"Receptor de syslog escuchando en UDP :{port} (lote cada {SYSLOG_FLUSH_SECONDS}s)")
    return transport, flush_task
