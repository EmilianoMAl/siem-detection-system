import re
import logging
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class LogEvent:
    """
    Estructura normalizada de un evento de log.
    Cada campo tiene un tipo definido — no dicts sueltos.
    Esto es lo que va a la base de datos.
    """
    raw_line:       str
    timestamp:      Optional[str]
    hostname:       Optional[str]
    service:        Optional[str]
    pid:            Optional[int]
    event_type:     Optional[str]   # accepted, failed, invalid_user, sudo
    username:       Optional[str]
    source_ip:      Optional[str]
    source_port:    Optional[int]
    command:        Optional[str]   # solo para eventos sudo
    parsed_at:      str = ""

    def __post_init__(self):
        self.parsed_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return asdict(self)


# --- Patrones regex para cada tipo de evento ---
# Estos patrones son los mismos que usan herramientas como Logstash y Graylog

PATTERNS = {
    "accepted_password": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s[\d:]+)\s"
        r"(?P<hostname>\S+)\s"
        r"(?P<service>sshd)\[(?P<pid>\d+)\]:\s"
        r"Accepted password for (?P<username>\S+)\s"
        r"from (?P<source_ip>[\d.]+)\s"
        r"port (?P<source_port>\d+)"
    ),
    "failed_password": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s[\d:]+)\s"
        r"(?P<hostname>\S+)\s"
        r"(?P<service>sshd)\[(?P<pid>\d+)\]:\s"
        r"Failed password for (?P<username>\S+)\s"
        r"from (?P<source_ip>[\d.]+)\s"
        r"port (?P<source_port>\d+)"
    ),
    "invalid_user": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s[\d:]+)\s"
        r"(?P<hostname>\S+)\s"
        r"(?P<service>sshd)\[(?P<pid>\d+)\]:\s"
        r"Invalid user (?P<username>\S+)\s"
        r"from (?P<source_ip>[\d.]+)\s"
        r"port (?P<source_port>\d+)"
    ),
    "sudo_command": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s[\d:]+)\s"
        r"(?P<hostname>\S+)\s"
        r"(?P<service>sudo)\[(?P<pid>\d+)\]:\s"
        r"(?P<username>\S+)\s.*COMMAND=(?P<command>.+)"
    ),
}


def parse_line(line: str) -> Optional[LogEvent]:
    """
    Parsea una línea de log y retorna un LogEvent estructurado.
    Retorna None si la línea no coincide con ningún patrón conocido.

    Args:
        line: línea cruda del log

    Returns:
        LogEvent o None
    """
    line = line.strip()
    if not line:
        return None

    for event_type, pattern in PATTERNS.items():
        match = pattern.match(line)
        if match:
            groups = match.groupdict()
            return LogEvent(
                raw_line=line,
                timestamp=groups.get("timestamp"),
                hostname=groups.get("hostname"),
                service=groups.get("service"),
                pid=int(groups["pid"]) if groups.get("pid") else None,
                event_type=event_type,
                username=groups.get("username"),
                source_ip=groups.get("source_ip"),
                source_port=int(groups["source_port"]) if groups.get("source_port") else None,
                command=groups.get("command"),
            )

    return None


def parse_log_file(filepath: Path) -> tuple[list[LogEvent], int]:
    """
    Parsea un archivo de log completo.

    Args:
        filepath: ruta al archivo .log

    Returns:
        tuple (lista de LogEvents parseados, total de líneas no parseadas)
    """
    events = []
    unparsed = 0

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    logger.info(f"Parseando {len(lines)} líneas de {filepath.name}")

    for line in lines:
        event = parse_line(line)
        if event:
            events.append(event)
        else:
            unparsed += 1

    parse_rate = (len(events) / len(lines) * 100) if lines else 0
    logger.info(
        f"Parsing completado | "
        f"parseados={len(events)} | "
        f"no_parseados={unparsed} | "
        f"tasa={parse_rate:.1f}%"
    )
    return events, unparsed


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    )

    # Buscar el log más reciente
    raw_files = sorted(Path("logs/raw").glob("auth_log_*.log"))
    if not raw_files:
        logger.error("No hay logs en logs/raw/ — corre primero el generador")
        exit(1)

    latest = raw_files[-1]
    events, unparsed = parse_log_file(latest)

    # Mostrar resumen por tipo de evento
    from collections import Counter
    event_counts = Counter(e.event_type for e in events)

    print("\n=== RESUMEN DE EVENTOS ===")
    for event_type, count in event_counts.most_common():
        print(f"  {event_type:<25} {count:>5} eventos")

    print(f"\n=== MUESTRA DE EVENTOS PARSEADOS ===")
    for event in events[:3]:
        print(f"\n  tipo:    {event.event_type}")
        print(f"  ip:      {event.source_ip}")
        print(f"  usuario: {event.username}")
        print(f"  tiempo:  {event.timestamp}")