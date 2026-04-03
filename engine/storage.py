import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from engine.parsers.auth_parser import LogEvent
from engine.detectors.rules import Alert

logger = logging.getLogger(__name__)

DB_PATH = Path("data/siem.db")


def get_connection() -> sqlite3.Connection:
    """
    Retorna conexión a SQLite.
    check_same_thread=False necesario para Streamlit.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Resultados como diccionarios
    return conn


def initialize_db() -> None:
    """
    Crea las tablas si no existen.
    Idempotente — seguro de correr múltiples veces.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            hostname      TEXT,
            service       TEXT,
            event_type    TEXT NOT NULL,
            username      TEXT,
            source_ip     TEXT,
            source_port   INTEGER,
            command       TEXT,
            raw_line      TEXT,
            parsed_at     TEXT,
            created_at    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id        TEXT UNIQUE NOT NULL,
            rule_name       TEXT NOT NULL,
            severity        TEXT NOT NULL,
            description     TEXT,
            source_ip       TEXT,
            username        TEXT,
            hostname        TEXT,
            evidence        TEXT,  -- JSON array
            recommendation  TEXT,
            mitre_technique TEXT,
            detected_at     TEXT,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_events_source_ip
            ON events(source_ip);

        CREATE INDEX IF NOT EXISTS idx_events_event_type
            ON events(event_type);

        CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON alerts(severity);

        CREATE INDEX IF NOT EXISTS idx_alerts_rule_name
            ON alerts(rule_name);
    """)

    conn.commit()
    conn.close()
    logger.info(f"Base de datos inicializada en {DB_PATH}")


def insert_events(events: list[LogEvent]) -> int:
    """
    Inserta eventos parseados en la base de datos.
    Usa batch insert para eficiencia.

    Returns:
        Número de eventos insertados
    """
    if not events:
        return 0

    conn = get_connection()
    cursor = conn.cursor()

    rows = [(
        e.timestamp, e.hostname, e.service,
        e.event_type, e.username, e.source_ip,
        e.source_port, e.command, e.raw_line, e.parsed_at
    ) for e in events]

    cursor.executemany("""
        INSERT INTO events (
            timestamp, hostname, service, event_type,
            username, source_ip, source_port, command,
            raw_line, parsed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    conn.commit()
    inserted = cursor.rowcount
    conn.close()

    logger.info(f"Eventos insertados: {inserted}")
    return inserted


def insert_alerts(alerts: list[Alert]) -> int:
    """
    Inserta alertas con INSERT OR IGNORE para evitar duplicados.

    Returns:
        Número de alertas insertadas
    """
    if not alerts:
        return 0

    conn = get_connection()
    cursor = conn.cursor()

    inserted = 0
    for alert in alerts:
        cursor.execute("""
            INSERT OR IGNORE INTO alerts (
                alert_id, rule_name, severity, description,
                source_ip, username, hostname, evidence,
                recommendation, mitre_technique, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.alert_id, alert.rule_name, alert.severity,
            alert.description, alert.source_ip, alert.username,
            alert.hostname, json.dumps(alert.evidence),
            alert.recommendation, alert.mitre_technique,
            alert.detected_at
        ))
        if cursor.rowcount > 0:
            inserted += 1

    conn.commit()
    conn.close()

    logger.info(f"Alertas insertadas: {inserted}")
    return inserted


def query_alerts(
    severity: Optional[str] = None,
    limit: int = 100
) -> list[dict]:
    """Consulta alertas con filtro opcional por severidad."""
    conn = get_connection()
    cursor = conn.cursor()

    if severity:
        cursor.execute("""
            SELECT * FROM alerts
            WHERE severity = ?
            ORDER BY detected_at DESC
            LIMIT ?
        """, (severity, limit))
    else:
        cursor.execute("""
            SELECT * FROM alerts
            ORDER BY detected_at DESC
            LIMIT ?
        """, (limit,))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def query_events_summary() -> dict:
    """Resumen estadístico de eventos para el dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            COUNT(*)                                    as total_events,
            COUNT(DISTINCT source_ip)                   as unique_ips,
            COUNT(DISTINCT username)                    as unique_users,
            SUM(CASE WHEN event_type = 'failed_password'
                THEN 1 ELSE 0 END)                      as failed_logins,
            SUM(CASE WHEN event_type = 'accepted_password'
                THEN 1 ELSE 0 END)                      as successful_logins,
            SUM(CASE WHEN event_type = 'sudo_command'
                THEN 1 ELSE 0 END)                      as sudo_events
        FROM events
    """)

    row = dict(cursor.fetchone())

    cursor.execute("""
        SELECT
            COUNT(*) as total_alerts,
            SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'HIGH'     THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'MEDIUM'   THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'LOW'      THEN 1 ELSE 0 END) as low
        FROM alerts
    """)

    row.update(dict(cursor.fetchone()))
    conn.close()
    return row


def query_top_attacking_ips(limit: int = 10) -> list[dict]:
    """Top IPs con más intentos fallidos."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            COUNT(*) as attempts,
            COUNT(DISTINCT username) as targeted_users
        FROM events
        WHERE event_type IN ('failed_password', 'invalid_user')
            AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY attempts DESC
        LIMIT ?
    """, (limit,))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    )

    from pathlib import Path
    from engine.parsers.auth_parser import parse_log_file
    from engine.detectors.rules import DetectionEngine

    # 1. Inicializar DB
    initialize_db()

    # 2. Parsear logs
    raw_files = sorted(Path("logs/raw").glob("auth_log_*.log"))
    if not raw_files:
        logger.error("No hay logs — corre primero el generador")
        exit(1)

    events, _ = parse_log_file(raw_files[-1])

    # 3. Detectar amenazas
    engine = DetectionEngine()
    alerts = engine.run_all_rules(events)

    # 4. Guardar en DB
    insert_events(events)
    insert_alerts(alerts)

    # 5. Verificar resultados
    summary = query_events_summary()
    top_ips = query_top_attacking_ips(5)

    print(f"\n{'='*50}")
    print(f"  RESUMEN DE LA BASE DE DATOS")
    print(f"{'='*50}")
    print(f"  Total eventos:     {summary['total_events']}")
    print(f"  IPs únicas:        {summary['unique_ips']}")
    print(f"  Logins fallidos:   {summary['failed_logins']}")
    print(f"  Logins exitosos:   {summary['successful_logins']}")
    print(f"  Alertas totales:   {summary['total_alerts']}")
    print(f"  Críticas:          {summary['critical']}")
    print(f"  Altas:             {summary['high']}")

    print(f"\n  TOP IPs ATACANTES:")
    for ip in top_ips:
        print(f"  {ip['source_ip']:<20} {ip['attempts']:>5} intentos")