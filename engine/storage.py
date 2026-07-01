import sqlite3
import json
import logging
from pathlib import Path
from typing import Optional
from engine.parsers.auth_parser import LogEvent
from engine.detectors.rules import Alert
from engine.agents import Agent

logger = logging.getLogger(__name__)

DB_PATH = Path("data/siem.db")

# Ventana de "heartbeat": si un agente no reporta en este tiempo, se
# muestra como DISCONNECTED en vez de ACTIVE (igual que el panel de
# Agents de Wazuh).
AGENT_OFFLINE_AFTER_SECONDS = 600


def get_connection() -> sqlite3.Connection:
    """
    Retorna conexión a SQLite.
    check_same_thread=False necesario para Streamlit. timeout=30 + WAL
    evitan "database is locked" cuando una página está escribiendo
    (bootstrap) mientras otra lee (ej. la página Agents) al mismo tiempo.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row  # Resultados como diccionarios
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def initialize_db() -> None:
    """
    Crea las tablas si no existen.
    Idempotente — seguro de correr múltiples veces.

    Si la DB viene de una versión anterior de SENTINEL (sin agentes/
    multi-fuente), `events`/`alerts` existen pero con el esquema viejo
    (sin agent_id/log_source/metadata). Como son datos de demo
    regenerables y en despliegues como Streamlit Cloud no hay forma de
    borrar el archivo a mano, se detecta y se recrean automáticamente
    en vez de fallar al crear los índices nuevos.
    """
    conn = get_connection()
    cursor = conn.cursor()

    tables = {row[0] for row in cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "events" in tables:
        columns = {row[1] for row in cursor.execute("PRAGMA table_info(events)").fetchall()}
        if "agent_id" not in columns:
            logger.warning(
                "Esquema de 'events' desactualizado (sin agent_id) — "
                "recreando events/alerts con el esquema multi-agente"
            )
            cursor.executescript("DROP TABLE IF EXISTS events; DROP TABLE IF EXISTS alerts;")
            conn.commit()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            hostname      TEXT,
            agent_id      TEXT,
            log_source    TEXT DEFAULT 'ssh',   -- ssh | web | fim
            service       TEXT,
            event_type    TEXT NOT NULL,
            username      TEXT,
            source_ip     TEXT,
            source_port   INTEGER,
            command       TEXT,
            metadata      TEXT,   -- JSON con campos propios de cada fuente
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

        CREATE TABLE IF NOT EXISTS agents (
            agent_id      TEXT PRIMARY KEY,
            hostname      TEXT NOT NULL,
            ip_address    TEXT,
            os            TEXT,
            log_sources   TEXT,   -- JSON array, ej. ["ssh","web"]
            last_seen     TEXT,
            registered_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_events_source_ip
            ON events(source_ip);

        CREATE INDEX IF NOT EXISTS idx_events_event_type
            ON events(event_type);

        CREATE INDEX IF NOT EXISTS idx_events_agent_id
            ON events(agent_id);

        CREATE INDEX IF NOT EXISTS idx_events_log_source
            ON events(log_source);

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
    Inserta eventos parseados (de cualquier fuente: ssh/web/fim) en la
    base de datos. Usa batch insert para eficiencia.

    Returns:
        Número de eventos insertados
    """
    if not events:
        return 0

    conn = get_connection()
    cursor = conn.cursor()

    rows = [(
        e.timestamp, e.hostname, e.agent_id, e.log_source, e.service,
        e.event_type, e.username, e.source_ip, e.source_port, e.command,
        json.dumps(e.metadata or {}), e.raw_line, e.parsed_at
    ) for e in events]

    cursor.executemany("""
        INSERT INTO events (
            timestamp, hostname, agent_id, log_source, service, event_type,
            username, source_ip, source_port, command, metadata,
            raw_line, parsed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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


def register_agents(agents: list[Agent]) -> None:
    """
    Registra la flota de agentes conocida. INSERT OR IGNORE — si el
    agente ya existe no se pisa su last_seen/registered_at.
    """
    conn = get_connection()
    cursor = conn.cursor()

    for agent in agents:
        cursor.execute("""
            INSERT OR IGNORE INTO agents (
                agent_id, hostname, ip_address, os, log_sources
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            agent.agent_id, agent.hostname, agent.ip_address,
            agent.os, json.dumps(agent.log_sources)
        ))

    conn.commit()
    conn.close()


def touch_agent(agent_id: str) -> None:
    """Marca a un agente como visto ahora mismo (heartbeat)."""
    conn = get_connection()
    conn.execute(
        "UPDATE agents SET last_seen = datetime('now') WHERE agent_id = ?",
        (agent_id,)
    )
    conn.commit()
    conn.close()


def query_agents() -> list[dict]:
    """
    Lista los agentes con su estado (ACTIVE/DISCONNECTED según
    last_seen) y conteo de eventos/alertas asociados.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(f"""
        SELECT
            a.agent_id, a.hostname, a.ip_address, a.os, a.log_sources,
            a.last_seen, a.registered_at,
            CASE
                WHEN a.last_seen IS NULL THEN 'NEVER_CONNECTED'
                WHEN (strftime('%s','now') - strftime('%s', a.last_seen))
                     < {AGENT_OFFLINE_AFTER_SECONDS} THEN 'ACTIVE'
                ELSE 'DISCONNECTED'
            END AS status,
            (SELECT COUNT(*) FROM events e WHERE e.agent_id = a.agent_id) AS event_count,
            (SELECT COUNT(*) FROM alerts al WHERE al.hostname = a.hostname) AS alert_count
        FROM agents a
        ORDER BY a.hostname
    """)

    rows = []
    for row in cursor.fetchall():
        d = dict(row)
        d["log_sources"] = json.loads(d["log_sources"]) if d["log_sources"] else []
        rows.append(d)

    conn.close()
    return rows


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
                THEN 1 ELSE 0 END)                      as sudo_events,
            SUM(CASE WHEN log_source = 'web'
                THEN 1 ELSE 0 END)                      as web_events,
            SUM(CASE WHEN log_source = 'fim'
                THEN 1 ELSE 0 END)                      as fim_events
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
    """Top IPs con más intentos fallidos (ssh) o solicitudes maliciosas (web)."""
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


def _log_source_clause(log_source: str) -> tuple[str, tuple]:
    """
    Clausula SQL parametrizada para filtrar por fuente. Nunca interpola
    el valor directamente en el SQL — se expone vía API HTTP y un
    log_source arbitrario no debe poder inyectar SQL.
    """
    if log_source == "ALL":
        return "", ()
    return "AND log_source = ?", (log_source.lower(),)


def query_summary(log_source: str = "ALL") -> dict:
    """KPIs del dashboard (eventos, alertas, agentes), con filtro opcional por fuente."""
    conn = get_connection()
    clause, params = _log_source_clause(log_source)

    row = conn.execute(f"""
        SELECT
            COUNT(*) as total_events,
            COUNT(DISTINCT source_ip) as unique_ips,
            SUM(CASE WHEN event_type='failed_password' OR
                          event_type='invalid_user' THEN 1 ELSE 0 END) as failed_logins,
            SUM(CASE WHEN event_type='accepted_password' THEN 1 ELSE 0 END) as ok_logins,
            SUM(CASE WHEN event_type='sudo_command'      THEN 1 ELSE 0 END) as sudo_events
        FROM events WHERE 1=1 {clause}
    """, params).fetchone()

    alert_row = conn.execute("""
        SELECT COUNT(*) as total,
            SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as crit,
            SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END) as high
        FROM alerts
    """).fetchone()

    agent_row = conn.execute(f"""
        SELECT COUNT(*) as total,
            SUM(CASE WHEN (strftime('%s','now') - strftime('%s', last_seen)) < {AGENT_OFFLINE_AFTER_SECONDS}
                THEN 1 ELSE 0 END) as active
        FROM agents
    """).fetchone()

    conn.close()
    return {
        "total_events": row[0] or 0,
        "unique_ips":   row[1] or 0,
        "failed":       row[2] or 0,
        "ok_logins":    row[3] or 0,
        "sudo":         row[4] or 0,
        "total_alerts": alert_row[0] or 0,
        "critical":     alert_row[1] or 0,
        "high":         alert_row[2] or 0,
        "agents_total":  agent_row[0] or 0,
        "agents_active": agent_row[1] or 0,
    }


def query_top_ips(log_source: str = "ALL", limit: int = 8) -> list[dict]:
    """Top IPs por intentos fallidos (ssh) o requests (web), con filtro opcional por fuente."""
    conn = get_connection()
    clause, params = _log_source_clause(log_source)
    event_types = "('http_request')" if log_source == "WEB" else "('failed_password','invalid_user')"

    rows = conn.execute(f"""
        SELECT source_ip, COUNT(*) as attempts,
               COUNT(DISTINCT username) as targeted_users
        FROM events
        WHERE event_type IN {event_types}
          AND source_ip IS NOT NULL {clause}
        GROUP BY source_ip ORDER BY attempts DESC LIMIT ?
    """, params + (limit,)).fetchall()

    conn.close()
    return [dict(row) for row in rows]


def query_event_types(log_source: str = "ALL") -> list[dict]:
    """Distribución de eventos por tipo, con filtro opcional por fuente."""
    conn = get_connection()
    clause, params = _log_source_clause(log_source)

    rows = conn.execute(f"""
        SELECT event_type, COUNT(*) as n FROM events
        WHERE 1=1 {clause}
        GROUP BY event_type
    """, params).fetchall()

    conn.close()
    return [dict(row) for row in rows]


def query_timeline(log_source: str = "ALL") -> list[dict]:
    """Serie de tiempo de eventos por tipo, con filtro opcional por fuente."""
    conn = get_connection()
    clause, params = _log_source_clause(log_source)

    rows = conn.execute(f"""
        SELECT substr(timestamp, 1, 8) as hour,
               event_type, COUNT(*) as n
        FROM events WHERE 1=1 {clause}
        GROUP BY hour, event_type
        ORDER BY hour
    """, params).fetchall()

    conn.close()
    return [dict(row) for row in rows]


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    )

    from engine.agents import SIMULATED_AGENTS
    from engine.log_generator import run_generator
    from engine.pipeline import ingest_agent_logs
    from engine.detectors.rules import DetectionEngine

    # 1. Inicializar DB y registrar agentes
    initialize_db()
    register_agents(SIMULATED_AGENTS)

    # 2. Generar + parsear logs de todos los agentes
    generated = run_generator(agents=SIMULATED_AGENTS)
    all_events = []
    for agent, source, filepath in generated:
        events, _ = ingest_agent_logs(agent, source, filepath)
        all_events.extend(events)
        touch_agent(agent.agent_id)

    # 3. Detectar amenazas
    engine = DetectionEngine()
    alerts = engine.run_all_rules(all_events)

    # 4. Guardar en DB
    insert_events(all_events)
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
    print(f"  Eventos web:       {summary['web_events']}")
    print(f"  Eventos FIM:       {summary['fim_events']}")
    print(f"  Alertas totales:   {summary['total_alerts']}")
    print(f"  Críticas:          {summary['critical']}")
    print(f"  Altas:             {summary['high']}")

    print(f"\n  TOP IPs ATACANTES:")
    for ip in top_ips:
        print(f"  {ip['source_ip']:<20} {ip['attempts']:>5} intentos")
