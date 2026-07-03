import sqlite3
import json
import logging
from pathlib import Path
from typing import Optional
from engine.parsers.auth_parser import LogEvent
from engine.detectors.rules import Alert
from engine.agents import Agent, REAL_AGENT_IDS
from engine.geoip import is_private_ip, lookup_ip

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

    if "alerts" in tables:
        # A diferencia de 'events', 'alerts' puede tener datos reales
        # valiosos (alertas del agente real) — nunca se recrea, solo se
        # le agregan columnas nuevas de forma aditiva si faltan.
        columns = {row[1] for row in cursor.execute("PRAGMA table_info(alerts)").fetchall()}
        if "status" not in columns:
            logger.info("Agregando columnas de gestión de alertas (status/note/resolved_at)")
            cursor.executescript("""
                ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'OPEN';
                ALTER TABLE alerts ADD COLUMN note TEXT;
                ALTER TABLE alerts ADD COLUMN resolved_at TEXT;
            """)
            conn.commit()

    # "environment" (simulated | real_vm) es una dimensión nueva y
    # ortogonal a log_source -- aditiva en las 3 tablas para no perder
    # el histórico real ya insertado. Se backfillea con los agent_id/
    # hostnames reales ya conocidos (agente SSH real + agente syslog).
    for table in ("events", "alerts", "agents"):
        if table not in tables:
            continue
        columns = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()}
        if "environment" not in columns:
            logger.info(f"Agregando columna environment a '{table}'")
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN environment TEXT DEFAULT 'simulated'")
            conn.commit()

    real_agent_ids = tuple(REAL_AGENT_IDS)
    placeholders = ",".join("?" * len(real_agent_ids))
    if "events" in tables:
        cursor.execute(
            f"UPDATE events SET environment='real_vm' WHERE agent_id IN ({placeholders})",
            real_agent_ids,
        )
    if "agents" in tables:
        cursor.execute(
            f"UPDATE agents SET environment='real_vm' WHERE agent_id IN ({placeholders})",
            real_agent_ids,
        )
    if "alerts" in tables and "agents" in tables:
        real_hostnames = tuple(
            row[0] for row in cursor.execute(
                f"SELECT DISTINCT hostname FROM agents WHERE agent_id IN ({placeholders})",
                real_agent_ids,
            ).fetchall()
        )
        if real_hostnames:
            host_placeholders = ",".join("?" * len(real_hostnames))
            cursor.execute(
                f"UPDATE alerts SET environment='real_vm' WHERE hostname IN ({host_placeholders})",
                real_hostnames,
            )
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
            environment   TEXT DEFAULT 'simulated',  -- simulated | real_vm
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
            status          TEXT DEFAULT 'OPEN',  -- OPEN | ACKNOWLEDGED | CLOSED
            note            TEXT,
            resolved_at     TEXT,
            environment     TEXT DEFAULT 'simulated',  -- simulated | real_vm
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS agents (
            agent_id      TEXT PRIMARY KEY,
            hostname      TEXT NOT NULL,
            ip_address    TEXT,
            os            TEXT,
            log_sources   TEXT,   -- JSON array, ej. ["ssh","web"]
            last_seen     TEXT,
            environment   TEXT DEFAULT 'simulated',  -- simulated | real_vm
            registered_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS custom_dashboards (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            layout        TEXT NOT NULL,   -- JSON: posiciones + config de cada widget
            created_at    TEXT DEFAULT (datetime('now')),
            updated_at    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS ip_geo_cache (
            source_ip     TEXT PRIMARY KEY,
            country       TEXT,
            country_code  TEXT,
            city          TEXT,
            lat           REAL,
            lon           REAL,
            looked_up_at  TEXT DEFAULT (datetime('now'))
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
        json.dumps(e.metadata or {}), e.raw_line, e.parsed_at, e.environment
    ) for e in events]

    cursor.executemany("""
        INSERT INTO events (
            timestamp, hostname, agent_id, log_source, service, event_type,
            username, source_ip, source_port, command, metadata,
            raw_line, parsed_at, environment
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                recommendation, mitre_technique, detected_at, environment
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.alert_id, alert.rule_name, alert.severity,
            alert.description, alert.source_ip, alert.username,
            alert.hostname, json.dumps(alert.evidence),
            alert.recommendation, alert.mitre_technique,
            alert.detected_at, alert.environment
        ))
        if cursor.rowcount > 0:
            inserted += 1

    conn.commit()
    conn.close()

    logger.info(f"Alertas insertadas: {inserted}")
    return inserted


def get_max_alert_counter() -> int:
    """
    Máximo sufijo numérico entre los alert_id existentes (ej. "ALERT-0042"
    -> 42), sin importar el orden de inserción. El motor de detección
    arranca su contador desde aquí en cada corrida (bootstrap, tick
    periódico, ingesta real) para que los IDs nuevos nunca choquen con
    uno ya insertado — si chocaran, el INSERT OR IGNORE de insert_alerts
    descartaría la alerta nueva en silencio.
    """
    conn = get_connection()
    row = conn.execute(
        "SELECT MAX(CAST(substr(alert_id, 7) AS INTEGER)) as max_counter FROM alerts"
    ).fetchone()
    conn.close()

    return row["max_counter"] or 0


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
                agent_id, hostname, ip_address, os, log_sources, environment
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            agent.agent_id, agent.hostname, agent.ip_address,
            agent.os, json.dumps(agent.log_sources), agent.environment
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


def query_agents(environment: str = "ALL") -> list[dict]:
    """
    Lista los agentes con su estado (ACTIVE/DISCONNECTED según
    last_seen) y conteo de eventos/alertas asociados.
    """
    conn = get_connection()
    cursor = conn.cursor()

    env_clause, env_params = _environment_clause(environment, column="a.environment")

    cursor.execute(f"""
        SELECT
            a.agent_id, a.hostname, a.ip_address, a.os, a.log_sources,
            a.last_seen, a.registered_at, a.environment,
            CASE
                WHEN a.last_seen IS NULL THEN 'NEVER_CONNECTED'
                WHEN (strftime('%s','now') - strftime('%s', a.last_seen))
                     < {AGENT_OFFLINE_AFTER_SECONDS} THEN 'ACTIVE'
                ELSE 'DISCONNECTED'
            END AS status,
            (SELECT COUNT(*) FROM events e WHERE e.agent_id = a.agent_id) AS event_count,
            (SELECT COUNT(*) FROM alerts al WHERE al.hostname = a.hostname) AS alert_count
        FROM agents a
        WHERE 1=1 {env_clause}
        ORDER BY a.hostname
    """, env_params)

    rows = []
    for row in cursor.fetchall():
        d = dict(row)
        d["log_sources"] = json.loads(d["log_sources"]) if d["log_sources"] else []
        rows.append(d)

    conn.close()
    return rows


def query_events(
    environment: str = "ALL", agent_id: str = "ALL", log_source: str = "ALL",
    time_range: str = "all", start: Optional[str] = None, end: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    """
    Eventos crudos (no solo alertas) para poder "profundizar" en algo
    que no cruzó ningún umbral de detección -- incluye raw_line y
    metadata, que hoy no se exponen en ningún otro endpoint.
    """
    conn = get_connection()
    env_clause, env_params = _environment_clause(environment)
    agent_clause, agent_params = _agent_clause(agent_id)
    source_clause, source_params = _log_source_clause(log_source)
    time_clause, time_params = _time_range_clause(time_range, start, end)

    rows = conn.execute(f"""
        SELECT id, timestamp, hostname, agent_id, log_source, service,
               event_type, username, source_ip, source_port, command,
               metadata, raw_line, created_at
        FROM events
        WHERE 1=1 {env_clause} {agent_clause} {source_clause} {time_clause}
        ORDER BY created_at DESC
        LIMIT ?
    """, env_params + agent_params + source_params + time_params + (limit,)).fetchall()

    conn.close()
    return [dict(row) for row in rows]


def query_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    time_range: str = "all",
    start: Optional[str] = None,
    end: Optional[str] = None,
    environment: str = "ALL",
    hostname: Optional[str] = None,
    limit: int = 100
) -> list[dict]:
    """
    Consulta alertas con filtro opcional por severidad, estado,
    antigüedad, workspace y agente. `alerts` no tiene columna agent_id
    (a diferencia de `events`) -- el filtro por agente se hace por
    hostname, mismo criterio ya usado para el backfill de environment.
    """
    conn = get_connection()
    cursor = conn.cursor()

    where_clauses = []
    params: list = []
    if severity:
        where_clauses.append("severity = ?")
        params.append(severity)
    if status:
        where_clauses.append("status = ?")
        params.append(status)
    if hostname:
        where_clauses.append("hostname = ?")
        params.append(hostname)

    time_clause, time_params = _time_range_clause(time_range, start, end)
    if time_clause:
        where_clauses.append(time_clause.replace("AND ", "", 1))
        params.extend(time_params)

    env_clause, env_params = _environment_clause(environment)
    if env_clause:
        where_clauses.append(env_clause.replace("AND ", "", 1))
        params.extend(env_params)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    cursor.execute(f"""
        SELECT * FROM alerts
        {where_sql}
        ORDER BY detected_at DESC
        LIMIT ?
    """, (*params, limit))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def update_alert_status(alert_id: str, status: str, note: Optional[str] = None) -> Optional[dict]:
    """
    Cambia el estado de una alerta (OPEN/ACKNOWLEDGED/CLOSED). Al cerrarla
    se registra resolved_at. Retorna la alerta actualizada, o None si el
    alert_id no existe.
    """
    conn = get_connection()

    if status == "CLOSED":
        cursor = conn.execute(
            """UPDATE alerts SET status = ?, note = COALESCE(?, note),
               resolved_at = datetime('now') WHERE alert_id = ?""",
            (status, note, alert_id),
        )
    else:
        cursor = conn.execute(
            "UPDATE alerts SET status = ?, note = COALESCE(?, note) WHERE alert_id = ?",
            (status, note, alert_id),
        )
    conn.commit()

    if cursor.rowcount == 0:
        conn.close()
        return None

    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    conn.close()
    return dict(row)


def query_mitre_coverage(environment: str = "ALL", hostname: Optional[str] = None) -> list[dict]:
    """
    Cuenta alertas por técnica MITRE. mitre_technique se guarda como
    "T1110 - Brute Force" — se separa en el primer " - " para quedarnos
    solo con el ID, que es lo que se compara contra MITRE_REFERENCE.
    `alerts` no tiene agent_id -- el filtro por agente se hace por hostname.
    """
    conn = get_connection()
    env_clause, env_params = _environment_clause(environment)
    host_clause, host_params = ("AND hostname = ?", (hostname,)) if hostname else ("", ())
    rows = conn.execute(f"""
        SELECT mitre_technique, COUNT(*) as n
        FROM alerts
        WHERE mitre_technique IS NOT NULL AND mitre_technique != '' {env_clause} {host_clause}
        GROUP BY mitre_technique
    """, env_params + host_params).fetchall()
    conn.close()

    counts: dict[str, int] = {}
    for row in rows:
        technique_id = row["mitre_technique"].split(" - ", 1)[0]
        counts[technique_id] = counts.get(technique_id, 0) + row["n"]

    return [{"technique_id": tid, "count": n} for tid, n in counts.items()]


def get_cached_geo(ips: list[str]) -> dict[str, dict]:
    """Geolocalización ya conocida para las IPs dadas (subset de las pedidas)."""
    if not ips:
        return {}

    conn = get_connection()
    placeholders = ",".join("?" * len(ips))
    rows = conn.execute(
        f"SELECT * FROM ip_geo_cache WHERE source_ip IN ({placeholders})", ips
    ).fetchall()
    conn.close()

    return {row["source_ip"]: dict(row) for row in rows}


def save_geo(source_ip: str, country: str, country_code: str, city: str, lat: float, lon: float) -> None:
    """Guarda (o reemplaza) la geolocalización de una IP. Sin TTL — se cachea para siempre."""
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO ip_geo_cache
           (source_ip, country, country_code, city, lat, lon, looked_up_at)
           VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
        (source_ip, country, country_code, city, lat, lon),
    )
    conn.commit()
    conn.close()


def get_attacker_geo(
    limit: int = 100, max_new_lookups: int = 20,
    environment: str = "ALL", agent_id: str = "ALL",
) -> list[dict]:
    """
    IPs públicas con actividad, geolocalizadas. Usa el cache primero;
    para las que falten, consulta ip-api.com (tope de `max_new_lookups`
    por llamada para no colgar el endpoint si un día aparecen muchas IPs
    nuevas de golpe — las que no alcancen se resuelven en la próxima
    llamada). Las IPs privadas (rangos que usan nuestros propios agentes
    simulados) se descartan sin gastar una consulta externa.
    """
    conn = get_connection()
    env_clause, env_params = _environment_clause(environment)
    agent_clause, agent_params = _agent_clause(agent_id)
    rows = conn.execute(f"""
        SELECT source_ip, COUNT(*) as attempts
        FROM events
        WHERE source_ip IS NOT NULL {env_clause} {agent_clause}
        GROUP BY source_ip
        ORDER BY attempts DESC
        LIMIT ?
    """, env_params + agent_params + (limit,)).fetchall()
    conn.close()

    attempts_by_ip = {row["source_ip"]: row["attempts"] for row in rows}
    public_ips = [ip for ip in attempts_by_ip if not is_private_ip(ip)]

    cached = get_cached_geo(public_ips)
    missing = [ip for ip in public_ips if ip not in cached][:max_new_lookups]

    for ip in missing:
        geo = lookup_ip(ip)
        if geo:
            save_geo(ip, geo["country"], geo["country_code"], geo["city"], geo["lat"], geo["lon"])
            cached[ip] = {**geo, "source_ip": ip}

    results = []
    for ip in public_ips:
        geo = cached.get(ip)
        if geo and geo.get("lat") is not None:
            results.append({
                "source_ip": ip,
                "country": geo.get("country"),
                "city": geo.get("city"),
                "lat": geo["lat"],
                "lon": geo["lon"],
                "attempts": attempts_by_ip[ip],
            })
    return results


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


def _environment_clause(environment: str, column: str = "environment") -> tuple[str, tuple]:
    """
    Clausula SQL parametrizada para filtrar por workspace (simulated |
    real_vm) — mismo shape que _log_source_clause. "ALL" no filtra nada.
    """
    if environment == "ALL":
        return "", ()
    return f"AND {column} = ?", (environment,)


def _agent_clause(agent_id: str, column: str = "agent_id") -> tuple[str, tuple]:
    """
    Clausula SQL parametrizada para filtrar por agente -- mismo shape
    que _log_source_clause/_environment_clause. "ALL" no filtra nada.
    """
    if agent_id == "ALL":
        return "", ()
    return f"AND {column} = ?", (agent_id,)


# Presets de rango de tiempo -> modificador de datetime('now', ?) de
# SQLite. Filtra por created_at (cuándo SENTINEL insertó la fila) y no
# por el timestamp del log -- ese es aleatorio/inconsistente entre
# fuentes sintéticas y reales, created_at es el reloj real del servidor.
TIME_RANGES = {
    "1h": "-1 hours",
    "24h": "-24 hours",
    "7d": "-7 days",
    "30d": "-30 days",
    "365d": "-365 days",
    "all": None,
}


def _time_range_clause(
    time_range: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    column: str = "created_at",
) -> tuple[str, tuple]:
    """
    Clausula SQL parametrizada para filtrar por antigüedad. "all" no
    filtra nada. "custom" ignora los presets de TIME_RANGES y filtra
    por un rango exacto (start/end como "YYYY-MM-DD HH:MM:SS", el
    mismo formato que produce datetime('now') en SQLite).
    """
    if time_range == "custom":
        clauses: list[str] = []
        params: list[str] = []
        if start:
            clauses.append(f"{column} >= ?")
            params.append(start)
        if end:
            clauses.append(f"{column} <= ?")
            params.append(end)
        if not clauses:
            return "", ()
        return "AND " + " AND ".join(clauses), tuple(params)

    modifier = TIME_RANGES.get(time_range)
    if modifier is None:
        return "", ()
    return f"AND {column} >= datetime('now', ?)", (modifier,)


def query_summary(
    log_source: str = "ALL", time_range: str = "all",
    start: Optional[str] = None, end: Optional[str] = None,
    environment: str = "ALL", agent_id: str = "ALL",
) -> dict:
    """KPIs del dashboard (eventos, alertas, agentes), con filtro opcional por fuente, antigüedad, workspace y agente."""
    conn = get_connection()
    source_clause, source_params = _log_source_clause(log_source)
    time_clause, time_params = _time_range_clause(time_range, start, end)
    env_clause, env_params = _environment_clause(environment)
    agent_clause, agent_params = _agent_clause(agent_id)

    row = conn.execute(f"""
        SELECT
            COUNT(*) as total_events,
            COUNT(DISTINCT source_ip) as unique_ips,
            SUM(CASE WHEN event_type='failed_password' OR
                          event_type='invalid_user' THEN 1 ELSE 0 END) as failed_logins,
            SUM(CASE WHEN event_type='accepted_password' THEN 1 ELSE 0 END) as ok_logins,
            SUM(CASE WHEN event_type='sudo_command'      THEN 1 ELSE 0 END) as sudo_events
        FROM events WHERE 1=1 {source_clause} {time_clause} {env_clause} {agent_clause}
    """, source_params + time_params + env_params + agent_params).fetchone()

    alert_row = conn.execute(f"""
        SELECT COUNT(*) as total,
            SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as crit,
            SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END) as high
        FROM alerts WHERE 1=1 {time_clause} {env_clause}
    """, time_params + env_params).fetchone()

    # Estado actual de los agentes -- no tiene sentido "filtrarlo por
    # antigüedad", un agente está activo o no en este momento.
    agent_env_clause, agent_env_params = _environment_clause(environment)
    agent_id_clause, agent_id_params = _agent_clause(agent_id)
    agent_row = conn.execute(f"""
        SELECT COUNT(*) as total,
            SUM(CASE WHEN (strftime('%s','now') - strftime('%s', last_seen)) < {AGENT_OFFLINE_AFTER_SECONDS}
                THEN 1 ELSE 0 END) as active
        FROM agents WHERE 1=1 {agent_env_clause} {agent_id_clause}
    """, agent_env_params + agent_id_params).fetchone()

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


def query_top_ips(
    log_source: str = "ALL", limit: int = 8, time_range: str = "all",
    start: Optional[str] = None, end: Optional[str] = None,
    environment: str = "ALL", agent_id: str = "ALL",
) -> list[dict]:
    """Top IPs por intentos fallidos (ssh) o requests (web), con filtro opcional por fuente, antigüedad, workspace y agente."""
    conn = get_connection()
    source_clause, source_params = _log_source_clause(log_source)
    time_clause, time_params = _time_range_clause(time_range, start, end)
    env_clause, env_params = _environment_clause(environment)
    agent_clause, agent_params = _agent_clause(agent_id)
    event_types = "('http_request')" if log_source == "WEB" else "('failed_password','invalid_user')"

    rows = conn.execute(f"""
        SELECT source_ip, COUNT(*) as attempts,
               COUNT(DISTINCT username) as targeted_users
        FROM events
        WHERE event_type IN {event_types}
          AND source_ip IS NOT NULL {source_clause} {time_clause} {env_clause} {agent_clause}
        GROUP BY source_ip ORDER BY attempts DESC LIMIT ?
    """, source_params + time_params + env_params + agent_params + (limit,)).fetchall()

    conn.close()
    return [dict(row) for row in rows]


def query_event_types(
    log_source: str = "ALL", time_range: str = "all",
    start: Optional[str] = None, end: Optional[str] = None,
    environment: str = "ALL", agent_id: str = "ALL",
) -> list[dict]:
    """Distribución de eventos por tipo, con filtro opcional por fuente, antigüedad, workspace y agente."""
    conn = get_connection()
    source_clause, source_params = _log_source_clause(log_source)
    time_clause, time_params = _time_range_clause(time_range, start, end)
    env_clause, env_params = _environment_clause(environment)
    agent_clause, agent_params = _agent_clause(agent_id)

    rows = conn.execute(f"""
        SELECT event_type, COUNT(*) as n FROM events
        WHERE 1=1 {source_clause} {time_clause} {env_clause} {agent_clause}
        GROUP BY event_type
    """, source_params + time_params + env_params + agent_params).fetchall()

    conn.close()
    return [dict(row) for row in rows]


def query_timeline(
    log_source: str = "ALL", time_range: str = "all",
    start: Optional[str] = None, end: Optional[str] = None,
    environment: str = "ALL", agent_id: str = "ALL",
) -> list[dict]:
    """Serie de tiempo de eventos por tipo, con filtro opcional por fuente, antigüedad, workspace y agente."""
    conn = get_connection()
    source_clause, source_params = _log_source_clause(log_source)
    time_clause, time_params = _time_range_clause(time_range, start, end)
    env_clause, env_params = _environment_clause(environment)
    agent_clause, agent_params = _agent_clause(agent_id)

    rows = conn.execute(f"""
        SELECT substr(timestamp, 1, 8) as hour,
               event_type, COUNT(*) as n
        FROM events WHERE 1=1 {source_clause} {time_clause} {env_clause} {agent_clause}
        GROUP BY hour, event_type
        ORDER BY hour
    """, source_params + time_params + env_params + agent_params).fetchall()

    conn.close()
    return [dict(row) for row in rows]


# Dimensiones agrupables permitidas por dataset, mapeadas a la expresión
# SQL real. Whitelist explícita: group_by llega desde una API HTTP pública
# (el builder), nunca se interpola el valor del usuario directo en SQL.
GENERIC_QUERY_DIMENSIONS = {
    "events": {
        "source_ip": "source_ip",
        "username": "username",
        "event_type": "event_type",
        "hostname": "hostname",
        "log_source": "log_source",
        "agent_id": "agent_id",
        "hour": "substr(timestamp, 1, 8)",
    },
    "alerts": {
        "rule_name": "rule_name",
        "severity": "severity",
        "mitre_technique": "mitre_technique",
        "source_ip": "source_ip",
        "hostname": "hostname",
    },
}


def query_generic(
    dataset: str,
    group_by: str,
    log_source: str = "ALL",
    severity: str = "ALL",
    environment: str = "ALL",
    limit: int = 10,
) -> list[dict]:
    """
    Consulta genérica para el builder de dashboards: agrupa `dataset`
    (events|alerts) por `group_by` y cuenta filas. Forma de salida fija
    ({label, value}) para que cualquier tipo de gráfica la pueda consumir
    sin importar la dimensión elegida.

    Lanza ValueError si dataset/group_by no están en el whitelist —
    el caller (API) lo traduce a un 400.
    """
    dimensions = GENERIC_QUERY_DIMENSIONS.get(dataset)
    if dimensions is None:
        raise ValueError(f"dataset inválido: {dataset}")

    column_expr = dimensions.get(group_by)
    if column_expr is None:
        raise ValueError(f"group_by inválido para '{dataset}': {group_by}")

    conn = get_connection()
    where_clauses = []
    params: list = []

    if dataset == "events":
        clause, source_params = _log_source_clause(log_source)
        if clause:
            where_clauses.append(clause.replace("AND ", "", 1))
            params.extend(source_params)
    elif dataset == "alerts" and severity != "ALL":
        where_clauses.append("severity = ?")
        params.append(severity)

    env_clause, env_params = _environment_clause(environment)
    if env_clause:
        where_clauses.append(env_clause.replace("AND ", "", 1))
        params.extend(env_params)

    where_clauses.append(f"{column_expr} IS NOT NULL")
    where_sql = f"WHERE {' AND '.join(where_clauses)}"

    rows = conn.execute(f"""
        SELECT {column_expr} as label, COUNT(*) as value
        FROM {dataset}
        {where_sql}
        GROUP BY label
        ORDER BY value DESC
        LIMIT ?
    """, (*params, limit)).fetchall()

    conn.close()
    return [dict(row) for row in rows]


def save_dashboard(name: str, layout: list) -> int:
    """Crea un dashboard nuevo. Retorna su id."""
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO custom_dashboards (name, layout) VALUES (?, ?)",
        (name, json.dumps(layout)),
    )
    conn.commit()
    dashboard_id = cursor.lastrowid
    conn.close()
    return dashboard_id


def update_dashboard(dashboard_id: int, name: str, layout: list) -> bool:
    """Actualiza un dashboard existente. Retorna False si no existe."""
    conn = get_connection()
    cursor = conn.execute(
        """UPDATE custom_dashboards
           SET name = ?, layout = ?, updated_at = datetime('now')
           WHERE id = ?""",
        (name, json.dumps(layout), dashboard_id),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def list_dashboards() -> list[dict]:
    """Lista los dashboards guardados (sin el layout completo, solo metadata)."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, name, created_at, updated_at FROM custom_dashboards ORDER BY updated_at DESC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_dashboard(dashboard_id: int) -> Optional[dict]:
    """Obtiene un dashboard completo (con su layout). None si no existe."""
    conn = get_connection()
    row = conn.execute(
        "SELECT id, name, layout, created_at, updated_at FROM custom_dashboards WHERE id = ?",
        (dashboard_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    d = dict(row)
    d["layout"] = json.loads(d["layout"])
    return d


def delete_dashboard(dashboard_id: int) -> bool:
    """Elimina un dashboard. Retorna False si no existía."""
    conn = get_connection()
    cursor = conn.execute("DELETE FROM custom_dashboards WHERE id = ?", (dashboard_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


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
