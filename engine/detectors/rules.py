import fnmatch
import logging
from urllib.parse import unquote
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

from engine.parsers.auth_parser import LogEvent
from engine.config import load_rules_config

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """
    Alerta generada por el motor de detección.
    Cada alerta tiene severidad, evidencia y recomendación.
    """
    alert_id:        str
    rule_name:       str
    severity:        str        # CRITICAL, HIGH, MEDIUM, LOW
    description:     str
    source_ip:       Optional[str]
    username:        Optional[str]
    hostname:        Optional[str]
    evidence:        list       # eventos que dispararon la alerta
    recommendation:  str
    detected_at:     str = ""
    mitre_technique: str = ""   # MITRE ATT&CK mapping

    def __post_init__(self):
        self.detected_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = [e if isinstance(e, str) else e for e in self.evidence]
        return d


class DetectionEngine:
    """
    Motor de detección basado en reglas.
    Cada método detect_* implementa una regla de detección diferente.
    Los umbrales/patrones vienen de config/rules.yaml (engine/config.py)
    en vez de estar hardcodeados — así se pueden ajustar sin tocar código,
    igual que el ruleset de un SIEM real.
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or load_rules_config()
        self.alerts: list[Alert] = []
        self._alert_counter = 0

    def _new_alert_id(self) -> str:
        self._alert_counter += 1
        return f"ALERT-{self._alert_counter:04d}"

    # ------------------------------------------------------------------
    # SSH
    # ------------------------------------------------------------------

    def detect_brute_force(self, events: list[LogEvent]) -> list[Alert]:
        """
        Regla: Detecta brute force SSH.
        Dispara cuando una IP tiene más de N intentos fallidos.

        MITRE ATT&CK: T1110 - Brute Force
        """
        cfg = self.config["ssh_brute_force"]
        alerts = []
        failed_by_ip = defaultdict(list)

        for event in events:
            if event.log_source != "ssh":
                continue
            if event.event_type in ("failed_password", "invalid_user"):
                if event.source_ip:
                    failed_by_ip[event.source_ip].append(event)

        for ip, failed_events in failed_by_ip.items():
            if len(failed_events) >= cfg["fail_threshold"]:
                usernames = list(set(
                    e.username for e in failed_events if e.username
                ))
                severity = "CRITICAL" if len(failed_events) >= cfg["critical_threshold"] else "HIGH"

                alert = Alert(
                    alert_id=self._new_alert_id(),
                    rule_name="SSH_BRUTE_FORCE",
                    severity=severity,
                    description=(
                        f"Brute force SSH detectado desde {ip}. "
                        f"{len(failed_events)} intentos fallidos. "
                        f"Usuarios objetivo: {', '.join(usernames[:5])}"
                    ),
                    source_ip=ip,
                    username=usernames[0] if usernames else None,
                    hostname=failed_events[0].hostname,
                    evidence=[e.raw_line for e in failed_events[:5]],
                    recommendation=(
                        f"Bloquear IP {ip} en firewall inmediatamente. "
                        f"Revisar si algún intento fue exitoso desde esta IP."
                    ),
                    mitre_technique="T1110 - Brute Force"
                )
                alerts.append(alert)
                logger.warning(
                    f"🚨 [{severity}] SSH_BRUTE_FORCE | "
                    f"ip={ip} | intentos={len(failed_events)}"
                )

        return alerts

    def detect_suspicious_commands(self, events: list[LogEvent]) -> list[Alert]:
        """
        Regla: Detecta comandos sudo sospechosos.
        Busca patrones de post-exploitation y escalada de privilegios.

        MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism
        """
        patterns = self.config["suspicious_sudo"]["patterns"]
        alerts = []

        for event in events:
            if event.log_source != "ssh" or event.event_type != "sudo_command":
                continue
            if not event.command:
                continue

            matched_patterns = [
                pattern for pattern in patterns
                if pattern.lower() in event.command.lower()
            ]

            if matched_patterns:
                alert = Alert(
                    alert_id=self._new_alert_id(),
                    rule_name="SUSPICIOUS_SUDO_COMMAND",
                    severity="HIGH",
                    description=(
                        f"Comando sudo sospechoso ejecutado por {event.username}. "
                        f"Patrones detectados: {', '.join(matched_patterns)}"
                    ),
                    source_ip=event.source_ip,
                    username=event.username,
                    hostname=event.hostname,
                    evidence=[event.raw_line],
                    recommendation=(
                        f"Revisar actividad del usuario {event.username}. "
                        f"Verificar si el comando fue autorizado. "
                        f"Considerar revocar privilegios sudo temporalmente."
                    ),
                    mitre_technique="T1548 - Abuse Elevation Control Mechanism"
                )
                alerts.append(alert)
                logger.warning(
                    f"🚨 [HIGH] SUSPICIOUS_SUDO | "
                    f"user={event.username} | "
                    f"cmd={event.command[:50]}"
                )

        return alerts

    def detect_successful_login_after_failures(
        self, events: list[LogEvent]
    ) -> list[Alert]:
        """
        Regla: Login exitoso desde IP que tuvo fallos previos.
        Indica posible brute force exitoso.

        MITRE ATT&CK: T1078 - Valid Accounts
        """
        alerts = []
        failed_ips = set()

        for event in events:
            if event.log_source != "ssh":
                continue
            if event.event_type in ("failed_password", "invalid_user"):
                if event.source_ip:
                    failed_ips.add(event.source_ip)

        for event in events:
            if event.log_source == "ssh" and event.event_type == "accepted_password":
                if event.source_ip in failed_ips:
                    alert = Alert(
                        alert_id=self._new_alert_id(),
                        rule_name="LOGIN_AFTER_FAILURES",
                        severity="CRITICAL",
                        description=(
                            f"Login EXITOSO desde {event.source_ip} "
                            f"que previamente tuvo intentos fallidos. "
                            f"Usuario: {event.username}. "
                            f"Posible brute force exitoso."
                        ),
                        source_ip=event.source_ip,
                        username=event.username,
                        hostname=event.hostname,
                        evidence=[event.raw_line],
                        recommendation=(
                            f"ACCIÓN INMEDIATA: Verificar si {event.username} "
                            f"reconoce este acceso desde {event.source_ip}. "
                            f"Considerar deshabilitar cuenta y forzar cambio de contraseña."
                        ),
                        mitre_technique="T1078 - Valid Accounts"
                    )
                    alerts.append(alert)
                    logger.critical(
                        f"🔴 [CRITICAL] LOGIN_AFTER_FAILURES | "
                        f"ip={event.source_ip} | user={event.username}"
                    )

        return alerts

    # ------------------------------------------------------------------
    # WEB
    # ------------------------------------------------------------------

    def detect_web_attacks(self, events: list[LogEvent]) -> list[Alert]:
        """
        Regla: Detecta payloads de SQLi/XSS/path traversal en requests web.

        MITRE ATT&CK: T1190 - Exploit Public-Facing Application
        """
        patterns = self.config["web_attack"]["patterns"]
        alerts = []

        for event in events:
            if event.log_source != "web":
                continue
            target = unquote(event.metadata.get("path", "")).lower()

            matched = [p for p in patterns if p.lower() in target]
            if matched:
                alert = Alert(
                    alert_id=self._new_alert_id(),
                    rule_name="WEB_ATTACK_PAYLOAD",
                    severity="HIGH",
                    description=(
                        f"Payload de ataque web detectado desde {event.source_ip}. "
                        f"Patrones: {', '.join(matched)}. "
                        f"Path: {event.metadata.get('path', '')[:100]}"
                    ),
                    source_ip=event.source_ip,
                    username=None,
                    hostname=event.hostname,
                    evidence=[event.raw_line],
                    recommendation=(
                        f"Bloquear IP {event.source_ip} en el WAF/firewall. "
                        f"Revisar logs de la aplicación por posible explotación exitosa."
                    ),
                    mitre_technique="T1190 - Exploit Public-Facing Application"
                )
                alerts.append(alert)
                logger.warning(f"🚨 [HIGH] WEB_ATTACK_PAYLOAD | ip={event.source_ip}")

        return alerts

    def detect_recon_scan(self, events: list[LogEvent]) -> list[Alert]:
        """
        Regla: Detecta escaneo/reconocimiento (directory brute-force) —
        muchas rutas distintas o muchos 404 desde la misma IP.

        MITRE ATT&CK: T1595 - Active Scanning
        """
        cfg = self.config["recon_scan"]
        alerts = []
        by_ip = defaultdict(list)

        for event in events:
            if event.log_source == "web" and event.source_ip:
                by_ip[event.source_ip].append(event)

        for ip, ip_events in by_ip.items():
            distinct_paths = {e.metadata.get("path") for e in ip_events}
            not_found = [e for e in ip_events if e.metadata.get("status_code") == 404]

            if (len(distinct_paths) >= cfg["distinct_paths_threshold"]
                    or len(not_found) >= cfg["not_found_threshold"]):
                severity = "HIGH" if len(distinct_paths) >= cfg["distinct_paths_threshold"] * 1.5 else "MEDIUM"
                alert = Alert(
                    alert_id=self._new_alert_id(),
                    rule_name="WEB_RECON_SCAN",
                    severity=severity,
                    description=(
                        f"Escaneo de rutas detectado desde {ip}. "
                        f"{len(distinct_paths)} rutas distintas, "
                        f"{len(not_found)} respuestas 404."
                    ),
                    source_ip=ip,
                    username=None,
                    hostname=ip_events[0].hostname,
                    evidence=[e.raw_line for e in ip_events[:5]],
                    recommendation=(
                        f"Vigilar IP {ip} — patrón típico de directory brute-forcing. "
                        f"Considerar rate-limiting o bloqueo temporal."
                    ),
                    mitre_technique="T1595 - Active Scanning"
                )
                alerts.append(alert)
                logger.warning(f"🚨 [{severity}] WEB_RECON_SCAN | ip={ip}")

        return alerts

    # ------------------------------------------------------------------
    # FIM
    # ------------------------------------------------------------------

    def detect_fim_critical_change(self, events: list[LogEvent]) -> list[Alert]:
        """
        Regla: Detecta cambios en archivos críticos del sistema
        (integridad de archivos / FIM).

        MITRE ATT&CK: T1098 - Account Manipulation (authorized_keys) /
                       T1565.001 - Stored Data Manipulation (otros)
        """
        critical_paths = self.config["fim_critical_change"]["critical_paths"]
        alerts = []

        for event in events:
            if event.log_source != "fim":
                continue
            file_path = event.metadata.get("file_path", "")

            if any(fnmatch.fnmatch(file_path, pattern) for pattern in critical_paths):
                technique = (
                    "T1098 - Account Manipulation" if "authorized_keys" in file_path
                    else "T1565.001 - Stored Data Manipulation"
                )
                alert = Alert(
                    alert_id=self._new_alert_id(),
                    rule_name="FIM_CRITICAL_FILE_CHANGE",
                    severity="CRITICAL",
                    description=(
                        f"Archivo crítico modificado: {file_path} "
                        f"(acción={event.metadata.get('action')}, usuario={event.username})."
                    ),
                    source_ip=None,
                    username=event.username,
                    hostname=event.hostname,
                    evidence=[event.raw_line],
                    recommendation=(
                        f"Verificar si el cambio en {file_path} fue autorizado. "
                        f"Comparar hash_before/hash_after y restaurar desde backup si es necesario."
                    ),
                    mitre_technique=technique
                )
                alerts.append(alert)
                logger.critical(f"🔴 [CRITICAL] FIM_CRITICAL_FILE_CHANGE | path={file_path}")

        return alerts

    # ------------------------------------------------------------------

    def run_all_rules(self, events: list[LogEvent]) -> list[Alert]:
        """
        Ejecuta todas las reglas de detección sobre un conjunto de eventos
        (de cualquier fuente: ssh/web/fim). Retorna todas las alertas
        generadas ordenadas por severidad.
        """
        logger.info(f"Ejecutando motor de detección | eventos={len(events)}")

        all_alerts = []
        all_alerts.extend(self.detect_brute_force(events))
        all_alerts.extend(self.detect_suspicious_commands(events))
        all_alerts.extend(self.detect_successful_login_after_failures(events))
        all_alerts.extend(self.detect_web_attacks(events))
        all_alerts.extend(self.detect_recon_scan(events))
        all_alerts.extend(self.detect_fim_critical_change(events))

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_alerts.sort(key=lambda a: severity_order.get(a.severity, 4))

        self.alerts = all_alerts
        logger.info(
            f"Detección completada | "
            f"alertas={len(all_alerts)} | "
            f"críticas={sum(1 for a in all_alerts if a.severity == 'CRITICAL')} | "
            f"altas={sum(1 for a in all_alerts if a.severity == 'HIGH')}"
        )
        return all_alerts


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

    generated = run_generator(agents=SIMULATED_AGENTS)
    all_events = []
    for agent, source, filepath in generated:
        events, _ = ingest_agent_logs(agent, source, filepath)
        all_events.extend(events)

    engine = DetectionEngine()
    alerts = engine.run_all_rules(all_events)

    print(f"\n{'='*60}")
    print(f"  ALERTAS GENERADAS: {len(alerts)}")
    print(f"{'='*60}")

    for alert in alerts:
        print(f"\n  [{alert.severity}] {alert.rule_name}")
        print(f"  ID:       {alert.alert_id}")
        print(f"  IP:       {alert.source_ip}")
        print(f"  Usuario:  {alert.username}")
        print(f"  Desc:     {alert.description}")
        print(f"  MITRE:    {alert.mitre_technique}")
        print(f"  Acción:   {alert.recommendation}")
        print(f"  {'-'*55}")
