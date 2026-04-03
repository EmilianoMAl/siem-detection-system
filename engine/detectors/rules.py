import logging
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional
from engine.parsers.auth_parser import LogEvent

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
    """

    # --- Umbrales configurables ---
    BRUTE_FORCE_THRESHOLD     = 5    # intentos fallidos para disparar alerta
    PORT_SCAN_THRESHOLD       = 10   # conexiones únicas para detectar scan
    SUSPICIOUS_COMMANDS = [
        "/etc/shadow", "/etc/passwd",
        "chmod 777", "/tmp/",
        ">& /dev/tcp", "wget http",
        "curl http", "python3 -c",
        "pty.spawn", "base64 -d",
        "nc -e", "bash -i"
    ]

    def __init__(self):
        self.alerts: list[Alert] = []
        self._alert_counter = 0

    def _new_alert_id(self) -> str:
        self._alert_counter += 1
        return f"ALERT-{self._alert_counter:04d}"

    def detect_brute_force(self, events: list[LogEvent]) -> list[Alert]:
        """
        Regla: Detecta brute force SSH.
        Dispara cuando una IP tiene más de N intentos fallidos.

        MITRE ATT&CK: T1110 - Brute Force
        """
        alerts = []
        failed_by_ip = defaultdict(list)

        for event in events:
            if event.event_type in ("failed_password", "invalid_user"):
                if event.source_ip:
                    failed_by_ip[event.source_ip].append(event)

        for ip, failed_events in failed_by_ip.items():
            if len(failed_events) >= self.BRUTE_FORCE_THRESHOLD:
                usernames = list(set(
                    e.username for e in failed_events if e.username
                ))
                severity = "CRITICAL" if len(failed_events) >= 20 else "HIGH"

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
        alerts = []

        for event in events:
            if event.event_type != "sudo_command":
                continue
            if not event.command:
                continue

            matched_patterns = [
                pattern for pattern in self.SUSPICIOUS_COMMANDS
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
            if event.event_type in ("failed_password", "invalid_user"):
                if event.source_ip:
                    failed_ips.add(event.source_ip)

        for event in events:
            if event.event_type == "accepted_password":
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

    def run_all_rules(self, events: list[LogEvent]) -> list[Alert]:
        """
        Ejecuta todas las reglas de detección sobre un conjunto de eventos.
        Retorna todas las alertas generadas ordenadas por severidad.
        """
        logger.info(f"Ejecutando motor de detección | eventos={len(events)}")

        all_alerts = []
        all_alerts.extend(self.detect_brute_force(events))
        all_alerts.extend(self.detect_suspicious_commands(events))
        all_alerts.extend(self.detect_successful_login_after_failures(events))

        # Ordenar por severidad
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

    from pathlib import Path
    from engine.parsers.auth_parser import parse_log_file

    raw_files = sorted(Path("logs/raw").glob("auth_log_*.log"))
    if not raw_files:
        logger.error("No hay logs — corre primero el generador")
        exit(1)

    events, _ = parse_log_file(raw_files[-1])

    engine = DetectionEngine()
    alerts = engine.run_all_rules(events)

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