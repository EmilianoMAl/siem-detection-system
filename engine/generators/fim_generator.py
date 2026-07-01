import random
import time
import logging
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

BENIGN_PATHS = [
    "/var/log/syslog", "/var/log/nginx/access.log",
    "/etc/hosts", "/etc/motd", "/var/www/html/cache/index.html",
]

CRITICAL_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys", "/home/deploy/.ssh/authorized_keys",
]

USERS = ["root", "deploy", "www-data"]


def _timestamp_random(hours_back: int = 24) -> str:
    now = datetime.now()
    delta = timedelta(
        hours=random.randint(0, hours_back),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    return (now - delta).strftime("%b %d %H:%M:%S")


def _fake_hash(seed: str) -> str:
    return hashlib.sha1(f"{seed}{random.random()}".encode()).hexdigest()[:12]


def _fim_line(hostname: str, file_path: str, action: str, user: str) -> str:
    hash_before = "none" if action == "created" else _fake_hash(file_path)
    hash_after = "none" if action == "deleted" else _fake_hash(file_path + action)
    return (
        f"{_timestamp_random()} {hostname} syscheck: File '{file_path}' {action} "
        f"(user={user}, hash_before={hash_before}, hash_after={hash_after})"
    )


def generate_benign_change(hostname: str) -> list[str]:
    path = random.choice(BENIGN_PATHS)
    action = random.choice(["modified", "modified", "created"])
    user = random.choice(USERS)
    return [_fim_line(hostname, path, action, user)]


def generate_critical_change(hostname: str) -> list[str]:
    """Modificación de un archivo crítico — persistencia/post-explotación."""
    path = random.choice(CRITICAL_PATHS)
    action = "modified" if "authorized_keys" not in path else random.choice(["modified", "created"])
    user = random.choice(["root", "www-data"])  # usuario poco usual para tocar estos archivos
    return [_fim_line(hostname, path, action, user)]


def write_logs(log_lines: list[str], filepath: Path) -> None:
    with open(filepath, "a", encoding="utf-8") as f:
        for line in log_lines:
            f.write(line + "\n")


def run_fim_stream(
    hostname: str,
    output_file: Path,
    duration_seconds: int = 30,
    events_per_second: float = 0.5,
    attack_probability: float = 0.15,
    realtime: bool = False,
) -> Path:
    """Genera eventos de integridad de archivos (ver run_ssh_stream para `realtime`)."""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    total_cycles = max(1, int(duration_seconds * events_per_second))
    total_events = 0
    total_critical = 0

    for _ in range(total_cycles):
        if random.random() < attack_probability:
            logs_to_write = generate_critical_change(hostname)
            total_critical += 1
        else:
            logs_to_write = generate_benign_change(hostname)

        write_logs(logs_to_write, output_file)
        total_events += len(logs_to_write)

        if realtime:
            time.sleep(1.0 / events_per_second)

    logger.info(
        f"[fim] {hostname} | eventos={total_events} | críticos={total_critical} | "
        f"archivo={output_file}"
    )
    return output_file
