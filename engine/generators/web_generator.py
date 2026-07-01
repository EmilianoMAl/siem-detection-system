import random
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

ATTACK_IPS = [
    "45.33.32.156", "198.20.69.74", "80.82.77.139",
    "185.220.101.45", "94.102.49.190",
]

NORMAL_IPS = [
    "200.68.128.1", "187.189.45.23", "201.134.56.78",
    "189.203.45.67", "148.243.12.34", "10.0.0.20",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
]
SCANNER_USER_AGENTS = ["sqlmap/1.7", "Nikto/2.5", "python-requests/2.31", "gobuster/3.6"]

NORMAL_PATHS = ["/", "/login", "/dashboard", "/api/health",
                "/images/logo.png", "/css/style.css", "/favicon.ico"]

SQLI_PAYLOADS = [
    "/login?user=admin' OR '1'='1",
    "/search?q=1 UNION SELECT username,password FROM users",
    "/products?id=1; DROP TABLE users;--",
]
XSS_PAYLOADS = [
    "/comment?text=<script>alert(document.cookie)</script>",
    "/profile?name=<img src=x onerror=alert(1)>",
]
TRAVERSAL_PAYLOADS = [
    "/download?file=../../../../etc/passwd",
    "/static/../../../etc/passwd",
]
SCAN_PATHS = [
    "/admin", "/wp-admin", "/.env", "/backup.zip", "/phpmyadmin",
    "/.git/config", "/config.php.bak", "/server-status", "/xmlrpc.php",
    "/api/v1/debug", "/.aws/credentials", "/shell.php",
]


def _timestamp_random(hours_back: int = 24) -> str:
    now = datetime.now()
    delta = timedelta(
        hours=random.randint(0, hours_back),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    return (now - delta).strftime("%d/%b/%Y:%H:%M:%S +0000")


def _access_log_line(ip: str, method: str, path: str, status: int, user_agent: str) -> str:
    """
    El path va en la request-line del log, que no puede contener
    espacios crudos (como haría un navegador/curl real) — se codifican
    para que el parser (que separa por espacios) siga funcionando.
    """
    size = random.randint(200, 15000)
    encoded_path = path.replace(" ", "%20")
    return (
        f'{ip} - - [{_timestamp_random()}] "{method} {encoded_path} HTTP/1.1" '
        f'{status} {size} "-" "{user_agent}"'
    )


def generate_normal_traffic() -> list[str]:
    ip = random.choice(NORMAL_IPS)
    ua = random.choice(USER_AGENTS)
    path = random.choice(NORMAL_PATHS)
    method = "POST" if path == "/login" else "GET"
    status = random.choice([200, 200, 200, 304])
    return [_access_log_line(ip, method, path, status, ua)]


def generate_web_attack(ip: str) -> list[str]:
    """SQLi / XSS / path traversal — un solo intento dirigido."""
    ua = random.choice(SCANNER_USER_AGENTS)
    payload = random.choice(SQLI_PAYLOADS + XSS_PAYLOADS + TRAVERSAL_PAYLOADS)
    status = random.choice([200, 403, 500])
    return [_access_log_line(ip, "GET", payload, status, ua)]


def generate_recon_scan(ip: str) -> list[str]:
    """Escaneo de rutas conocidas (directory brute-force) — casi todo 404."""
    ua = random.choice(SCANNER_USER_AGENTS)
    logs = []
    for path in random.sample(SCAN_PATHS, k=min(len(SCAN_PATHS), random.randint(8, 12))):
        logs.append(_access_log_line(ip, "GET", path, 404, ua))
    return logs


def write_logs(log_lines: list[str], filepath: Path) -> None:
    with open(filepath, "a", encoding="utf-8") as f:
        for line in log_lines:
            f.write(line + "\n")


def run_web_stream(
    output_file: Path,
    duration_seconds: int = 30,
    events_per_second: float = 3.0,
    attack_probability: float = 0.2,
    realtime: bool = False,
) -> Path:
    """Genera un access log de un servidor web (ver run_ssh_stream para semántica de `realtime`)."""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    total_cycles = max(1, int(duration_seconds * events_per_second))
    total_events = 0
    total_attacks = 0

    for _ in range(total_cycles):
        if random.random() < attack_probability:
            attack_ip = random.choice(ATTACK_IPS)
            logs_to_write = (
                generate_recon_scan(attack_ip)
                if random.random() < 0.5
                else generate_web_attack(attack_ip)
            )
            total_attacks += 1
        else:
            logs_to_write = generate_normal_traffic()

        write_logs(logs_to_write, output_file)
        total_events += len(logs_to_write)

        if realtime:
            time.sleep(1.0 / events_per_second)

    logger.info(
        f"[web] eventos={total_events} | ataques={total_attacks} | archivo={output_file}"
    )
    return output_file
