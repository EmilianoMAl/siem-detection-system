#!/usr/bin/env python3
"""
Agente real de SENTINEL — corre en la VM (fuera de Docker, vía systemd
timer, ver DEPLOYMENT.md) y manda a la API las líneas nuevas de los logs
reales del sistema (SSH, Nginx). Solo usa la librería estándar de Python
para no depender de "pip install" en la máquina que lo corre.
"""
import json
import os
import sys
import urllib.error
import urllib.request

API_URL = os.environ.get("SENTINEL_API_URL", "http://127.0.0.1:8000")
TOKEN = os.environ.get("SENTINEL_INGEST_TOKEN", "")
AGENT_ID = os.environ.get("SENTINEL_AGENT_ID", "agent-real-vm")
STATE_PATH = os.environ.get("SENTINEL_AGENT_STATE", "/var/lib/sentinel-agent/offsets.json")
MAX_LINES_PER_REQUEST = 500

LOG_SOURCES = {
    "ssh": os.environ.get("SENTINEL_AUTH_LOG", "/var/log/auth.log"),
    "web": os.environ.get("SENTINEL_NGINX_LOG", "/var/log/nginx/access.log"),
}


def load_offsets() -> dict:
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH) as f:
            return json.load(f)
    return {}


def save_offsets(offsets: dict) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(offsets, f)


def read_new_lines(path: str, offset: int) -> tuple[list[str], int]:
    if not os.path.exists(path):
        return [], offset

    size = os.path.getsize(path)
    if size < offset:
        # El archivo se truncó o logrotate lo reemplazó por uno nuevo
        # más chico -- empezar de cero en vez de fallar al hacer seek.
        offset = 0

    with open(path, "r", errors="ignore") as f:
        f.seek(offset)
        lines = [line for line in f.read().splitlines() if line.strip()]
        new_offset = f.tell()

    return lines, new_offset


def ship(log_source: str, lines: list[str]) -> bool:
    if not lines:
        return True

    body = json.dumps({
        "agent_id": AGENT_ID,
        "log_source": log_source,
        "lines": lines,
    }).encode("utf-8")

    request = urllib.request.Request(
        f"{API_URL}/ingest",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Sentinel-Token": TOKEN},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read())
            print(f"[{log_source}] {len(lines)} líneas enviadas -> {result}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[{log_source}] error HTTP {e.code}: {e.read().decode(errors='ignore')}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"[{log_source}] no se pudo conectar a {API_URL}: {e}", file=sys.stderr)
    return False


def main() -> int:
    if not TOKEN:
        print("SENTINEL_INGEST_TOKEN no está configurado — abortando", file=sys.stderr)
        return 1

    offsets = load_offsets()

    for log_source, path in LOG_SOURCES.items():
        offset = offsets.get(path, 0)
        lines, new_offset = read_new_lines(path, offset)

        ok = True
        for i in range(0, len(lines), MAX_LINES_PER_REQUEST):
            ok = ship(log_source, lines[i:i + MAX_LINES_PER_REQUEST]) and ok

        # Solo avanzamos el offset si se logró mandar todo -- si la API
        # estaba caída, el siguiente tick reintenta desde el mismo punto.
        if ok:
            offsets[path] = new_offset

    save_offsets(offsets)
    return 0


if __name__ == "__main__":
    sys.exit(main())
