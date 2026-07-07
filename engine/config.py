import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

RULES_CONFIG_PATH = Path("config/rules.yaml")

# Usados si config/rules.yaml no existe o le falta alguna clave.
DEFAULT_RULES_CONFIG: dict[str, Any] = {
    "ssh_brute_force": {
        "fail_threshold": 5,
        "critical_threshold": 20,
    },
    "suspicious_sudo": {
        "patterns": [
            "/etc/shadow", "/etc/passwd", "chmod 777", "/tmp/",
            ">& /dev/tcp", "wget http", "curl http", "python3 -c",
            "pty.spawn", "base64 -d", "nc -e", "bash -i",
        ],
    },
    "web_attack": {
        "patterns": [
            "union select", "' or '1'='1", "<script", "../../",
            "etc/passwd", "drop table", "; exec", "onerror=",
        ],
    },
    "recon_scan": {
        "distinct_paths_threshold": 10,
        "not_found_threshold": 8,
    },
    "fim_critical_change": {
        "critical_paths": [
            "/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
            "/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys",
            "/usr/bin/*",
        ],
    },
    "sonicwall_denials": {
        "fail_threshold": 5,
        "critical_threshold": 20,
    },
}


def load_rules_config(path: Path = RULES_CONFIG_PATH) -> dict[str, Any]:
    """
    Carga config/rules.yaml. Si el archivo no existe o hay claves faltantes,
    rellena con DEFAULT_RULES_CONFIG para que el motor de detección nunca
    se quede sin umbrales.
    """
    config: dict[str, Any] = {
        section: dict(values) for section, values in DEFAULT_RULES_CONFIG.items()
    }

    if not path.exists():
        logger.warning(f"{path} no existe — usando configuración por defecto")
        return config

    with open(path, "r", encoding="utf-8") as f:
        loaded = yaml.safe_load(f) or {}

    for section, values in loaded.items():
        if section in config and isinstance(values, dict):
            config[section].update(values)
        else:
            config[section] = values

    logger.info(f"Configuración de reglas cargada desde {path}")
    return config
