"""
Geolocalización de IPs vía ip-api.com (gratis, sin API key). Solo
librería estándar — mismo criterio que agent/ship_logs.py: nada de
agregar `requests` a api/requirements.txt solo para esto.
"""
import ipaddress
import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon"
TIMEOUT = 5


def is_private_ip(ip: str) -> bool:
    """
    True si la IP es privada/reservada/loopback (RFC1918, etc.) — no
    tiene sentido gastar una consulta externa en ellas, y son justo los
    rangos que usan nuestros propios agentes simulados como "internos".
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # IP inválida/no parseable -> no la mandamos a la API


def lookup_ip(ip: str) -> dict | None:
    """
    Consulta país/ciudad/lat/lon de una IP pública. None ante cualquier
    falla (timeout, rate limit, IP inválida para el servicio) — un
    lookup fallido nunca debe tumbar el endpoint que lo llama.
    """
    if is_private_ip(ip):
        return None

    try:
        with urllib.request.urlopen(GEOIP_URL.format(ip=ip), timeout=TIMEOUT) as response:
            data = json.loads(response.read())
    # OSError cubre ConnectionResetError/ConnectionRefusedError/socket.timeout
    # -- urllib no siempre los envuelve en URLError, y un lookup fallido de
    # una API externa jamás debe tumbar el endpoint que lo llama.
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as e:
        logger.warning(f"Geolocalización falló para {ip}: {e}")
        return None

    if data.get("status") != "success":
        return None

    return {
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "city": data.get("city"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }
