import os
import requests

API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:8000")
TIMEOUT = 10


def _get(path: str, params: dict | None = None):
    response = requests.get(f"{API_URL}{path}", params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def get_health() -> dict:
    return _get("/health")


def get_summary(log_source: str = "ALL") -> dict:
    return _get("/summary", {"log_source": log_source})


def get_alerts() -> list[dict]:
    return _get("/alerts")


def get_agents() -> list[dict]:
    return _get("/agents")


def get_top_ips(log_source: str = "ALL") -> list[dict]:
    return _get("/top-ips", {"log_source": log_source})


def get_event_types(log_source: str = "ALL") -> list[dict]:
    return _get("/event-types", {"log_source": log_source})


def get_timeline(log_source: str = "ALL") -> list[dict]:
    return _get("/timeline", {"log_source": log_source})
