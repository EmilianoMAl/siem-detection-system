import os
import requests

API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:8000")
TIMEOUT = 10


def _get(path: str, params: dict | None = None):
    response = requests.get(f"{API_URL}{path}", params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def _patch(path: str, body: dict):
    response = requests.patch(f"{API_URL}{path}", json=body, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def get_health() -> dict:
    return _get("/health")


def get_summary(log_source: str = "ALL", time_range: str = "all") -> dict:
    return _get("/summary", {"log_source": log_source, "time_range": time_range})


def get_alerts(status: str | None = None, time_range: str = "all") -> list[dict]:
    params = {"time_range": time_range}
    if status:
        params["status"] = status
    return _get("/alerts", params)


def update_alert_status(alert_id: str, status: str, note: str | None = None) -> dict:
    return _patch(f"/alerts/{alert_id}", {"status": status, "note": note})


def get_agents() -> list[dict]:
    return _get("/agents")


def get_top_ips(log_source: str = "ALL", time_range: str = "all") -> list[dict]:
    return _get("/top-ips", {"log_source": log_source, "time_range": time_range})


def get_event_types(log_source: str = "ALL", time_range: str = "all") -> list[dict]:
    return _get("/event-types", {"log_source": log_source, "time_range": time_range})


def get_timeline(log_source: str = "ALL", time_range: str = "all") -> list[dict]:
    return _get("/timeline", {"log_source": log_source, "time_range": time_range})


def get_mitre_coverage() -> list[dict]:
    return _get("/mitre-coverage")


def get_geo_attackers() -> list[dict]:
    return _get("/geo-attackers")
