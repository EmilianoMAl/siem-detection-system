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


def get_summary(
    log_source: str = "ALL", time_range: str = "all",
    start: str | None = None, end: str | None = None,
    environment: str = "ALL", agent_id: str = "ALL",
) -> dict:
    params = {
        "log_source": log_source, "time_range": time_range,
        "environment": environment, "agent_id": agent_id,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    return _get("/summary", params)


def get_alerts(
    status: str | None = None, time_range: str = "all",
    start: str | None = None, end: str | None = None,
    environment: str = "ALL", hostname: str | None = None,
    query: str | None = None,
) -> list[dict]:
    params = {"time_range": time_range, "environment": environment}
    if status:
        params["status"] = status
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    if hostname:
        params["hostname"] = hostname
    if query:
        params["query"] = query
    return _get("/alerts", params)


def update_alert_status(alert_id: str, status: str, note: str | None = None) -> dict:
    return _patch(f"/alerts/{alert_id}", {"status": status, "note": note})


def get_agents(environment: str = "ALL") -> list[dict]:
    return _get("/agents", {"environment": environment})


def get_top_ips(
    log_source: str = "ALL", time_range: str = "all",
    start: str | None = None, end: str | None = None,
    environment: str = "ALL", agent_id: str = "ALL",
) -> list[dict]:
    params = {
        "log_source": log_source, "time_range": time_range,
        "environment": environment, "agent_id": agent_id,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    return _get("/top-ips", params)


def get_event_types(
    log_source: str = "ALL", time_range: str = "all",
    start: str | None = None, end: str | None = None,
    environment: str = "ALL", agent_id: str = "ALL",
) -> list[dict]:
    params = {
        "log_source": log_source, "time_range": time_range,
        "environment": environment, "agent_id": agent_id,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    return _get("/event-types", params)


def get_timeline(
    log_source: str = "ALL", time_range: str = "all",
    start: str | None = None, end: str | None = None,
    environment: str = "ALL", agent_id: str = "ALL",
) -> list[dict]:
    params = {
        "log_source": log_source, "time_range": time_range,
        "environment": environment, "agent_id": agent_id,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    return _get("/timeline", params)


def get_events(
    environment: str = "ALL", agent_id: str = "ALL", log_source: str = "ALL",
    time_range: str = "all", start: str | None = None, end: str | None = None,
    limit: int = 50, query: str | None = None,
) -> list[dict]:
    params = {
        "environment": environment, "agent_id": agent_id, "log_source": log_source,
        "time_range": time_range, "limit": limit,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    if query:
        params["query"] = query
    return _get("/events", params)


def get_mitre_coverage(environment: str = "ALL", hostname: str | None = None) -> list[dict]:
    params = {"environment": environment}
    if hostname:
        params["hostname"] = hostname
    return _get("/mitre-coverage", params)


def get_geo_attackers(environment: str = "ALL", agent_id: str = "ALL") -> list[dict]:
    return _get("/geo-attackers", {"environment": environment, "agent_id": agent_id})
