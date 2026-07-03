from typing import Literal, Optional
from pydantic import BaseModel


class SummaryResponse(BaseModel):
    total_events: int
    unique_ips: int
    failed: int
    ok_logins: int
    sudo: int
    total_alerts: int
    critical: int
    high: int
    agents_total: int
    agents_active: int


class AlertResponse(BaseModel):
    alert_id: str
    rule_name: str
    severity: str
    description: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    mitre_technique: Optional[str] = None
    recommendation: Optional[str] = None
    detected_at: Optional[str] = None
    evidence: Optional[str] = None  # JSON string, tal como se guarda en SQLite
    status: str = "OPEN"
    note: Optional[str] = None
    resolved_at: Optional[str] = None


class AlertStatusUpdate(BaseModel):
    status: Literal["OPEN", "ACKNOWLEDGED", "CLOSED"]
    note: Optional[str] = None


class AgentResponse(BaseModel):
    agent_id: str
    hostname: str
    ip_address: Optional[str] = None
    os: Optional[str] = None
    log_sources: list[str]
    last_seen: Optional[str] = None
    registered_at: Optional[str] = None
    status: str
    event_count: int
    alert_count: int


class TopIpResponse(BaseModel):
    source_ip: str
    attempts: int
    targeted_users: int


class EventTypeResponse(BaseModel):
    event_type: str
    n: int


class TimelinePointResponse(BaseModel):
    hour: str
    event_type: str
    n: int


class HealthResponse(BaseModel):
    status: str


class MitreTechniqueResponse(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    count: int


class GeoAttackerResponse(BaseModel):
    source_ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    lat: float
    lon: float
    attempts: int


class QueryPointResponse(BaseModel):
    label: Optional[str] = None
    value: int


class DashboardSummary(BaseModel):
    id: int
    name: str
    created_at: str
    updated_at: str


class DashboardDetail(BaseModel):
    id: int
    name: str
    layout: list[dict]
    created_at: str
    updated_at: str


class DashboardSaveRequest(BaseModel):
    name: str
    layout: list[dict]


class IngestRequest(BaseModel):
    agent_id: str
    log_source: str
    lines: list[str]


class IngestResponse(BaseModel):
    ingested: int
    unparsed: int
    alerts: int
