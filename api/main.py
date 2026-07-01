import logging
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI

from engine.bootstrap import bootstrap_data
from engine.storage import (
    query_summary, query_alerts, query_agents,
    query_top_ips, query_event_types, query_timeline,
)
from api.schemas import (
    SummaryResponse, AlertResponse, AgentResponse,
    TopIpResponse, EventTypeResponse, TimelinePointResponse, HealthResponse,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

LogSource = Literal["ALL", "SSH", "WEB", "FIM"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SENTINEL API iniciando — corriendo bootstrap si la DB está vacía")
    bootstrap_data()
    yield


app = FastAPI(
    title="SENTINEL SIEM API",
    description=(
        "Manager central de SENTINEL: normaliza eventos ssh/web/fim de la "
        "flota de agentes, corre el motor de detección (MITRE ATT&CK) y "
        "expone los resultados al dashboard."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse)
def health() -> dict:
    return {"status": "ok"}


@app.get("/summary", response_model=SummaryResponse)
def get_summary(log_source: LogSource = "ALL") -> dict:
    return query_summary(log_source)


@app.get("/alerts", response_model=list[AlertResponse])
def get_alerts() -> list[dict]:
    return query_alerts(limit=500)


@app.get("/agents", response_model=list[AgentResponse])
def get_agents() -> list[dict]:
    return query_agents()


@app.get("/top-ips", response_model=list[TopIpResponse])
def get_top_ips(log_source: LogSource = "ALL") -> list[dict]:
    return query_top_ips(log_source)


@app.get("/event-types", response_model=list[EventTypeResponse])
def get_event_types(log_source: LogSource = "ALL") -> list[dict]:
    return query_event_types(log_source)


@app.get("/timeline", response_model=list[TimelinePointResponse])
def get_timeline(log_source: LogSource = "ALL") -> list[dict]:
    return query_timeline(log_source)
