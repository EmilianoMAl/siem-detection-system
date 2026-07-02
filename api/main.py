import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from engine.bootstrap import bootstrap_data
from engine.storage import (
    query_summary, query_alerts, query_agents,
    query_top_ips, query_event_types, query_timeline,
    query_generic, GENERIC_QUERY_DIMENSIONS,
    save_dashboard, update_dashboard, list_dashboards,
    get_dashboard, delete_dashboard,
)
from api.schemas import (
    SummaryResponse, AlertResponse, AgentResponse,
    TopIpResponse, EventTypeResponse, TimelinePointResponse, HealthResponse,
    QueryPointResponse, DashboardSummary, DashboardDetail, DashboardSaveRequest,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

LogSource = Literal["ALL", "SSH", "WEB", "FIM"]
Severity = Literal["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
Dataset = Literal["events", "alerts"]

STATIC_DIR = Path(__file__).parent / "static"


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

# Todas las rutas de datos se definen en este router y se montan DOS veces:
# en la raíz (lo que ya consume dashboard/api_client.py tal cual) y bajo
# /api (para que el builder estático en /builder funcione igual pegándole
# directo a :8000/api/... en local que a través de Nginx en la VM, donde
# /api/ ya se enruta al backend).
router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health() -> dict:
    return {"status": "ok"}


@router.get("/summary", response_model=SummaryResponse)
def get_summary(log_source: LogSource = "ALL") -> dict:
    return query_summary(log_source)


@router.get("/alerts", response_model=list[AlertResponse])
def get_alerts() -> list[dict]:
    return query_alerts(limit=500)


@router.get("/agents", response_model=list[AgentResponse])
def get_agents() -> list[dict]:
    return query_agents()


@router.get("/top-ips", response_model=list[TopIpResponse])
def get_top_ips(log_source: LogSource = "ALL") -> list[dict]:
    return query_top_ips(log_source)


@router.get("/event-types", response_model=list[EventTypeResponse])
def get_event_types(log_source: LogSource = "ALL") -> list[dict]:
    return query_event_types(log_source)


@router.get("/timeline", response_model=list[TimelinePointResponse])
def get_timeline(log_source: LogSource = "ALL") -> list[dict]:
    return query_timeline(log_source)


@router.get("/query-dimensions")
def get_query_dimensions() -> dict:
    """Dimensiones agrupables válidas por dataset — el builder las usa para poblar sus selects."""
    return {dataset: list(dims.keys()) for dataset, dims in GENERIC_QUERY_DIMENSIONS.items()}


@router.get("/query", response_model=list[QueryPointResponse])
def run_query(
    dataset: Dataset,
    group_by: str,
    log_source: LogSource = "ALL",
    severity: Severity = "ALL",
    limit: int = 10,
) -> list[dict]:
    try:
        return query_generic(dataset, group_by, log_source=log_source, severity=severity, limit=limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/dashboards", response_model=list[DashboardSummary])
def get_dashboards() -> list[dict]:
    return list_dashboards()


@router.post("/dashboards", response_model=DashboardDetail)
def create_dashboard(body: DashboardSaveRequest) -> dict:
    dashboard_id = save_dashboard(body.name, body.layout)
    return get_dashboard(dashboard_id)


@router.get("/dashboards/{dashboard_id}", response_model=DashboardDetail)
def read_dashboard(dashboard_id: int) -> dict:
    dashboard = get_dashboard(dashboard_id)
    if dashboard is None:
        raise HTTPException(status_code=404, detail="Dashboard no encontrado")
    return dashboard


@router.put("/dashboards/{dashboard_id}", response_model=DashboardDetail)
def edit_dashboard(dashboard_id: int, body: DashboardSaveRequest) -> dict:
    if not update_dashboard(dashboard_id, body.name, body.layout):
        raise HTTPException(status_code=404, detail="Dashboard no encontrado")
    return get_dashboard(dashboard_id)


@router.delete("/dashboards/{dashboard_id}")
def remove_dashboard(dashboard_id: int) -> dict:
    if not delete_dashboard(dashboard_id):
        raise HTTPException(status_code=404, detail="Dashboard no encontrado")
    return {"deleted": dashboard_id}


app.include_router(router)
app.include_router(router, prefix="/api")

app.mount("/builder", StaticFiles(directory=str(STATIC_DIR / "builder"), html=True), name="builder")
