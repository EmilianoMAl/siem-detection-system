import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles

from engine.agents import find_known_agent
from engine.bootstrap import bootstrap_data, simulate_tick
from engine.detectors.rules import DetectionEngine
from engine.pipeline import ingest_lines, LINE_PARSERS
from engine.storage import (
    query_summary, query_alerts, query_agents,
    query_top_ips, query_event_types, query_timeline,
    query_generic, GENERIC_QUERY_DIMENSIONS,
    save_dashboard, update_dashboard, list_dashboards,
    get_dashboard, delete_dashboard,
    insert_events, insert_alerts, touch_agent, get_max_alert_counter,
    update_alert_status,
)
from api.schemas import (
    SummaryResponse, AlertResponse, AgentResponse,
    TopIpResponse, EventTypeResponse, TimelinePointResponse, HealthResponse,
    QueryPointResponse, DashboardSummary, DashboardDetail, DashboardSaveRequest,
    IngestRequest, IngestResponse, AlertStatusUpdate,
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

INGEST_TOKEN = os.environ.get("SENTINEL_INGEST_TOKEN", "")
MAX_INGEST_LINES = 500
SIMULATION_TICK_SECONDS = int(os.environ.get("SENTINEL_SIMULATION_TICK_SECONDS", 300))


async def _simulation_loop():
    """
    Mantiene la demo "viva": cada SIMULATION_TICK_SECONDS genera un lote
    nuevo de actividad simulada y actualiza el heartbeat de los agentes
    simulados. Sin esto, el bootstrap corre una sola vez y los agentes
    se ven DISCONNECTED / el dashboard se ve igual en cada refresh.
    """
    while True:
        await asyncio.sleep(SIMULATION_TICK_SECONDS)
        try:
            await asyncio.to_thread(simulate_tick)
        except Exception:
            logger.exception("Tick de simulación falló — se reintenta en el siguiente ciclo")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SENTINEL API iniciando — corriendo bootstrap si la DB está vacía")
    bootstrap_data()

    task = asyncio.create_task(_simulation_loop())
    yield
    task.cancel()


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


AlertStatus = Literal["OPEN", "ACKNOWLEDGED", "CLOSED"]


@router.get("/alerts", response_model=list[AlertResponse])
def get_alerts(status: AlertStatus | None = None) -> list[dict]:
    return query_alerts(status=status, limit=500)


@router.patch("/alerts/{alert_id}", response_model=AlertResponse)
def patch_alert(alert_id: str, body: AlertStatusUpdate) -> dict:
    updated = update_alert_status(alert_id, body.status, body.note)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Alerta no encontrada: {alert_id}")
    return updated


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


@router.post("/ingest", response_model=IngestResponse)
def ingest(body: IngestRequest, x_sentinel_token: str = Header(default="")) -> dict:
    """
    Recibe líneas de log de un agente real (ver agent/ship_logs.py) y las
    procesa igual que la simulación: parsea, detecta, inserta. Protegido
    con un secreto compartido — nunca se expone en Nginx a propósito,
    pero de todos modos queda alcanzable vía /api/ingest (así funciona el
    proxy hoy), así que el token es la única defensa real, no la ruta.
    """
    if not INGEST_TOKEN or not hmac.compare_digest(x_sentinel_token, INGEST_TOKEN):
        raise HTTPException(status_code=401, detail="Token inválido o no configurado")

    if body.log_source not in LINE_PARSERS:
        raise HTTPException(status_code=400, detail=f"log_source inválido: {body.log_source}")

    if len(body.lines) > MAX_INGEST_LINES:
        raise HTTPException(status_code=400, detail=f"Máximo {MAX_INGEST_LINES} líneas por request")

    agent = find_known_agent(body.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"agent_id desconocido: {body.agent_id}")

    events, unparsed = ingest_lines(agent, body.log_source, body.lines)
    touch_agent(agent.agent_id)

    engine = DetectionEngine(start_counter=get_max_alert_counter())
    alerts = engine.run_all_rules(events)

    insert_events(events)
    insert_alerts(alerts)

    return {"ingested": len(events), "unparsed": unparsed, "alerts": len(alerts)}


app.include_router(router)
app.include_router(router, prefix="/api")

app.mount("/builder", StaticFiles(directory=str(STATIC_DIR / "builder"), html=True), name="builder")
