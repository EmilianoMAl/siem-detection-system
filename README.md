# 🛡️ SENTINEL — Multi-Agent Detection System

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-manager-009688?logo=fastapi)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite)
![Streamlit](https://img.shields.io/badge/Streamlit-dashboard-FF4B4B?logo=streamlit)
![Docker](https://img.shields.io/badge/Docker-compose-2496ED?logo=docker)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)
![Tests](https://img.shields.io/badge/tests-pytest-0A9EDC)

SIEM de detección multi-agente inspirado en el modelo manager/agente de
Wazuh: una flota de hosts simulados reporta eventos de **SSH, tráfico web
y FIM (integridad de archivos)** a un manager central (API FastAPI), que
los normaliza, los corre contra un ruleset configurable mapeado a MITRE
ATT&CK, y los expone a un dashboard estilo SOC.

---

## 📐 Architecture

```
┌──────────────────────────┐
│  Agents (engine/agents.py)│  4 hosts simulados: ssh / web / fim
└────────────┬──────────────┘
             │  engine/generators/{ssh,web,fim}_generator.py
             ▼
┌──────────────────────────┐
│  Log Generator            │  Orquesta generación por agente/fuente
│  engine/log_generator.py  │  → logs/raw/{agent_id}_{source}_*.log
└────────────┬──────────────┘
             │  engine/pipeline.py (dispatch por fuente)
             ▼
┌──────────────────────────┐
│  Parsers                  │  auth_parser · web_parser · fim_parser
│  → LogEvent normalizado   │  (agent_id, log_source, metadata)
└────────────┬──────────────┘
             ▼
┌──────────────────────────┐
│  Detection Engine         │  6 reglas · umbrales en config/rules.yaml
│  engine/detectors/rules.py│  MITRE ATT&CK mapped alerts
└────────────┬──────────────┘
             ▼
┌──────────────────────────┐
│  SQLite Database          │  events + alerts + agents
└────────────┬──────────────┘
             │  engine/bootstrap.py (corre al iniciar si la DB está vacía)
             ▼
┌──────────────────────────┐         ┌───────────────────────────┐
│  SENTINEL API (FastAPI)   │  HTTP   │  Streamlit Dashboard       │
│  api/main.py · :8000      │◀───────▶│  Home + Agents · :8501     │
│  /summary /alerts /agents │         │  (cliente puro de la API)  │
└──────────────────────────┘         └───────────────────────────┘
```

El dashboard **no toca SQLite directamente** — todo pasa por la API, lo
que permite desplegar cada pieza como su propio contenedor/proceso (ver
[`docker-compose.yml`](docker-compose.yml) y [`DEPLOYMENT.md`](DEPLOYMENT.md)).

---

## 🎯 Detection Rules

| Rule | Fuente | Técnica | MITRE ID | Severidad |
|---|---|---|---|---|
| SSH Brute Force | ssh | Múltiples logins fallidos desde una IP | T1110 | HIGH/CRITICAL |
| Suspicious Sudo | ssh | Comandos con patrones de post-explotación | T1548 | HIGH |
| Login After Failures | ssh | Login exitoso desde IP con fallos previos | T1078 | CRITICAL |
| Web Attack Payload | web | SQLi / XSS / path traversal en requests | T1190 | HIGH |
| Web Recon Scan | web | Directory brute-force (muchas rutas/404) | T1595 | MEDIUM/HIGH |
| FIM Critical File Change | fim | Modificación de archivo crítico del sistema | T1098 / T1565.001 | CRITICAL |

Los umbrales y patrones de cada regla viven en [`config/rules.yaml`](config/rules.yaml)
— se pueden ajustar sin tocar código, igual que un ruleset de Wazuh.

---

## 🖥️ Simulated Agent Fleet

| Agent | Hostname | Fuentes | OS |
|---|---|---|---|
| agent-001 | prod-server-01 | ssh, fim | Ubuntu 22.04 LTS |
| agent-002 | web-server-02 | ssh, web | Ubuntu 22.04 LTS |
| agent-003 | db-server-03 | ssh, fim | Debian 12 |
| agent-004 | mail-server-04 | ssh | Rocky Linux 9 |

Definidos en [`engine/agents.py`](engine/agents.py). El dashboard tiene una
página **Agents** que muestra su estado (ACTIVE/DISCONNECTED por heartbeat),
IP, OS y conteo de eventos/alertas — el equivalente al panel de Agents de
un SIEM real.

---

## 🧩 Custom Dashboard Builder

Un lienzo de arrastrar-y-soltar (estilo Power BI/Tableau) para armar tus
propias vistas — sin tocar código. Página estática propia servida por la
API en `/builder/` (enlazada desde el sidebar del dashboard), construida
con [GridStack.js](https://gridstack.github.io/gridstack.js/) para el
grid y [Plotly.js](https://plotly.com/javascript/) para las gráficas.

- Cada widget se configura eligiendo dataset (eventos/alertas), dimensión
  para agrupar, filtros y tipo de gráfica (barras/líneas/pastel/KPI).
- El endpoint `GET /query` (`engine/storage.py::query_generic`) resuelve
  cualquier combinación dataset+dimensión contra un whitelist explícito de
  columnas agrupables — nunca se interpola la dimensión elegida por el
  usuario directo en SQL.
- Los dashboards armados se guardan (`custom_dashboards` en SQLite) y se
  pueden recargar después con su layout exacto (posición/tamaño por widget).

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Log simulation | Python — auth.log / access log / FIM |
| Parsing | Python + Regex |
| Detection engine | Python, reglas configurables vía YAML |
| Storage | SQLite (events, alerts, agents) |
| Manager API | FastAPI + Uvicorn (`/docs` con Swagger UI) |
| Dashboard | Streamlit + Plotly (multi-page), cliente HTTP de la API |
| Deployment | Docker Compose + Nginx (ver `DEPLOYMENT.md`) |
| Tests | Pytest |

---

## 📁 Project Structure

```
siem-detection-system/
│
├── config/
│   └── rules.yaml               # Umbrales y patrones del ruleset
│
├── engine/                       # Lógica de negocio — el manager
│   ├── agents.py                 # Entidad Agent + flota simulada
│   ├── config.py                 # Carga config/rules.yaml
│   ├── bootstrap.py              # Genera datos de demo si la DB está vacía
│   ├── log_generator.py          # Orquestador multi-agente/multi-fuente
│   ├── pipeline.py                # Dispatch de parsing por fuente
│   ├── storage.py                # Persistencia SQLite (events/alerts/agents)
│   ├── generators/
│   │   ├── ssh_generator.py
│   │   ├── web_generator.py
│   │   └── fim_generator.py
│   ├── parsers/
│   │   ├── auth_parser.py        # → LogEvent (log_source="ssh")
│   │   ├── web_parser.py         # → LogEvent (log_source="web")
│   │   └── fim_parser.py         # → LogEvent (log_source="fim")
│   └── detectors/
│       └── rules.py              # 6 reglas + Alert generation
│
├── api/                          # Manager HTTP — único que toca engine/
│   ├── main.py                   # FastAPI: /summary /alerts /agents /...
│   ├── schemas.py                # Modelos Pydantic de respuesta
│   ├── Dockerfile
│   └── requirements.txt
│
├── dashboard/                    # Cliente puro de la API (sin SQLite)
│   ├── app.py                    # Home — KPIs, feed de alertas, gráficos
│   ├── api_client.py             # Wrapper HTTP sobre la API
│   ├── theme.py                  # CSS/tema compartido entre páginas
│   ├── Dockerfile
│   └── pages/
│       └── 1_🖥️_Agents.py        # Estado de la flota de agentes
│
├── deploy/nginx/sentinel.conf    # Reverse proxy para la VM
├── docker-compose.yml            # api + dashboard
├── DEPLOYMENT.md                 # Guía paso a paso: VM Hyper-V + Docker + Nginx
│
├── data/
│   └── siem.db                    # SQLite (gitignored)
│
├── logs/raw/                      # Logs generados (gitignored)
│
└── tests/                         # pytest — parsers, rules, storage
```

---

## 🚀 Local Setup

### Prerequisites
- Python 3.11+
- Git

### 1. Clone
```bash
git clone https://github.com/EmilianoMAl/siem-detection-system.git
cd siem-detection-system
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

> Si vienes de una versión anterior de SENTINEL (sin agentes/multi-fuente),
> borra `data/siem.db` una vez — el esquema cambió.

### 3. Run tests
```bash
pytest -q
```

### 4. Launch the API (el manager — genera los datos de demo al iniciar)
```bash
uvicorn api.main:app --reload --port 8000
```
Docs interactivas en http://localhost:8000/docs

### 5. Launch the dashboard (en otra terminal)
```bash
streamlit run dashboard/app.py
```
El dashboard es un cliente HTTP puro — necesita la API corriendo en
`http://localhost:8000` (configurable con la variable de entorno
`SENTINEL_API_URL`). La página **Agents** aparece en el sidebar.

### Alternativa: Docker Compose (api + dashboard juntos)
```bash
docker compose up -d --build
```
Ver [`DEPLOYMENT.md`](DEPLOYMENT.md) para desplegar esto en una VM propia.

---

## ⚙️ Technical Decisions

**Por qué un modelo de agentes en vez de un solo host**
Un SIEM real correlaciona telemetría de muchos endpoints, no de uno.
Modelar `Agent` como entidad propia (en vez de un hostname suelto) es lo
que permite después conectar un agente real (daemon en una VM) sin
rediseñar el esquema.

**Por qué SQLite sobre Elasticsearch**
Para un proyecto de portafolio, SQLite da capacidades de consulta
equivalentes sin requerir un stack ELK de 3 contenedores. La lógica de
detección es idéntica — solo cambia el backend de storage.

**Por qué reglas en YAML y no hardcodeadas**
Permite ajustar umbrales/patrones sin tocar código — el mismo principio
que el ruleset de Wazuh o las reglas SIGMA.

**Por qué MITRE ATT&CK mapping**
Cada regla está mapeada a una técnica MITRE. Es el estándar de la
industria para clasificación de amenazas — hace que las alertas sean
accionables para un analista.

**Por qué separar la API del dashboard**
Streamlit hablando directo con SQLite funciona para una demo, pero no
escala a un despliegue real: no puedes correr el dashboard en un host y
la base de datos en otro, ni añadir después un agente real que empuje
eventos sin que el dashboard también tenga que saber de SQLite. La API
(FastAPI) es la única que toca `engine/`; el dashboard es un cliente HTTP
puro — así cada pieza se despliega y escala por separado.

---

## 🔍 Simulated Attack Scenarios

**SSH Brute Force**
```
Apr 03 10:23:45 prod-server-01 sshd[4521]: Failed password for root from 94.102.49.190 port 52341 ssh2
Apr 03 10:23:46 prod-server-01 sshd[4522]: Failed password for root from 94.102.49.190 port 52342 ssh2
... (hasta 25 intentos)
```

**Web Attack (SQLi)**
```
45.33.32.156 - - [03/Apr/2026:10:23:45 +0000] "GET /login?user=admin'%20OR%20'1'='1 HTTP/1.1" 200 512 "-" "sqlmap/1.7"
```

**FIM — Persistencia vía authorized_keys**
```
Apr 03 10:24:12 prod-server-01 syscheck: File '/root/.ssh/authorized_keys' created (user=root, hash_before=none, hash_after=aaa111)
```

---

## 🎓 Defensive Recommendations

Cada alerta incluye una recomendación accionable:

- **Brute Force** → Bloquear IP en firewall, revisar si algún intento fue exitoso
- **Suspicious sudo** → Revocar privilegios sudo temporalmente, auditar al usuario
- **Login after failures** → Verificación inmediata de cuenta, forzar cambio de contraseña
- **Web attack payload** → Bloquear IP en el WAF, revisar logs de la aplicación
- **Web recon scan** → Rate-limiting o bloqueo temporal de la IP
- **FIM critical change** → Verificar autorización del cambio, comparar hashes, restaurar backup

---

*Built by Emiliano — Data Engineering + Cybersecurity Portfolio*
*Stack: Python · SQLite · Streamlit · MITRE ATT&CK Framework*
