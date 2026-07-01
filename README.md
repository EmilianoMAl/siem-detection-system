# 🛡️ SENTINEL — Multi-Agent Detection System

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite)
![Streamlit](https://img.shields.io/badge/Streamlit-deployed-FF4B4B?logo=streamlit)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)
![Tests](https://img.shields.io/badge/tests-pytest-0A9EDC)

SIEM de detección multi-agente inspirado en el modelo manager/agente de
Wazuh: una flota de hosts simulados reporta eventos de **SSH, tráfico web
y FIM (integridad de archivos)** a un manager central, que los normaliza,
los corre contra un ruleset configurable mapeado a MITRE ATT&CK, y los
visualiza en un dashboard estilo SOC.

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
┌─────────────────────┐    ┌───────────────────────────┐
│  SQLite Database     │    │  Streamlit SIEM Dashboard  │
│  events+alerts+agents│───▶│  Home + Agents page        │
└─────────────────────┘    └───────────────────────────┘
```

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

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Log simulation | Python — auth.log / access log / FIM |
| Parsing | Python + Regex |
| Detection engine | Python, reglas configurables vía YAML |
| Storage | SQLite (events, alerts, agents) |
| Dashboard | Streamlit + Plotly (multi-page) |
| Tests | Pytest |

---

## 📁 Project Structure

```
siem-detection-system/
│
├── config/
│   └── rules.yaml               # Umbrales y patrones del ruleset
│
├── engine/
│   ├── agents.py                 # Entidad Agent + flota simulada
│   ├── config.py                 # Carga config/rules.yaml
│   ├── log_generator.py          # Orquestador multi-agente/multi-fuente
│   ├── pipeline.py               # Dispatch de parsing por fuente
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
├── dashboard/
│   ├── app.py                    # Home — KPIs, feed de alertas, gráficos
│   ├── theme.py                  # CSS/tema compartido entre páginas
│   └── pages/
│       └── 1_🖥️_Agents.py        # Estado de la flota de agentes
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

### 4. Generate + ingest logs manually (opcional — el dashboard lo hace solo)
```bash
python -m engine.storage
```

### 5. Launch dashboard
```bash
streamlit run dashboard/app.py
```
Al abrir por primera vez, SENTINEL genera automáticamente datos de demo
para los 4 agentes simulados. La página **Agents** aparece en el sidebar.

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
