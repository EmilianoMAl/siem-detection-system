import streamlit as st

# Tema visual compartido por todas las páginas del dashboard
# (Home, Agents, ...). "Quiet Console" — antracita cálido + acento zafiro,
# sin neón ni parpadeos: la idea es que se lea como un producto SaaS
# terminado, no como una terminal de película de hackers.

CSS = """
<style>
:root {
    --bg:            #17181C;
    --bg-sidebar:    #121317;
    --surface:       #1D1E23;
    --border:        #2B2C31;
    --text:          #F1F0EE;
    --text-muted:    #ABA9A3;
    --text-faint:    #6E6D68;
    --accent:        #5B8CF0;
    --critical:      #F0685E;
    --critical-bg:   rgba(240,104,94,0.16);
    --critical-text: #F0938B;
    --high:          #E5A63C;
    --high-bg:       rgba(229,166,60,0.16);
    --medium:        #6B93D6;
    --medium-bg:     rgba(107,147,214,0.16);
    --ok:            #5FD09A;
}

/* ── BASE ── */
html, body, [class*="css"] {
    font-family: -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    background-color: var(--bg);
    color: var(--text-muted);
}
.stApp { background: var(--bg); }

/* ── SIDEBAR ── */
[data-testid="stSidebar"] {
    background: var(--bg-sidebar) !important;
    border-right: 1px solid var(--border);
}
[data-testid="stSidebar"] * { color: var(--text-muted) !important; }

/* ── HEADERS ── */
h1 {
    color: var(--text) !important;
    font-size: 1.5rem !important;
    font-weight: 650 !important;
    letter-spacing: -0.01em;
}
h2, h3 {
    color: var(--text-muted) !important;
    font-weight: 600 !important;
    font-size: 0.8rem !important;
    letter-spacing: 0.02em;
}

/* ── METRICAS (KPIs) ── */
[data-testid="metric-container"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 16px !important;
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.02);
}
[data-testid="stMetricLabel"] {
    color: var(--text-muted) !important;
    font-size: 0.72rem !important;
    letter-spacing: 0.02em;
}
[data-testid="stMetricValue"] {
    font-size: 1.6rem !important;
    font-weight: 650 !important;
    color: var(--text) !important;
    letter-spacing: -0.01em;
}

/* ── TABLAS ── */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: 10px;
}

/* ── SELECTBOX ── */
[data-testid="stSelectbox"] > div > div {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    color: var(--text) !important;
}

/* ── DIVIDER ── */
hr { border-color: var(--border) !important; }

/* ── ALERT CARDS ── */
.alert-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 8px;
}

/* ── SEVERITY PILLS ── */
.sev-pill {
    font-size: 0.68rem;
    font-weight: 650;
    padding: 3px 10px;
    border-radius: 999px;
}
.sev-critical { background: var(--critical-bg); color: var(--critical-text); }
.sev-high     { background: var(--high-bg);     color: var(--high); }
.sev-medium   { background: var(--medium-bg);   color: var(--medium); }
.sev-low      { background: var(--border);      color: var(--text-muted); }

/* ── CHIPS (ip / mitre / source / agent) ── */
.chip {
    background: var(--border);
    color: var(--text-muted);
    font-size: 0.68rem;
    padding: 3px 10px;
    border-radius: 999px;
}
.chip-accent { color: var(--accent); }

.status-badge-active {
    background: rgba(95,208,154,0.16);
    color: var(--ok);
    font-size: 0.68rem;
    font-weight: 650;
    padding: 3px 10px;
    border-radius: 999px;
}
.status-badge-disconnected {
    background: var(--border);
    color: var(--text-faint);
    font-size: 0.68rem;
    font-weight: 650;
    padding: 3px 10px;
    border-radius: 999px;
}

.status-dot {
    display: inline-block;
    width: 7px; height: 7px;
    border-radius: 50%;
    margin-right: 6px;
    background: var(--ok);
}
.status-dot.off { background: var(--text-faint); }

.section-label {
    color: var(--text-muted);
    font-weight: 600;
    font-size: 0.72rem;
    letter-spacing: 0.02em;
    margin-bottom: 10px;
}

.muted-text {
    color: var(--text-faint);
    font-size: 0.78rem;
}
</style>
"""

# Colores compartidos por tipo de evento — usados en los gráficos Plotly
# y en cualquier chip que necesite distinguir el tipo de evento.
EVENT_COLORS = {
    "failed_password":   "#F0685E",
    "accepted_password": "#5FD09A",
    "accepted_publickey": "#4FBF8F",
    "invalid_user":       "#E5A63C",
    "ssh_preauth_disconnect": "#C97A3D",
    "sudo_command":       "#8C7AE0",
    "http_request":       "#5B8CF0",
    "fim_modified":        "#D98E3B",
    "fim_created":         "#5FD09A",
    "fim_deleted":         "#F0685E",
}

SEVERITY_CLASS = {
    "CRITICAL": "sev-critical",
    "HIGH":     "sev-high",
    "MEDIUM":   "sev-medium",
    "LOW":      "sev-low",
}

# Layout compartido para gráficos Plotly.
PLOTLY = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="-apple-system, Segoe UI, sans-serif", color="#ABA9A3"),
    margin=dict(l=10, r=10, t=10, b=10),
)


def inject_theme() -> None:
    """Inyecta el CSS del tema SENTINEL. Llamar una vez por página."""
    st.markdown(CSS, unsafe_allow_html=True)


def sidebar_brand() -> None:
    """Bloque de marca que aparece arriba del sidebar en todas las páginas."""
    st.markdown("""
    <div style='padding:8px 0 20px'>
        <div style='font-size:1rem; font-weight:650; color:#F1F0EE'>
            Sentinel
        </div>
        <div style='color:#6E6D68; font-size:0.7rem; margin-top:2px'>
            v3.0 · Multi-agent detection
        </div>
    </div>
    """, unsafe_allow_html=True)
