import streamlit as st

# Tema visual compartido por todas las páginas del dashboard
# (Home, Agents, ...). Se centraliza aquí para no duplicar el
# bloque de CSS en cada archivo de dashboard/pages/.

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&display=swap');

/* ── BASE ── */
html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #030712;
    color: #94a3b8;
}

.stApp {
    background:
        linear-gradient(rgba(0,255,136,0.015) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,136,0.015) 1px, transparent 1px),
        #030712;
    background-size: 40px 40px;
}

/* ── SIDEBAR ── */
[data-testid="stSidebar"] {
    background: #050d18 !important;
    border-right: 1px solid #0f2a1a;
}
[data-testid="stSidebar"] * { color: #4b7a5e !important; }

/* ── HEADERS ── */
h1 {
    font-family: 'Share Tech Mono', monospace !important;
    color: #00ff88 !important;
    font-size: 1.6rem !important;
    text-shadow: 0 0 20px rgba(0,255,136,0.4);
    letter-spacing: 0.1em;
}
h2, h3 {
    font-family: 'Rajdhani', sans-serif !important;
    color: #64748b !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    font-size: 0.75rem !important;
}

/* ── MÉTRICAS ── */
[data-testid="metric-container"] {
    background: #050d18;
    border: 1px solid #0f2a1a;
    border-radius: 4px;
    padding: 16px !important;
    position: relative;
    overflow: hidden;
    transition: border-color 0.3s;
}
[data-testid="metric-container"]::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00ff88, transparent);
    animation: scanline 3s linear infinite;
}
@keyframes scanline {
    0%   { transform: translateX(-100%); }
    100% { transform: translateX(100%); }
}
[data-testid="metric-container"]:hover { border-color: #00ff88; }
[data-testid="stMetricLabel"] {
    color: #1f4a2e !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.65rem !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}
[data-testid="stMetricValue"] {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 2rem !important;
    color: #00ff88 !important;
    text-shadow: 0 0 15px rgba(0,255,136,0.3);
}

/* ── TABLAS ── */
[data-testid="stDataFrame"] {
    border: 1px solid #0f2a1a;
    border-radius: 4px;
}

/* ── SELECTBOX ── */
[data-testid="stSelectbox"] > div > div {
    background: #050d18 !important;
    border: 1px solid #0f2a1a !important;
    border-radius: 4px !important;
    color: #4b7a5e !important;
    font-family: 'Share Tech Mono', monospace !important;
}

/* ── DIVIDER ── */
hr { border-color: #0f2a1a !important; }

/* ── CUSTOM CARDS ── */
.alert-critical {
    background: linear-gradient(135deg, #1a0a0a, #0d0505);
    border: 1px solid #7f1d1d;
    border-left: 3px solid #ff2d55;
    border-radius: 4px;
    padding: 12px 16px;
    margin-bottom: 8px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    animation: pulse-red 2s infinite;
}
.alert-high {
    background: linear-gradient(135deg, #1a0f00, #0d0800);
    border: 1px solid #78350f;
    border-left: 3px solid #ffb800;
    border-radius: 4px;
    padding: 12px 16px;
    margin-bottom: 8px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
}
@keyframes pulse-red {
    0%, 100% { border-left-color: #ff2d55; }
    50%       { border-left-color: #ff6b81; box-shadow: 0 0 12px rgba(255,45,85,0.2); }
}

.severity-badge-critical {
    background: #ff2d55;
    color: #fff;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.6rem;
    padding: 2px 8px;
    border-radius: 2px;
    font-weight: bold;
}
.severity-badge-high {
    background: #ffb800;
    color: #000;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.6rem;
    padding: 2px 8px;
    border-radius: 2px;
    font-weight: bold;
}
.status-badge-active {
    background: #00ff88;
    color: #000;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.6rem;
    padding: 2px 8px;
    border-radius: 2px;
    font-weight: bold;
}
.status-badge-disconnected {
    background: #334155;
    color: #cbd5e1;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.6rem;
    padding: 2px 8px;
    border-radius: 2px;
    font-weight: bold;
}
.ip-tag {
    background: #0a1628;
    color: #00ff88;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    padding: 2px 10px;
    border: 1px solid #0f2a1a;
    border-radius: 2px;
}
.mitre-tag {
    background: #0d0d1a;
    color: #6366f1;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    padding: 2px 8px;
    border: 1px solid #1e1b4b;
    border-radius: 2px;
}
.source-tag {
    background: #0d1a14;
    color: #4b7a5e;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    padding: 2px 8px;
    border: 1px solid #0f2a1a;
    border-radius: 2px;
}
.terminal-text {
    font-family: 'Share Tech Mono', monospace;
    color: #4b7a5e;
    font-size: 0.72rem;
}
.status-live {
    display: inline-block;
    width: 8px; height: 8px;
    background: #00ff88;
    border-radius: 50%;
    margin-right: 6px;
    animation: blink 1.5s infinite;
    box-shadow: 0 0 6px #00ff88;
}
@keyframes blink {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.2; }
}
.section-label {
    font-family: 'Share Tech Mono', monospace;
    color: #1f4a2e;
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    margin-bottom: 10px;
    border-bottom: 1px solid #0f2a1a;
    padding-bottom: 6px;
}
</style>
"""

# Layout compartido para gráficos Plotly.
PLOTLY = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Share Tech Mono", color="#4b7a5e"),
    margin=dict(l=10, r=10, t=10, b=10),
)


def inject_theme() -> None:
    """Inyecta el CSS del tema SENTINEL. Llamar una vez por página."""
    st.markdown(CSS, unsafe_allow_html=True)


def sidebar_brand() -> None:
    """Bloque de marca que aparece arriba del sidebar en todas las páginas."""
    st.markdown("""
    <div style='padding:8px 0 20px'>
        <div style='font-family:Share Tech Mono,monospace;font-size:1rem;
                    color:#00ff88;text-shadow:0 0 10px rgba(0,255,136,0.4)'>
            SENTINEL//SIEM
        </div>
        <div style='color:#1f4a2e;font-size:0.65rem;font-family:Share Tech Mono,monospace;
                    margin-top:2px'>
            v3.0 · MULTI-AGENT DETECTION
        </div>
    </div>
    """, unsafe_allow_html=True)
