import sys
from pathlib import Path

# Asegura que "theme"/"api_client" (dashboard/) sean importables sin depender
# de cómo Streamlit resuelva sys.path para páginas en subcarpetas.
_DASHBOARD_DIR = Path(__file__).resolve().parent.parent
if str(_DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(_DASHBOARD_DIR))

import streamlit as st
import pandas as pd
import requests

import api_client
from theme import inject_theme, sidebar_brand

st.set_page_config(
    page_title="SENTINEL — Agents",
    page_icon="🖥️",
    layout="wide",
    initial_sidebar_state="expanded"
)
inject_theme()

try:
    api_client.get_health()
except requests.exceptions.RequestException:
    st.error(
        f"No se puede conectar a la API de SENTINEL en `{api_client.API_URL}`. "
        f"¿Está corriendo `uvicorn api.main:app --port 8000`?"
    )
    st.stop()

with st.sidebar:
    sidebar_brand()
    st.markdown('<div class="section-label">Navigation</div>', unsafe_allow_html=True)
    st.markdown(
        "<div class='terminal-text'>🏠 Home — sidebar arriba</div>"
        "<div class='terminal-text'>🖥️ Agents — esta página</div>",
        unsafe_allow_html=True
    )

st.markdown("""
<h1 style='margin:0'>🖥️ AGENTS</h1>
<p style='color:#1f4a2e;font-family:Share Tech Mono,monospace;font-size:0.7rem;margin:4px 0 0'>
    FLOTA DE HOSTS MONITOREADOS · ESTADO EN TIEMPO REAL
</p>
""", unsafe_allow_html=True)
st.markdown("---")

agents = api_client.get_agents()

k1, k2, k3 = st.columns(3)
active = sum(1 for a in agents if a["status"] == "ACTIVE")
with k1: st.metric("TOTAL AGENTS", len(agents))
with k2: st.metric("ACTIVE", active)
with k3: st.metric("DISCONNECTED", len(agents) - active)

st.markdown("---")
st.markdown('<div class="section-label">Registered Agents</div>', unsafe_allow_html=True)

if not agents:
    st.markdown("<div class='terminal-text'>// NO AGENTS REGISTERED</div>", unsafe_allow_html=True)
else:
    for agent in agents:
        status = agent["status"]
        badge_class = "status-badge-active" if status == "ACTIVE" else "status-badge-disconnected"
        sources_html = "".join(
            f"<span class='source-tag'>{s.upper()}</span>" for s in agent["log_sources"]
        )
        st.markdown(f"""
        <div class='alert-high' style='animation:none'>
            <div style='display:flex;align-items:center;gap:8px;margin-bottom:6px'>
                <span class='{badge_class}'>{status}</span>
                <span style='color:#e2e8f0;font-size:0.85rem;
                             font-family:Rajdhani,sans-serif;font-weight:600'>
                    {agent['hostname']}
                </span>
                <span style='color:#334155;font-size:0.6rem;margin-left:auto'>
                    {agent['agent_id']}
                </span>
            </div>
            <div style='color:#64748b;font-size:0.72rem;margin-bottom:6px;
                        font-family:Rajdhani,sans-serif'>
                IP: {agent['ip_address']} &nbsp;·&nbsp; OS: {agent['os']} &nbsp;·&nbsp;
                Last seen: {agent['last_seen'] or 'never'}
            </div>
            <div style='display:flex;gap:8px;flex-wrap:wrap;margin-bottom:6px'>
                {sources_html}
            </div>
            <div class='terminal-text'>
                events={agent['event_count']} · alerts={agent['alert_count']}
            </div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")
st.markdown('<div class="section-label">📋 Raw Table</div>', unsafe_allow_html=True)
if agents:
    df = pd.DataFrame([{
        "Agent ID": a["agent_id"],
        "Hostname": a["hostname"],
        "IP": a["ip_address"],
        "OS": a["os"],
        "Sources": ", ".join(a["log_sources"]),
        "Status": a["status"],
        "Events": a["event_count"],
        "Alerts": a["alert_count"],
        "Last Seen": a["last_seen"],
    } for a in agents])
    st.dataframe(df, use_container_width=True, hide_index=True)
