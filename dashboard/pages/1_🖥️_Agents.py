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
from theme import inject_theme, sidebar_brand, workspace_selector, agent_selector

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
    environment = workspace_selector()
    st.markdown("---")
    st.markdown('<div class="section-label">Filters</div>', unsafe_allow_html=True)
    agent_id, _agent_hostname = agent_selector(api_client.get_agents(environment))
    st.markdown("---")
    st.markdown('<div class="section-label">Navigation</div>', unsafe_allow_html=True)
    st.markdown(
        "<div class='muted-text'>Home — arriba en el sidebar</div>"
        "<div class='muted-text'>Agents — esta página</div>"
        "<div class='muted-text'>MITRE</div>"
        "<div class='muted-text'>Geomap</div>",
        unsafe_allow_html=True
    )
    st.markdown("---")
    st.markdown(
        "<a href='/builder/' target='_blank' "
        "style='color:#5B8CF0;text-decoration:none;font-size:0.78rem;font-weight:600'>"
        "Custom Builder ↗</a>",
        unsafe_allow_html=True
    )

st.markdown("""
<h1 style='margin:0'>Agents</h1>
<p class='muted-text' style='margin:4px 0 0'>
    Flota de hosts monitoreados · Estado en tiempo real
</p>
""", unsafe_allow_html=True)
st.markdown("---")

agents = api_client.get_agents(environment)
if agent_id != "ALL":
    agents = [a for a in agents if a["agent_id"] == agent_id]

k1, k2, k3 = st.columns(3)
active = sum(1 for a in agents if a["status"] == "ACTIVE")
with k1: st.metric("Total agents", len(agents))
with k2: st.metric("Active", active)
with k3: st.metric("Disconnected", len(agents) - active)

st.markdown("---")
st.markdown('<div class="section-label">Registered agents</div>', unsafe_allow_html=True)

if not agents:
    st.markdown("<div class='muted-text'>No agents registered</div>", unsafe_allow_html=True)
else:
    for agent in agents:
        status = agent["status"]
        badge_class = "status-badge-active" if status == "ACTIVE" else "status-badge-disconnected"
        sources_html = "".join(
            f"<span class='chip'>{s.upper()}</span>" for s in agent["log_sources"]
        )
        st.markdown(f"""
        <div class='alert-card'>
            <div style='display:flex;align-items:center;gap:8px;margin-bottom:8px'>
                <span class='{badge_class}'>{status}</span>
                <span style='color:#F1F0EE;font-size:0.85rem;font-weight:600'>
                    {agent['hostname']}
                </span>
                <span class='muted-text' style='margin-left:auto'>{agent['agent_id']}</span>
            </div>
            <div class='muted-text' style='margin-bottom:8px'>
                IP: {agent['ip_address']} &nbsp;·&nbsp; OS: {agent['os']} &nbsp;·&nbsp;
                Last seen: {agent['last_seen'] or 'never'}
            </div>
            <div style='display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px'>
                {sources_html}
            </div>
            <div class='muted-text'>
                events={agent['event_count']} · alerts={agent['alert_count']}
            </div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")
st.markdown('<div class="section-label">Raw table</div>', unsafe_allow_html=True)
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
