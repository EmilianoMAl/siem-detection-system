import sys
import json
from pathlib import Path

_DASHBOARD_DIR = Path(__file__).resolve().parent.parent
if str(_DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(_DASHBOARD_DIR))

import streamlit as st
import requests

import api_client
from theme import inject_theme, sidebar_brand, workspace_selector, agent_selector

st.set_page_config(
    page_title="SENTINEL — Events",
    page_icon="📜",
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
    log_source = st.selectbox(
        "Log Source", ["ALL", "SSH", "WEB", "FIM", "SONICWALL", "SYSLOG"],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.markdown('<div class="section-label">Navigation</div>', unsafe_allow_html=True)
    st.markdown(
        "<div class='muted-text'>Home — arriba en el sidebar</div>"
        "<div class='muted-text'>Agents</div>"
        "<div class='muted-text'>MITRE</div>"
        "<div class='muted-text'>Geomap</div>"
        "<div class='muted-text'>Events — esta página</div>",
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
<h1 style='margin:0'>Events</h1>
<p class='muted-text' style='margin:4px 0 0'>
    Eventos crudos — todo lo que llega, tenga o no una alerta asociada
</p>
""", unsafe_allow_html=True)
st.markdown("---")

events = api_client.get_events(environment=environment, agent_id=agent_id, log_source=log_source, limit=50)

k1, k2, k3 = st.columns(3)
with k1: st.metric("Events shown", len(events))
with k2: st.metric("Distinct agents", len({e["agent_id"] for e in events if e["agent_id"]}))
with k3: st.metric("Distinct types", len({e["event_type"] for e in events}))

st.markdown("---")
st.markdown('<div class="section-label">Recent events</div>', unsafe_allow_html=True)

if not events:
    st.markdown("<div class='muted-text'>No hay eventos con estos filtros</div>", unsafe_allow_html=True)
else:
    for event in events:
        source_html = f"<span class='chip'>{(event['log_source'] or '?').upper()}</span>"
        ip_html = f"<span class='chip'>{event['source_ip']}</span>" if event["source_ip"] else ""
        agent_html = f"<span class='chip chip-accent'>{event['hostname'] or event['agent_id'] or '?'}</span>"

        st.markdown(f"""
        <div class='alert-card'>
            <div style='display:flex;align-items:center;gap:8px;margin-bottom:8px'>
                <span style='color:#F1F0EE;font-size:0.85rem;font-weight:600'>
                    {event['event_type']}
                </span>
                <span class='muted-text' style='margin-left:auto'>{event['timestamp'] or event['created_at']}</span>
            </div>
            <div style='display:flex;gap:8px;flex-wrap:wrap'>
                {source_html} {agent_html} {ip_html}
            </div>
        </div>
        """, unsafe_allow_html=True)

        with st.expander("Ver detalle"):
            try:
                metadata = json.loads(event["metadata"]) if event["metadata"] else {}
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            detail_lines = [
                f"timestamp: {event['timestamp']}",
                f"created_at: {event['created_at']}",
                f"hostname: {event['hostname']}",
                f"agent_id: {event['agent_id']}",
                f"log_source: {event['log_source']}",
                f"event_type: {event['event_type']}",
                f"username: {event['username']}",
                f"source_ip: {event['source_ip']}",
                f"source_port: {event['source_port']}",
            ]
            for key, value in metadata.items():
                detail_lines.append(f"metadata.{key}: {value}")
            detail_lines.append(f"raw_line: {event['raw_line']}")

            st.code("\n".join(detail_lines), language=None)

st.markdown("---")
st.markdown("""
<div class='muted-text' style='text-align:center'>
    Se muestran los últimos 50 eventos según los filtros elegidos.
</div>
""", unsafe_allow_html=True)
