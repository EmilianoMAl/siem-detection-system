import sys
from pathlib import Path

_DASHBOARD_DIR = Path(__file__).resolve().parent.parent
if str(_DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(_DASHBOARD_DIR))

import streamlit as st
import requests

import api_client
from theme import inject_theme, sidebar_brand, workspace_selector

st.set_page_config(
    page_title="SENTINEL — MITRE ATT&CK",
    page_icon="🎯",
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
    st.markdown('<div class="section-label">Navigation</div>', unsafe_allow_html=True)
    st.markdown(
        "<div class='muted-text'>Home — arriba en el sidebar</div>"
        "<div class='muted-text'>Agents</div>"
        "<div class='muted-text'>MITRE — esta página</div>"
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
<h1 style='margin:0'>MITRE ATT&CK Coverage</h1>
<p class='muted-text' style='margin:4px 0 0'>
    Técnicas detectadas por SENTINEL, organizadas por táctica del framework
</p>
""", unsafe_allow_html=True)
st.markdown("---")

techniques = api_client.get_mitre_coverage(environment)

detected = [t for t in techniques if t["count"] > 0]
total_hits = sum(t["count"] for t in techniques)

k1, k2, k3 = st.columns(3)
with k1: st.metric("Techniques with hits", f"{len(detected)}/{len(techniques)}")
with k2: st.metric("Total alerts mapped", total_hits)
with k3: st.metric("Tactics covered", len({t['tactic'] for t in detected}) if detected else 0)

st.markdown("---")

by_tactic: dict[str, list[dict]] = {}
for t in techniques:
    by_tactic.setdefault(t["tactic"], []).append(t)

for tactic, items in by_tactic.items():
    st.markdown(f"<div class='mitre-tactic-label'>{tactic}</div>", unsafe_allow_html=True)

    # Streamlit corre esto por un parser de Markdown antes de aceptar el
    # HTML crudo -- un string multilínea indentado (4+ espacios tras una
    # línea en blanco) se interpreta como bloque de código, no como HTML.
    # Por eso todo va en una sola línea, sin indentación ni saltos.
    cells_html = "".join(
        f"<div class='mitre-cell mitre-cell-hit'>"
        f"<span class='id'>{item['technique_id']}</span>"
        f"<span class='name'>{item['technique_name']}</span>"
        f"<span class='count'>{item['count']} alert(s)</span></div>"
        if item["count"] > 0 else
        f"<div class='mitre-cell'>"
        f"<span class='id'>{item['technique_id']}</span>"
        f"<span class='name'>{item['technique_name']}</span></div>"
        for item in items
    )

    st.markdown(cells_html, unsafe_allow_html=True)

st.markdown("---")
st.markdown("""
<div class='muted-text' style='text-align:center'>
    Cobertura curada de ~40 técnicas de MITRE ATT&CK Enterprise — no es el
    dataset STIX completo, pero incluye exactas todas las técnicas que
    producen las reglas de detección de SENTINEL.
</div>
""", unsafe_allow_html=True)
