import sys
from pathlib import Path

_DASHBOARD_DIR = Path(__file__).resolve().parent.parent
if str(_DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(_DASHBOARD_DIR))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import requests

import api_client
from theme import inject_theme, sidebar_brand, workspace_selector

st.set_page_config(
    page_title="SENTINEL — Geomap",
    page_icon="🌍",
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
        "<div class='muted-text'>MITRE</div>"
        "<div class='muted-text'>Geomap — esta página</div>",
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
<h1 style='margin:0'>Attacker Geomap</h1>
<p class='muted-text' style='margin:4px 0 0'>
    Origen geográfico de las IPs públicas con actividad — geolocalizado vía ip-api.com
</p>
""", unsafe_allow_html=True)
st.markdown("---")

with st.spinner("Geolocalizando IPs nuevas…"):
    geo = api_client.get_geo_attackers(environment)

if not geo:
    st.markdown(
        "<div class='muted-text'>Sin IPs públicas geolocalizables todavía.</div>",
        unsafe_allow_html=True
    )
    st.stop()

df = pd.DataFrame(geo)

k1, k2, k3 = st.columns(3)
with k1: st.metric("IPs geolocalizadas", len(df))
with k2: st.metric("Países distintos", df["country"].nunique())
with k3: st.metric("Total intentos", int(df["attempts"].sum()))

st.markdown("---")

fig = go.Figure(go.Scattergeo(
    lon=df["lon"],
    lat=df["lat"],
    text=df.apply(lambda r: f"{r['source_ip']} · {r['city']}, {r['country']} · {r['attempts']} intentos", axis=1),
    mode="markers",
    marker=dict(
        size=(df["attempts"] / df["attempts"].max() * 26 + 6),
        color=df["attempts"],
        colorscale=[[0, "#2B2C31"], [0.5, "#5B8CF0"], [1, "#F0685E"]],
        line=dict(width=1, color="#17181C"),
        sizemode="diameter",
    ),
))
fig.update_geos(
    projection_type="natural earth",
    showland=True, landcolor="#1D1E23",
    showocean=True, oceancolor="#121317",
    showcountries=True, countrycolor="#2B2C31",
    showcoastlines=False,
    bgcolor="rgba(0,0,0,0)",
)
fig.update_layout(
    paper_bgcolor="rgba(0,0,0,0)",
    height=560,
    margin=dict(l=0, r=0, t=0, b=0),
    font=dict(color="#ABA9A3"),
)
st.plotly_chart(fig, use_container_width=True)

st.markdown("---")
st.markdown('<div class="section-label">Detail</div>', unsafe_allow_html=True)
table = df[["source_ip", "country", "city", "attempts"]].sort_values("attempts", ascending=False)
table.columns = ["IP", "Country", "City", "Attempts"]
st.dataframe(table, use_container_width=True, hide_index=True)
