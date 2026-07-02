import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import requests
from datetime import datetime

import api_client
from theme import inject_theme, sidebar_brand, PLOTLY, EVENT_COLORS, SEVERITY_CLASS

RULE_SOURCE = {
    "SSH_BRUTE_FORCE": "ssh",
    "SUSPICIOUS_SUDO_COMMAND": "ssh",
    "LOGIN_AFTER_FAILURES": "ssh",
    "WEB_ATTACK_PAYLOAD": "web",
    "WEB_RECON_SCAN": "web",
    "FIM_CRITICAL_FILE_CHANGE": "fim",
}

st.set_page_config(
    page_title="SENTINEL — SIEM Dashboard",
    page_icon="🛡️",
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


# ── DATA LAYER — el dashboard es un cliente puro de la API, no toca SQLite ──
@st.cache_data(ttl=30)
def load_summary(source: str):
    return api_client.get_summary(source)


@st.cache_data(ttl=30)
def load_alerts():
    alerts = api_client.get_alerts()
    for a in alerts:
        a["source"] = RULE_SOURCE.get(a["rule_name"], "ssh")
    return alerts


def act_on_alert(alert_id: str, status: str):
    # Se usa como on_click de un st.button — Streamlit ya rehace el
    # render solo después de que el callback termina, así que basta con
    # invalidar el cache aquí (nada de st.rerun(), Streamlit lo desaconseja
    # dentro de un callback).
    api_client.update_alert_status(alert_id, status)
    load_alerts.clear()


@st.cache_data(ttl=30)
def load_top_ips(source: str):
    rows = api_client.get_top_ips(source)
    return pd.DataFrame(
        [(r["source_ip"], r["attempts"], r["targeted_users"]) for r in rows],
        columns=["IP", "Intentos", "Usuarios objetivo"],
    )


@st.cache_data(ttl=30)
def load_event_types(source: str):
    rows = api_client.get_event_types(source)
    return pd.DataFrame([(r["event_type"], r["n"]) for r in rows], columns=["Tipo", "Count"])


@st.cache_data(ttl=30)
def load_timeline(source: str):
    rows = api_client.get_timeline(source)
    return pd.DataFrame(
        [(r["hour"], r["event_type"], r["n"]) for r in rows],
        columns=["Hora", "Tipo", "Count"],
    )


# ── SIDEBAR ──
with st.sidebar:
    sidebar_brand()

    st.markdown('<div class="section-label">Filters</div>', unsafe_allow_html=True)
    severity_filter = st.selectbox(
        "Severidad", ["ALL", "CRITICAL", "HIGH", "MEDIUM"],
        label_visibility="collapsed"
    )
    source_filter = st.selectbox(
        "Log Source", ["ALL", "SSH", "WEB", "FIM"],
        label_visibility="collapsed"
    )
    show_closed = st.checkbox("Show closed alerts", value=False)

    st.markdown("---")
    st.markdown('<div class="section-label">System status</div>', unsafe_allow_html=True)

    summary_for_status = load_summary(source_filter)
    st.markdown(f"""
    <div style='background:var(--surface);border:1px solid var(--border);
                border-radius:10px;padding:12px 14px;margin-bottom:10px'>
        <div style='display:flex;align-items:center;margin-bottom:8px'>
            <span class='status-dot'></span>
            <span style='color:#F1F0EE;font-size:0.72rem;font-weight:600'>Monitoring active</span>
        </div>
        <div class='muted-text'>Engine: online</div>
        <div class='muted-text'>Rules loaded: 6</div>
        <div class='muted-text'>Agents: {summary_for_status['agents_active']}/{summary_for_status['agents_total']} active</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="section-label">Detection rules</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class='muted-text'>SSH_BRUTE_FORCE</div>
    <div class='muted-text'>SUSPICIOUS_SUDO_COMMAND</div>
    <div class='muted-text'>LOGIN_AFTER_FAILURES</div>
    <div class='muted-text'>WEB_ATTACK_PAYLOAD</div>
    <div class='muted-text'>WEB_RECON_SCAN</div>
    <div class='muted-text'>FIM_CRITICAL_FILE_CHANGE</div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown(
        "<a href='/builder/' target='_blank' "
        "style='color:#5B8CF0;text-decoration:none;font-size:0.78rem;font-weight:600'>"
        "Custom Builder ↗</a>",
        unsafe_allow_html=True
    )
    st.markdown(
        "<a href='https://github.com/EmilianoMAl/siem-detection-system' "
        "class='muted-text' style='text-decoration:none'>"
        "Source code ↗</a>",
        unsafe_allow_html=True
    )


# ── HEADER ──
summary = load_summary(source_filter)

st.markdown(f"""
<div style='display:flex;align-items:center;justify-content:space-between;
            margin-bottom:4px'>
    <div>
        <h1 style='margin:0'>Sentinel</h1>
        <p class='muted-text' style='margin:4px 0 0'>
            Real-time intrusion detection · Log analysis · Threat intelligence
        </p>
    </div>
    <div style='text-align:right'>
        <div style='display:flex;align-items:center;justify-content:flex-end'>
            <span class='status-dot'></span>
            <span style='color:#F1F0EE;font-size:0.72rem;font-weight:600'>Live</span>
        </div>
        <div class='muted-text' style='margin-top:2px'>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
</div>
""", unsafe_allow_html=True)
st.markdown("---")

# ── KPIs ──
k1, k2, k3, k4, k5, k6 = st.columns(6)
with k1: st.metric("Total events",   summary["total_events"])
with k2: st.metric("Unique IPs",     summary["unique_ips"])
with k3: st.metric("Agents active",  f"{summary['agents_active']}/{summary['agents_total']}")
with k4: st.metric("Sudo events",    summary["sudo"])
with k5: st.metric("Critical",       summary["critical"])
with k6: st.metric("High",           summary["high"])

st.markdown("---")

# ── ALERT FEED + TOP IPs ──
col_alerts, col_ips = st.columns([3, 2])

with col_alerts:
    st.markdown('<div class="section-label">Active threat feed</div>', unsafe_allow_html=True)
    alerts = load_alerts()
    filtered = alerts
    if not show_closed:
        filtered = [a for a in filtered if a.get("status", "OPEN") != "CLOSED"]
    if severity_filter != "ALL":
        filtered = [a for a in filtered if a["severity"] == severity_filter]
    if source_filter != "ALL":
        filtered = [a for a in filtered if a["source"] == source_filter.lower()]

    if not filtered:
        st.markdown("<div class='muted-text'>No alerts matching filter</div>", unsafe_allow_html=True)
    else:
        for alert in filtered[:8]:
            sev = alert["severity"]
            status = alert.get("status", "OPEN")
            sev_class = SEVERITY_CLASS.get(sev, "sev-low")
            ip_html = f"<span class='chip'>{alert['source_ip']}</span>" if alert["source_ip"] else ""
            mitre_html = (
                f"<span class='chip chip-accent'>{alert['mitre_technique']}</span>"
                if alert["mitre_technique"] else ""
            )
            source_html = f"<span class='chip'>{alert['source'].upper()}</span>"
            status_html = f"<span class='chip'>{status}</span>" if status != "OPEN" else ""

            card_col, action_col = st.columns([6, 1])
            with card_col:
                st.markdown(f"""
                <div class='alert-card'>
                    <div style='display:flex;align-items:center;gap:8px;margin-bottom:8px'>
                        <span class='sev-pill {sev_class}'>{sev}</span>
                        <span style='color:#F1F0EE;font-size:0.85rem;font-weight:600'>
                            {alert['rule_name']}
                        </span>
                        <span class='muted-text' style='margin-left:auto'>{alert['alert_id']}</span>
                    </div>
                    <div class='muted-text' style='margin-bottom:10px;line-height:1.5'>
                        {alert['description'][:120]}...
                    </div>
                    <div style='display:flex;gap:8px;flex-wrap:wrap'>
                        {source_html} {ip_html} {mitre_html} {status_html}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            with action_col:
                if status == "OPEN":
                    st.button("Ack", key=f"ack_{alert['alert_id']}",
                              on_click=act_on_alert, args=(alert["alert_id"], "ACKNOWLEDGED"))
                if status in ("OPEN", "ACKNOWLEDGED"):
                    st.button("Close", key=f"close_{alert['alert_id']}",
                              on_click=act_on_alert, args=(alert["alert_id"], "CLOSED"))

with col_ips:
    st.markdown('<div class="section-label">Top attacking IPs</div>', unsafe_allow_html=True)
    df_ips = load_top_ips(source_filter)
    if not df_ips.empty:
        fig_ips = go.Figure(go.Bar(
            x=df_ips["Intentos"],
            y=df_ips["IP"],
            orientation="h",
            marker=dict(color="#5B8CF0", line=dict(width=0)),
            text=df_ips["Intentos"],
            textposition="outside",
            textfont=dict(color="#ABA9A3", size=10),
        ))
        fig_ips.update_layout(
            **PLOTLY,
            height=320,
            xaxis=dict(showgrid=True, gridcolor="#2B2C31", color="#6E6D68", tickfont=dict(size=9)),
            yaxis=dict(showgrid=False, color="#ABA9A3", tickfont=dict(size=9)),
        )
        st.plotly_chart(fig_ips, use_container_width=True, key="chart_ips")
    else:
        st.markdown("<div class='muted-text'>No data</div>", unsafe_allow_html=True)

st.markdown("---")

# ── EVENT DISTRIBUTION + TIMELINE ──
col_donut, col_timeline = st.columns([2, 3])

with col_donut:
    st.markdown('<div class="section-label">Event distribution</div>', unsafe_allow_html=True)
    df_types = load_event_types(source_filter)
    if not df_types.empty:
        colors = [EVENT_COLORS.get(t, "#3A3B41") for t in df_types["Tipo"]]
        fig_donut = go.Figure(go.Pie(
            labels=df_types["Tipo"],
            values=df_types["Count"],
            hole=0.65,
            marker=dict(colors=colors, line=dict(color="#17181C", width=2)),
            textinfo="percent",
            textfont=dict(size=10, color="#17181C"),
        ))
        fig_donut.update_layout(
            **PLOTLY,
            height=280,
            showlegend=True,
            legend=dict(font=dict(size=9, color="#ABA9A3"), bgcolor="rgba(0,0,0,0)"),
            annotations=[dict(
                text=f"<b>{df_types['Count'].sum()}</b><br>events",
                x=0.5, y=0.5, font=dict(size=14, color="#F1F0EE"),
                showarrow=False
            )]
        )
        st.plotly_chart(fig_donut, use_container_width=True, key="chart_donut")
    else:
        st.markdown("<div class='muted-text'>No data</div>", unsafe_allow_html=True)

with col_timeline:
    st.markdown('<div class="section-label">Event timeline</div>', unsafe_allow_html=True)
    df_time = load_timeline(source_filter)
    if not df_time.empty:
        fig_time = go.Figure()
        for etype in df_time["Tipo"].unique():
            subset = df_time[df_time["Tipo"] == etype]
            fig_time.add_trace(go.Scatter(
                x=subset["Hora"],
                y=subset["Count"],
                name=etype,
                mode="lines+markers",
                line=dict(color=EVENT_COLORS.get(etype, "#3A3B41"), width=2),
                marker=dict(size=5),
                fill="tozeroy",
                fillcolor="rgba(0,0,0,0.08)",
            ))
        fig_time.update_layout(
            **PLOTLY,
            height=280,
            xaxis=dict(showgrid=True, gridcolor="#2B2C31", color="#6E6D68", tickfont=dict(size=9)),
            yaxis=dict(showgrid=True, gridcolor="#2B2C31", color="#6E6D68", tickfont=dict(size=9)),
            legend=dict(font=dict(size=9, color="#ABA9A3"), bgcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig_time, use_container_width=True, key="chart_timeline")
    else:
        st.markdown("<div class='muted-text'>No data</div>", unsafe_allow_html=True)

st.markdown("---")
st.markdown("""
<div class='muted-text' style='text-align:center'>
    Sentinel SIEM · Detection engine v3.0 · Multi-agent · MITRE ATT&CK framework ·
    Portfolio — Emiliano · Data engineering + cybersecurity
</div>
""", unsafe_allow_html=True)
