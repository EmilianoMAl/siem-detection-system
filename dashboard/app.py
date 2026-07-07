import json
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import requests
from datetime import datetime, timedelta, timezone, time as dtime

import api_client
from theme import inject_theme, sidebar_brand, workspace_selector, agent_selector, LOCAL_TZ, PLOTLY, EVENT_COLORS, SEVERITY_CLASS

RULE_SOURCE = {
    "SSH_BRUTE_FORCE": "ssh",
    "SUSPICIOUS_SUDO_COMMAND": "ssh",
    "LOGIN_AFTER_FAILURES": "ssh",
    "WEB_ATTACK_PAYLOAD": "web",
    "WEB_RECON_SCAN": "web",
    "FIM_CRITICAL_FILE_CHANGE": "fim",
    "SONICWALL_REPEATED_DENIALS": "sonicwall",
}

# Mapeos usados solo para la vista "estilo Wazuh" (formato campo: valor
# que el usuario ya conoce de su trabajo) -- aproximaciones razonables,
# no hay un mapeo 1:1 oficial entre las reglas de SENTINEL y Wazuh.
DECODER_NAME = {"ssh": "sshd", "web": "web-accesslog", "fim": "syscheck", "sonicwall": "sonicwall"}
SEVERITY_TO_LEVEL = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 7, "LOW": 3}


def format_wazuh_style(alert: dict) -> str:
    """
    Arma un bloque "campo: valor" parecido al que produce Wazuh para sus
    alertas (rule.level, data.srcip, full_log, etc.) -- full_log usa la
    primera línea de evidencia cruda que ya guarda la alerta, que para
    alertas de SonicWall es literalmente la línea de syslog original.
    """
    source = alert.get("source", "ssh")
    full_log = ""
    if alert.get("evidence"):
        try:
            lines = json.loads(alert["evidence"])
            full_log = lines[0] if lines else ""
        except (json.JSONDecodeError, TypeError):
            full_log = str(alert["evidence"])

    fields = [
        ("input.type", "log"),
        ("agent.name", alert.get("hostname") or "unknown"),
        ("manager.name", "sentinel-siem"),
        ("data.srcip", alert.get("source_ip") or "-"),
        ("data.action", alert["description"]),
        ("rule.level", SEVERITY_TO_LEVEL.get(alert["severity"], 5)),
        ("rule.description", alert["description"]),
        ("rule.groups", f"syslog, {source}"),
        ("rule.id", alert["alert_id"]),
        ("location", alert.get("hostname") or "-"),
        ("decoder.name", DECODER_NAME.get(source, source)),
        ("id", alert["alert_id"]),
        ("full_log", full_log),
    ]
    return "\n".join(f"{key}: {value}" for key, value in fields)

TIME_RANGE_LABELS = {
    "Todo el tiempo": "all",
    "Última hora": "1h",
    "Últimas 24 horas": "24h",
    "Últimos 7 días": "7d",
    "Últimos 30 días": "30d",
    "Último año": "365d",
    "Personalizado": "custom",
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
@st.cache_data(ttl=10)
def load_summary(source: str, time_range: str, start: str | None = None, end: str | None = None, environment: str = "ALL", agent_id: str = "ALL"):
    return api_client.get_summary(source, time_range, start, end, environment, agent_id)


@st.cache_data(ttl=10)
def load_alerts(time_range: str, start: str | None = None, end: str | None = None, environment: str = "ALL", hostname: str | None = None):
    alerts = api_client.get_alerts(time_range=time_range, start=start, end=end, environment=environment, hostname=hostname)
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


@st.cache_data(ttl=10)
def load_top_ips(source: str, time_range: str, start: str | None = None, end: str | None = None, environment: str = "ALL", agent_id: str = "ALL"):
    rows = api_client.get_top_ips(source, time_range, start, end, environment, agent_id)
    return pd.DataFrame(
        [(r["source_ip"], r["attempts"], r["targeted_users"]) for r in rows],
        columns=["IP", "Intentos", "Usuarios objetivo"],
    )


@st.cache_data(ttl=10)
def load_event_types(source: str, time_range: str, start: str | None = None, end: str | None = None, environment: str = "ALL", agent_id: str = "ALL"):
    rows = api_client.get_event_types(source, time_range, start, end, environment, agent_id)
    return pd.DataFrame([(r["event_type"], r["n"]) for r in rows], columns=["Tipo", "Count"])


@st.cache_data(ttl=10)
def load_timeline(source: str, time_range: str, start: str | None = None, end: str | None = None, environment: str = "ALL", agent_id: str = "ALL"):
    rows = api_client.get_timeline(source, time_range, start, end, environment, agent_id)
    return pd.DataFrame(
        [(r["hour"], r["event_type"], r["n"]) for r in rows],
        columns=["Hora", "Tipo", "Count"],
    )


# ── SIDEBAR ──
with st.sidebar:
    sidebar_brand()

    if st.button("🔄 Refrescar ahora", use_container_width=True):
        load_summary.clear()
        load_alerts.clear()
        load_top_ips.clear()
        load_event_types.clear()
        load_timeline.clear()

    environment = workspace_selector()

    st.markdown("---")
    st.markdown('<div class="section-label">Filters</div>', unsafe_allow_html=True)
    agent_id, agent_hostname = agent_selector(api_client.get_agents(environment))
    severity_filter = st.selectbox(
        "Severidad", ["ALL", "CRITICAL", "HIGH", "MEDIUM"],
        label_visibility="collapsed"
    )
    source_filter = st.selectbox(
        "Log Source", ["ALL", "SSH", "WEB", "FIM", "SONICWALL", "SYSLOG", "WAZUH"],
        label_visibility="collapsed"
    )
    time_range_label = st.selectbox(
        "Time range", list(TIME_RANGE_LABELS.keys()),
        label_visibility="collapsed"
    )
    time_range = TIME_RANGE_LABELS[time_range_label]

    start_str = end_str = None
    if time_range == "custom":
        today = datetime.now(LOCAL_TZ).date()
        date_range = st.date_input(
            "Rango de fechas", value=(today - timedelta(days=7), today),
        )
        if isinstance(date_range, tuple) and len(date_range) == 2:
            range_start, range_end = date_range
        else:
            # Streamlit devuelve una tupla de 1 elemento mientras el
            # usuario no elige el segundo día del rango todavía.
            only_day = date_range[0] if isinstance(date_range, tuple) else date_range
            range_start = range_end = only_day

        col_from, col_to = st.columns(2)
        with col_from:
            time_from = st.time_input("Desde", value=dtime(0, 0))
        with col_to:
            time_to = st.time_input("Hasta", value=dtime(23, 59))

        # El usuario elige en hora CDMX -- se convierte a UTC antes de
        # comparar contra created_at (que siempre está en UTC en la BD).
        start_str = datetime.combine(range_start, time_from, tzinfo=LOCAL_TZ).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        end_str = datetime.combine(range_end, time_to, tzinfo=LOCAL_TZ).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        st.caption("Horario CDMX (se convierte a UTC internamente para filtrar).")

    show_closed = st.checkbox("Show closed alerts", value=False)

    st.markdown("---")
    st.markdown('<div class="section-label">System status</div>', unsafe_allow_html=True)

    summary_for_status = load_summary(source_filter, time_range, start_str, end_str, environment, agent_id)
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
summary = load_summary(source_filter, time_range, start_str, end_str, environment, agent_id)

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
        <div class='muted-text' style='margin-top:2px'>{datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S')} CDMX</div>
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
    alerts = load_alerts(time_range, start_str, end_str, environment, agent_hostname)
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
                with st.expander("Ver como Wazuh"):
                    st.code(format_wazuh_style(alert), language=None)
            with action_col:
                if status == "OPEN":
                    st.button("Ack", key=f"ack_{alert['alert_id']}",
                              on_click=act_on_alert, args=(alert["alert_id"], "ACKNOWLEDGED"))
                if status in ("OPEN", "ACKNOWLEDGED"):
                    st.button("Close", key=f"close_{alert['alert_id']}",
                              on_click=act_on_alert, args=(alert["alert_id"], "CLOSED"))

with col_ips:
    st.markdown('<div class="section-label">Top attacking IPs</div>', unsafe_allow_html=True)
    df_ips = load_top_ips(source_filter, time_range, start_str, end_str, environment, agent_id)
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
    df_types = load_event_types(source_filter, time_range, start_str, end_str, environment, agent_id)
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
    df_time = load_timeline(source_filter, time_range, start_str, end_str, environment, agent_id)
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
