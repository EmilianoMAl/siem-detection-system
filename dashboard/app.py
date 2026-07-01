import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import sqlite3
from datetime import datetime

import sys
sys.path.insert(0, ".")

from engine.agents import SIMULATED_AGENTS
from engine.log_generator import run_generator
from engine.pipeline import ingest_agent_logs
from engine.detectors.rules import DetectionEngine
from engine.storage import (
    initialize_db, insert_events, insert_alerts, register_agents,
    touch_agent, DB_PATH,
)
from theme import inject_theme, sidebar_brand, PLOTLY

RULE_SOURCE = {
    "SSH_BRUTE_FORCE": "ssh",
    "SUSPICIOUS_SUDO_COMMAND": "ssh",
    "LOGIN_AFTER_FAILURES": "ssh",
    "WEB_ATTACK_PAYLOAD": "web",
    "WEB_RECON_SCAN": "web",
    "FIM_CRITICAL_FILE_CHANGE": "fim",
}


def bootstrap_data():
    """
    Si la base de datos no existe o está vacía, genera datos de demo
    para toda la flota de agentes (ssh/web/fim según cada agente) y
    corre el motor de detección. Corre una sola vez al iniciar el dashboard.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    initialize_db()
    register_agents(SIMULATED_AGENTS)

    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()

    if count == 0:
        with st.spinner("🔄 Initializing threat database across all agents..."):
            generated = run_generator(
                agents=SIMULATED_AGENTS,
                duration_seconds=45,
                events_per_second=4.0,
                attack_probability=0.25,
                realtime=False,
            )
            all_events = []
            for agent, source, filepath in generated:
                events, _ = ingest_agent_logs(agent, source, filepath)
                all_events.extend(events)
                touch_agent(agent.agent_id)

            engine = DetectionEngine()
            alerts = engine.run_all_rules(all_events)

            insert_events(all_events)
            insert_alerts(alerts)


bootstrap_data()

st.set_page_config(
    page_title="SENTINEL — SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_theme()


# ── DATA LAYER ──
@st.cache_resource
def get_conn():
    return sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30.0)


def _source_filter_clause(source: str) -> str:
    return "" if source == "ALL" else f"AND log_source = '{source.lower()}'"


@st.cache_data(ttl=30)
def load_summary(source: str):
    conn = get_conn()
    clause = _source_filter_clause(source)
    row = conn.execute(f"""
        SELECT
            COUNT(*)                                          as total_events,
            COUNT(DISTINCT source_ip)                         as unique_ips,
            SUM(CASE WHEN event_type='failed_password' OR
                          event_type='invalid_user' THEN 1 ELSE 0 END) as failed_logins,
            SUM(CASE WHEN event_type='accepted_password' THEN 1 ELSE 0 END) as ok_logins,
            SUM(CASE WHEN event_type='sudo_command'      THEN 1 ELSE 0 END) as sudo_events
        FROM events WHERE 1=1 {clause}
    """).fetchone()
    alert_row = conn.execute("""
        SELECT COUNT(*) as total,
            SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as crit,
            SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END) as high
        FROM alerts
    """).fetchone()
    agent_row = conn.execute("""
        SELECT COUNT(*) as total,
            SUM(CASE WHEN (strftime('%s','now') - strftime('%s', last_seen)) < 600
                THEN 1 ELSE 0 END) as active
        FROM agents
    """).fetchone()
    return {
        "total_events": row[0] or 0,
        "unique_ips":   row[1] or 0,
        "failed":       row[2] or 0,
        "ok_logins":    row[3] or 0,
        "sudo":         row[4] or 0,
        "total_alerts": alert_row[0] or 0,
        "critical":     alert_row[1] or 0,
        "high":         alert_row[2] or 0,
        "agents_total":  agent_row[0] or 0,
        "agents_active": agent_row[1] or 0,
    }


@st.cache_data(ttl=30)
def load_alerts():
    conn = get_conn()
    rows = conn.execute("""
        SELECT alert_id, rule_name, severity, description,
               source_ip, username, mitre_technique,
               recommendation, detected_at, evidence
        FROM alerts ORDER BY
            CASE severity WHEN 'CRITICAL' THEN 0
                          WHEN 'HIGH'     THEN 1 ELSE 2 END,
            detected_at DESC
    """).fetchall()
    cols = ["alert_id", "rule_name", "severity", "description",
            "source_ip", "username", "mitre_technique",
            "recommendation", "detected_at", "evidence"]
    alerts = [dict(zip(cols, r)) for r in rows]
    for a in alerts:
        a["source"] = RULE_SOURCE.get(a["rule_name"], "ssh")
    return alerts


@st.cache_data(ttl=30)
def load_top_ips(source: str):
    conn = get_conn()
    clause = _source_filter_clause(source)
    event_types = "('failed_password','invalid_user')" if source != "web" else "('http_request')"
    rows = conn.execute(f"""
        SELECT source_ip, COUNT(*) as attempts,
               COUNT(DISTINCT username) as users
        FROM events
        WHERE event_type IN {event_types}
          AND source_ip IS NOT NULL {clause}
        GROUP BY source_ip ORDER BY attempts DESC LIMIT 8
    """).fetchall()
    return pd.DataFrame(rows, columns=["IP", "Intentos", "Usuarios objetivo"])


@st.cache_data(ttl=30)
def load_event_types(source: str):
    conn = get_conn()
    clause = _source_filter_clause(source)
    rows = conn.execute(f"""
        SELECT event_type, COUNT(*) as n FROM events
        WHERE 1=1 {clause}
        GROUP BY event_type
    """).fetchall()
    return pd.DataFrame(rows, columns=["Tipo", "Count"])


@st.cache_data(ttl=30)
def load_timeline(source: str):
    conn = get_conn()
    clause = _source_filter_clause(source)
    rows = conn.execute(f"""
        SELECT substr(timestamp, 1, 8) as hour,
               event_type, COUNT(*) as n
        FROM events WHERE 1=1 {clause}
        GROUP BY hour, event_type
        ORDER BY hour
    """).fetchall()
    return pd.DataFrame(rows, columns=["Hora", "Tipo", "Count"])


# ── SIDEBAR ──
with st.sidebar:
    sidebar_brand()

    st.markdown('<div class="section-label">Filters</div>',
                unsafe_allow_html=True)
    severity_filter = st.selectbox(
        "Severidad", ["ALL", "CRITICAL", "HIGH", "MEDIUM"],
        label_visibility="collapsed"
    )
    source_filter = st.selectbox(
        "Log Source", ["ALL", "SSH", "WEB", "FIM"],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown('<div class="section-label">System Status</div>',
                unsafe_allow_html=True)

    summary_for_status = load_summary(source_filter)
    st.markdown(f"""
    <div style='background:#050d18;border:1px solid #0f2a1a;border-radius:4px;
                padding:10px 14px;margin-bottom:10px'>
        <div style='display:flex;align-items:center;margin-bottom:6px'>
            <span class='status-live'></span>
            <span style='color:#00ff88;font-family:Share Tech Mono,monospace;
                         font-size:0.65rem'>MONITORING ACTIVE</span>
        </div>
        <div class='terminal-text'>ENGINE: ONLINE</div>
        <div class='terminal-text'>RULES LOADED: 6</div>
        <div class='terminal-text'>AGENTS: {summary_for_status['agents_active']}/{summary_for_status['agents_total']} ACTIVE</div>
        <div class='terminal-text'>DB: siem.db</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="section-label">Detection Rules</div>',
                unsafe_allow_html=True)
    st.markdown("""
    <div class='terminal-text'>✓ SSH_BRUTE_FORCE</div>
    <div class='terminal-text'>✓ SUSPICIOUS_SUDO</div>
    <div class='terminal-text'>✓ LOGIN_AFTER_FAIL</div>
    <div class='terminal-text'>✓ WEB_ATTACK_PAYLOAD</div>
    <div class='terminal-text'>✓ WEB_RECON_SCAN</div>
    <div class='terminal-text'>✓ FIM_CRITICAL_CHANGE</div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown(
        "<a href='https://github.com/EmilianoMAl/siem-detection-system' "
        "style='color:#1f4a2e;font-family:Share Tech Mono,monospace;"
        "font-size:0.65rem;text-decoration:none'>"
        "↗ SOURCE CODE</a>",
        unsafe_allow_html=True
    )


# ── HEADER ──
summary = load_summary(source_filter)

st.markdown(f"""
<div style='display:flex;align-items:center;justify-content:space-between;
            margin-bottom:4px'>
    <div>
        <h1 style='margin:0'>🛡️ SENTINEL // SIEM</h1>
        <p style='color:#1f4a2e;font-family:Share Tech Mono,monospace;
                  font-size:0.7rem;margin:4px 0 0'>
            REAL-TIME INTRUSION DETECTION · LOG ANALYSIS · THREAT INTELLIGENCE
        </p>
    </div>
    <div style='text-align:right'>
        <div style='display:flex;align-items:center;justify-content:flex-end'>
            <span class='status-live'></span>
            <span style='color:#00ff88;font-family:Share Tech Mono,monospace;
                         font-size:0.65rem'>LIVE</span>
        </div>
        <div style='color:#1f4a2e;font-family:Share Tech Mono,monospace;
                    font-size:0.6rem'>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
    </div>
</div>
""", unsafe_allow_html=True)
st.markdown("---")

# ── KPIs ──
k1, k2, k3, k4, k5, k6 = st.columns(6)
with k1: st.metric("TOTAL EVENTS",   summary["total_events"])
with k2: st.metric("UNIQUE IPs",     summary["unique_ips"])
with k3: st.metric("AGENTS ACTIVE",  f"{summary['agents_active']}/{summary['agents_total']}")
with k4: st.metric("SUDO EVENTS",    summary["sudo"])
with k5: st.metric("🔴 CRITICAL",    summary["critical"])
with k6: st.metric("🟡 HIGH",        summary["high"])

st.markdown("---")

# ── ALERT FEED + TOP IPs ──
col_alerts, col_ips = st.columns([3, 2])

with col_alerts:
    st.markdown('<div class="section-label">⚡ Active Threat Feed</div>',
                unsafe_allow_html=True)
    alerts = load_alerts()
    filtered = alerts
    if severity_filter != "ALL":
        filtered = [a for a in filtered if a["severity"] == severity_filter]
    if source_filter != "ALL":
        filtered = [a for a in filtered if a["source"] == source_filter.lower()]

    if not filtered:
        st.markdown(
            "<div class='terminal-text'>// NO ALERTS MATCHING FILTER</div>",
            unsafe_allow_html=True
        )
    else:
        for alert in filtered[:8]:
            sev = alert["severity"]
            css = "alert-critical" if sev == "CRITICAL" else "alert-high"
            badge = (
                f"<span class='severity-badge-critical'>{sev}</span>"
                if sev == "CRITICAL"
                else f"<span class='severity-badge-high'>{sev}</span>"
            )
            ip_html = (
                f"<span class='ip-tag'>{alert['source_ip']}</span>"
                if alert["source_ip"] else ""
            )
            mitre_html = (
                f"<span class='mitre-tag'>{alert['mitre_technique']}</span>"
                if alert["mitre_technique"] else ""
            )
            source_html = f"<span class='source-tag'>{alert['source'].upper()}</span>"
            st.markdown(f"""
            <div class='{css}'>
                <div style='display:flex;align-items:center;gap:8px;margin-bottom:6px'>
                    {badge}
                    <span style='color:#e2e8f0;font-size:0.8rem;
                                 font-family:Rajdhani,sans-serif;font-weight:600'>
                        {alert['rule_name']}
                    </span>
                    <span style='color:#334155;font-size:0.6rem;margin-left:auto'>
                        {alert['alert_id']}
                    </span>
                </div>
                <div style='color:#64748b;font-size:0.72rem;margin-bottom:6px;
                            font-family:Rajdhani,sans-serif'>
                    {alert['description'][:120]}...
                </div>
                <div style='display:flex;gap:8px;flex-wrap:wrap'>
                    {source_html} {ip_html} {mitre_html}
                </div>
            </div>
            """, unsafe_allow_html=True)

with col_ips:
    st.markdown('<div class="section-label">🎯 Top Attacking IPs</div>',
                unsafe_allow_html=True)
    df_ips = load_top_ips(source_filter)
    if not df_ips.empty:
        fig_ips = go.Figure(go.Bar(
            x=df_ips["Intentos"],
            y=df_ips["IP"],
            orientation="h",
            marker=dict(
                color=df_ips["Intentos"],
                colorscale=[[0, "#0f2a1a"], [0.5, "#00a854"], [1, "#00ff88"]],
                line=dict(width=0),
            ),
            text=df_ips["Intentos"],
            textposition="outside",
            textfont=dict(color="#1f4a2e", size=10,
                         family="Share Tech Mono"),
        ))
        fig_ips.update_layout(
            **PLOTLY,
            height=320,
            xaxis=dict(showgrid=True, gridcolor="#0a1a0f",
                      color="#1f4a2e", tickfont=dict(size=9)),
            yaxis=dict(showgrid=False, color="#4b7a5e",
                      tickfont=dict(size=9)),
        )
        st.plotly_chart(fig_ips, use_container_width=True, key="chart_ips")
    else:
        st.markdown("<div class='terminal-text'>// NO DATA</div>", unsafe_allow_html=True)

st.markdown("---")

# ── EVENT DISTRIBUTION + TIMELINE ──
col_donut, col_timeline = st.columns([2, 3])

EVENT_COLORS = {
    "failed_password":   "#ff2d55",
    "accepted_password": "#00ff88",
    "invalid_user":      "#ffb800",
    "sudo_command":      "#6366f1",
    "http_request":      "#38bdf8",
    "fim_modified":       "#f97316",
    "fim_created":        "#a3e635",
    "fim_deleted":        "#ef4444",
}

with col_donut:
    st.markdown('<div class="section-label">📊 Event Distribution</div>',
                unsafe_allow_html=True)
    df_types = load_event_types(source_filter)
    if not df_types.empty:
        colors = [EVENT_COLORS.get(t, "#334155") for t in df_types["Tipo"]]
        fig_donut = go.Figure(go.Pie(
            labels=df_types["Tipo"],
            values=df_types["Count"],
            hole=0.65,
            marker=dict(colors=colors, line=dict(color="#030712", width=2)),
            textinfo="percent",
            textfont=dict(size=10, family="Share Tech Mono", color="#030712"),
        ))
        fig_donut.update_layout(
            **PLOTLY,
            height=280,
            showlegend=True,
            legend=dict(
                font=dict(size=9, family="Share Tech Mono", color="#4b7a5e"),
                bgcolor="rgba(0,0,0,0)",
            ),
            annotations=[dict(
                text=f"<b>{df_types['Count'].sum()}</b><br>events",
                x=0.5, y=0.5, font=dict(
                    size=14, color="#00ff88", family="Share Tech Mono"
                ),
                showarrow=False
            )]
        )
        st.plotly_chart(fig_donut, use_container_width=True, key="chart_donut")
    else:
        st.markdown("<div class='terminal-text'>// NO DATA</div>", unsafe_allow_html=True)

with col_timeline:
    st.markdown('<div class="section-label">📈 Event Timeline</div>',
                unsafe_allow_html=True)
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
                line=dict(
                    color=EVENT_COLORS.get(etype, "#334155"),
                    width=2
                ),
                marker=dict(size=5),
                fill="tozeroy",
                fillcolor="rgba(0,0,0,0.05)",
            ))
        fig_time.update_layout(
            **PLOTLY,
            height=280,
            xaxis=dict(showgrid=True, gridcolor="#0a1a0f",
                      color="#1f4a2e", tickfont=dict(size=9)),
            yaxis=dict(showgrid=True, gridcolor="#0a1a0f",
                      color="#1f4a2e", tickfont=dict(size=9)),
            legend=dict(
                font=dict(size=9, family="Share Tech Mono", color="#4b7a5e"),
                bgcolor="rgba(0,0,0,0)",
            ),
        )
        st.plotly_chart(fig_time, use_container_width=True, key="chart_timeline")
    else:
        st.markdown("<div class='terminal-text'>// NO DATA</div>", unsafe_allow_html=True)

st.markdown("---")
st.markdown("""
<div style='color:#0f2a1a;font-family:Share Tech Mono,monospace;
            font-size:0.6rem;text-align:center'>
    SENTINEL SIEM · DETECTION ENGINE v3.0 · MULTI-AGENT ·
    MITRE ATT&CK FRAMEWORK ·
    PORTFOLIO — EMILIANO · DATA ENGINEERING + CYBERSECURITY
</div>
""", unsafe_allow_html=True)
