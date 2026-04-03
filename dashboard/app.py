import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
import json
from pathlib import Path
from datetime import datetime


import sys
sys.path.insert(0, ".")

from engine.log_generator import run_generator
from engine.parsers.auth_parser import parse_log_file
from engine.detectors.rules import DetectionEngine
from engine.storage import initialize_db, insert_events, insert_alerts, DB_PATH


def bootstrap_data():
    """
    Si la base de datos no existe o está vacía,
    genera datos de demo automáticamente.
    Corre una sola vez al iniciar el dashboard.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    initialize_db()

    import sqlite3
    conn = sqlite3.connect(str(DB_PATH))
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()

    if count == 0:
        with st.spinner("🔄 Initializing threat database..."):
            # Generar 60 segundos de logs con 25% de ataques
            log_file = run_generator(
                duration_seconds=60,
                events_per_second=5.0,
                attack_probability=0.25
            )
            # Parsear y detectar
            events, _ = parse_log_file(log_file)
            engine = DetectionEngine()
            alerts = engine.run_all_rules(events)
            # Persistir
            insert_events(events)
            insert_alerts(alerts)


bootstrap_data()

DB_PATH = Path("data/siem.db")

st.set_page_config(
    page_title="SENTINEL — SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
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
""", unsafe_allow_html=True)

# ── PLOTLY THEME ──
PLOTLY = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Share Tech Mono", color="#4b7a5e"),
    margin=dict(l=10, r=10, t=10, b=10),
)


# ── DATA LAYER ──
@st.cache_resource
def get_conn():
    return sqlite3.connect(str(DB_PATH), check_same_thread=False)


@st.cache_data(ttl=30)
def load_summary():
    conn = get_conn()
    row = conn.execute("""
        SELECT
            COUNT(*)                                          as total_events,
            COUNT(DISTINCT source_ip)                         as unique_ips,
            SUM(CASE WHEN event_type='failed_password' OR
                          event_type='invalid_user' THEN 1 ELSE 0 END) as failed_logins,
            SUM(CASE WHEN event_type='accepted_password' THEN 1 ELSE 0 END) as ok_logins,
            SUM(CASE WHEN event_type='sudo_command'      THEN 1 ELSE 0 END) as sudo_events
        FROM events
    """).fetchone()
    alert_row = conn.execute("""
        SELECT COUNT(*) as total,
            SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as crit,
            SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END) as high
        FROM alerts
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
    return [dict(zip(cols, r)) for r in rows]


@st.cache_data(ttl=30)
def load_top_ips():
    conn = get_conn()
    rows = conn.execute("""
        SELECT source_ip, COUNT(*) as attempts,
               COUNT(DISTINCT username) as users
        FROM events
        WHERE event_type IN ('failed_password','invalid_user')
          AND source_ip IS NOT NULL
        GROUP BY source_ip ORDER BY attempts DESC LIMIT 8
    """).fetchall()
    return pd.DataFrame(rows, columns=["IP", "Intentos", "Usuarios objetivo"])


@st.cache_data(ttl=30)
def load_event_types():
    conn = get_conn()
    rows = conn.execute("""
        SELECT event_type, COUNT(*) as n FROM events GROUP BY event_type
    """).fetchall()
    return pd.DataFrame(rows, columns=["Tipo", "Count"])


@st.cache_data(ttl=30)
def load_timeline():
    conn = get_conn()
    rows = conn.execute("""
        SELECT substr(timestamp, 1, 8) as hour,
               event_type, COUNT(*) as n
        FROM events GROUP BY hour, event_type
        ORDER BY hour
    """).fetchall()
    return pd.DataFrame(rows, columns=["Hora", "Tipo", "Count"])


# ── SIDEBAR ──
with st.sidebar:
    st.markdown("""
    <div style='padding:8px 0 20px'>
        <div style='font-family:Share Tech Mono,monospace;font-size:1rem;
                    color:#00ff88;text-shadow:0 0 10px rgba(0,255,136,0.4)'>
            SENTINEL//SIEM
        </div>
        <div style='color:#1f4a2e;font-size:0.65rem;font-family:Share Tech Mono,monospace;
                    margin-top:2px'>
            v2.0 · INTRUSION DETECTION SYSTEM
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-label">Filter Alerts</div>',
                unsafe_allow_html=True)
    severity_filter = st.selectbox(
        "Severidad", ["ALL", "CRITICAL", "HIGH", "MEDIUM"],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown('<div class="section-label">System Status</div>',
                unsafe_allow_html=True)
    st.markdown("""
    <div style='background:#050d18;border:1px solid #0f2a1a;border-radius:4px;
                padding:10px 14px;margin-bottom:10px'>
        <div style='display:flex;align-items:center;margin-bottom:6px'>
            <span class='status-live'></span>
            <span style='color:#00ff88;font-family:Share Tech Mono,monospace;
                         font-size:0.65rem'>MONITORING ACTIVE</span>
        </div>
        <div class='terminal-text'>ENGINE: ONLINE</div>
        <div class='terminal-text'>RULES LOADED: 3</div>
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
summary = load_summary()

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
with k3: st.metric("FAILED LOGINS",  summary["failed"])
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
    filtered = alerts if severity_filter == "ALL" else [
        a for a in alerts if a["severity"] == severity_filter
    ]

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
                    {ip_html} {mitre_html}
                </div>
            </div>
            """, unsafe_allow_html=True)

with col_ips:
    st.markdown('<div class="section-label">🎯 Top Attacking IPs</div>',
                unsafe_allow_html=True)
    df_ips = load_top_ips()
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

st.markdown("---")

# ── EVENT DISTRIBUTION + TIMELINE ──
col_donut, col_timeline = st.columns([2, 3])

with col_donut:
    st.markdown('<div class="section-label">📊 Event Distribution</div>',
                unsafe_allow_html=True)
    df_types = load_event_types()
    if not df_types.empty:
        COLORS = {
            "failed_password":   "#ff2d55",
            "accepted_password": "#00ff88",
            "invalid_user":      "#ffb800",
            "sudo_command":      "#6366f1",
        }
        colors = [COLORS.get(t, "#334155") for t in df_types["Tipo"]]
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

with col_timeline:
    st.markdown('<div class="section-label">📈 Event Timeline</div>',
                unsafe_allow_html=True)
    df_time = load_timeline()
    if not df_time.empty:
        COLORS_T = {
            "failed_password":   "#ff2d55",
            "accepted_password": "#00ff88",
            "invalid_user":      "#ffb800",
            "sudo_command":      "#6366f1",
        }
        fig_time = go.Figure()
        for etype in df_time["Tipo"].unique():
            subset = df_time[df_time["Tipo"] == etype]
            fig_time.add_trace(go.Scatter(
                x=subset["Hora"],
                y=subset["Count"],
                name=etype,
                mode="lines+markers",
                line=dict(
                    color=COLORS_T.get(etype, "#334155"),
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
        st.plotly_chart(fig_time, use_container_width=True)
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

st.markdown("---")
st.markdown("""
<div style='color:#0f2a1a;font-family:Share Tech Mono,monospace;
            font-size:0.6rem;text-align:center'>
    SENTINEL SIEM · DETECTION ENGINE v2.0 ·
    MITRE ATT&CK FRAMEWORK ·
    PORTFOLIO — EMILIANO · DATA ENGINEERING + CYBERSECURITY
</div>
""", unsafe_allow_html=True)