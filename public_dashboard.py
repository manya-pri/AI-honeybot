"""Public SOC dashboard showcase backed only by fictional in-code examples."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st


st.set_page_config(page_title="AI Honeybot · SOC Demo", page_icon="◈", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background: radial-gradient(ellipse at 78% 0%, #172e4e 0, transparent 36%), #080d18; color: #edf4ff; }
    [data-testid="stSidebar"] { background: #0b1320; border-right: 1px solid #203149; }
    .block-container { max-width: 1320px; padding-top: 2rem; }
    .eyebrow { color:#63dfd1; letter-spacing:.17em; font-weight:700; font-size:.72rem; text-transform:uppercase; }
    .hero { padding:1.4rem 0 1rem; }
    .hero h1 { font-size:clamp(2.3rem,5vw,4rem); letter-spacing:-.055em; line-height:1.04; margin:.35rem 0; }
    .hero p { color:#adbed4; max-width:760px; font-size:1.02rem; }
    .demo-note { border:1px solid #355070; border-left:4px solid #f2c66d; border-radius:10px; padding:12px 15px; background:#101a29; color:#c5d3e5; margin:.75rem 0 1.2rem; }
    div[data-testid="stMetric"] { background:linear-gradient(145deg,#111d30,#0d1523); border:1px solid #24364e; border-radius:13px; padding:15px 17px; }
    h2, h3 { letter-spacing:-.025em; }
    .pill { display:inline-block; color:#8df0bd; background:#10271f; border:1px solid #376c57; border-radius:999px; padding:5px 10px; font-size:.7rem; letter-spacing:.12em; }
    </style>
    """,
    unsafe_allow_html=True,
)


def synthetic_events() -> pd.DataFrame:
    """Build a fresh, deterministic demo timeline without reading stored traffic."""
    now = datetime.now(timezone.utc)
    rows = [
        ("203.0.113.24", "GET", "/", 0, "LOW", "ALLOWED", "normal", "Baseline browsing"),
        ("203.0.113.24", "GET", "/login", 30, "MEDIUM", "MONITORED", "credential_probe", "Sensitive endpoint"),
        ("198.51.100.42", "GET", "/.env", 72, "HIGH", "BLOCKED", "scanner", "Synthetic decoy resource"),
        ("198.51.100.42", "POST", "/login", 78, "HIGH", "BLOCKED", "credential_attack", "Repeated login attempt"),
        ("192.0.2.17", "GET", "/admin", 45, "MEDIUM", "MONITORED", "admin_probe", "Administrative endpoint"),
        ("198.51.100.42", "POST", "/login", 92, "CRITICAL", "TEMPORARY BLOCK", "credential_attack", "Containment threshold reached"),
        ("203.0.113.57", "GET", "/credentials.txt", 66, "HIGH", "BLOCKED", "scanner", "Synthetic decoy resource"),
        ("192.0.2.17", "PUT", "/api/config", 61, "HIGH", "BLOCKED", "unusual_method", "Unusual HTTP method"),
        ("203.0.113.24", "GET", "/", 12, "LOW", "ALLOWED", "normal", "Known source returned"),
        ("198.51.100.42", "GET", "/database_backup.sql", 84, "CRITICAL", "TEMPORARY BLOCK", "scanner", "Repeated suspicious activity"),
        ("203.0.113.57", "POST", "/login", 58, "MEDIUM", "MONITORED", "credential_probe", "Failed decoy sign-in"),
        ("192.0.2.17", "GET", "/", 8, "LOW", "ALLOWED", "normal", "Baseline browsing"),
    ]
    return pd.DataFrame([
        {
            "timestamp": now - timedelta(minutes=(len(rows) - index - 1) * 4),
            "source_ip": ip,
            "method": method,
            "path": path,
            "risk_score": score,
            "risk_level": level,
            "action": action,
            "classification": label,
            "indicator": indicator,
            "synthetic": True,
        }
        for index, (ip, method, path, score, level, action, label, indicator) in enumerate(rows)
    ])


events = synthetic_events()
st.sidebar.markdown("## ◈ AI—HONEYBOT")
st.sidebar.caption("Adaptive defensive honeypot")
page = st.sidebar.radio(
    "Dashboard view",
    ("Overview", "Threats", "Attackers", "AI Analysis", "Deception", "Containment"),
)
st.sidebar.markdown("---")
st.sidebar.markdown('<span class="pill">PUBLIC SYNTHETIC DEMO</span>', unsafe_allow_html=True)
st.sidebar.caption("This dashboard is isolated from live event storage and APIs.")

st.markdown('<div class="hero"><div class="eyebrow">Public prototype · SOC command center</div>', unsafe_allow_html=True)
st.title("Adaptive honeypot dashboard")
st.markdown(
    "Explore a read-only SOC dashboard with fictional events, risk scores, and response decisions. "
    "The live local dashboard and captured honeypot events are not connected to this service."
)
st.markdown(
    '<div class="demo-note"><strong>DEMO DATA.</strong> All IPs use documentation-only example ranges. '
    "Classifications, locations, counts, and response actions below are illustrative and are not live detections.</div>",
    unsafe_allow_html=True,
)

if page == "Overview":
    total_sources = events["source_ip"].nunique()
    high_risk = int(events["risk_level"].isin(["HIGH", "CRITICAL"]).sum())
    contained = int(events["action"].eq("TEMPORARY BLOCK").sum())
    metrics = st.columns(4)
    metrics[0].metric("Demo events", len(events))
    metrics[1].metric("Synthetic sources", total_sources)
    metrics[2].metric("High / critical", high_risk)
    metrics[3].metric("Simulated blocks", contained)

    left, right = st.columns([1, 1.25])
    with left:
        st.subheader("Risk distribution")
        counts = events["risk_level"].value_counts().reindex(["LOW", "MEDIUM", "HIGH", "CRITICAL"], fill_value=0)
        st.bar_chart(counts, color="#69a9ff")
    with right:
        st.subheader("Risk timeline")
        timeline = events.set_index("timestamp")["risk_score"]
        st.line_chart(timeline, color="#57dfd0")

    st.subheader("Recent synthetic events")
    st.dataframe(
        events.sort_values("timestamp", ascending=False)[
            ["timestamp", "source_ip", "method", "path", "risk_score", "risk_level", "action"]
        ],
        use_container_width=True,
        hide_index=True,
    )

elif page == "Threats":
    st.subheader("Threat review")
    threshold = st.selectbox("Minimum risk", ["All", "MEDIUM", "HIGH", "CRITICAL"], index=0)
    filtered = events if threshold == "All" else events[events["risk_level"].isin(
        {"MEDIUM": ["MEDIUM", "HIGH", "CRITICAL"], "HIGH": ["HIGH", "CRITICAL"], "CRITICAL": ["CRITICAL"]}[threshold]
    )]
    st.caption(f"{len(filtered)} fictional rows match this view.")
    st.dataframe(filtered, use_container_width=True, hide_index=True)

elif page == "Attackers":
    st.subheader("Source profiles")
    profiles = events.groupby("source_ip", as_index=False).agg(
        events=("source_ip", "size"), peak_risk=("risk_score", "max"),
        latest_activity=("timestamp", "max"), behavior=("classification", "last"),
    ).sort_values("peak_risk", ascending=False)
    profiles["source_ip"] = profiles["source_ip"] + " · fictional"
    st.dataframe(profiles, use_container_width=True, hide_index=True)
    st.info("Source addresses are TEST-NET examples; no real visitors or attacker profiles are shown.")

elif page == "AI Analysis":
    st.subheader("Evidence-led analysis preview")
    st.markdown("The prototype combines explainable rules with a separate synthetic behavior label. The labels below are fixture values, not a live model inference.")
    selected = st.selectbox("Example event", events.index, format_func=lambda i: f"{events.loc[i, 'source_ip']} · {events.loc[i, 'method']} {events.loc[i, 'path']}")
    event = events.loc[selected]
    st.metric("Illustrative behavior label", event["classification"].replace("_", " ").title())
    st.metric("Rule risk", f"{event['risk_score']} / 100 · {event['risk_level']}")
    st.write("Evidence:", event["indicator"])
    st.caption("No LLM or external provider is called by this public dashboard.")

elif page == "Deception":
    st.subheader("Adaptive deception preview")
    st.write("A fictional source moves through decoy depth as risk indicators accumulate.")
    st.dataframe(pd.DataFrame([
        {"Synthetic source": "198.51.100.42", "Stage": "1 · Basic", "Trigger": "Initial endpoint probe", "Response": "Fictional portal"},
        {"Synthetic source": "198.51.100.42", "Stage": "2 · Elevated", "Trigger": "Repeated login + decoy access", "Response": "Expanded synthetic resources"},
        {"Synthetic source": "198.51.100.42", "Stage": "3 · Contained", "Trigger": "Configured threshold reached", "Response": "Temporary honeypot-only block"},
    ]), use_container_width=True, hide_index=True)
    st.caption("These transitions are examples and do not control a live honeypot.")

else:
    st.subheader("Containment policy preview")
    st.metric("Illustrative threshold", "3 suspicious events")
    st.metric("Illustrative duration", "5 minutes")
    st.dataframe(events[events["action"].eq("TEMPORARY BLOCK")][
        ["timestamp", "source_ip", "path", "risk_score", "action", "indicator"]
    ], use_container_width=True, hide_index=True)
    st.warning("This view is read-only. It cannot block or release any real source.")

st.markdown("---")
st.markdown("**AI-Honeybot public dashboard demo** · Synthetic fixture only · [Source code](https://github.com/manya-pri/AI-honeybot)")
