"""Premium, read-only Streamlit presentation over the local honeypot event log."""

from __future__ import annotations

import html
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import pandas as pd
import pydeck as pdk
import streamlit as st
from dotenv import load_dotenv

from dashboard_data import prepare_dashboard_data
from analyzer import RuleBasedAnalyzer, extract_behavior_features
from risk_response import InMemoryRiskStore, RiskResponseManager

load_dotenv()
EVENTS_FILE = Path(os.environ.get("HONEYPOT_EVENTS_FILE", "data/events.jsonl"))
API_URL = os.environ.get("HONEYPOT_API_URL", "http://127.0.0.1:8000").rstrip("/")
NAVIGATION = ("Overview", "Threats", "Attackers", "AI Analysis", "Deception", "Containment", "Live Demo")

st.set_page_config(page_title="AI—HONEYBOT | Security Monitor", page_icon="◈", layout="wide")
st.markdown(
    """
    <style>
      :root { color-scheme: dark; --ink:#f4f7ff; --muted:#8994ad; --blue:#4f8cff; --cyan:#61d9ff; --violet:#9874ff; }
      [data-testid="stAppViewContainer"] { background:radial-gradient(ellipse at 78% 0%,rgba(51,68,156,.18),transparent 36%),#05070d; }
      [data-testid="stHeader"] { background:rgba(5,7,13,.68); backdrop-filter:blur(18px); }
      [data-testid="stToolbar"] { right:1rem; }
      .block-container { max-width:1600px; padding:1.1rem clamp(1rem,4vw,4.5rem) 4rem; }
      h1,h2,h3,p,label { color:var(--ink); }
      .brand-row { display:flex; justify-content:space-between; align-items:center; gap:1.5rem;
        border:1px solid rgba(131,157,220,.12); border-radius:18px; padding:.85rem 1.15rem; margin-bottom:1.15rem;
        background:rgba(11,16,29,.68); backdrop-filter:blur(16px); box-shadow:0 12px 40px rgba(0,0,0,.18); }
      .brand-name { font-size:1.05rem; font-weight:760; letter-spacing:.15em; color:#f7f9ff; }
      .brand-mark { color:var(--cyan); margin-right:.55rem; text-shadow:0 0 18px rgba(76,180,255,.9); }
      .brand-tagline { color:var(--muted); margin:.28rem 0 0; font-size:.75rem; letter-spacing:.1em; text-transform:uppercase; }
      .status-stack { text-align:right; }
      .live-pill { display:inline-flex; gap:.5rem; align-items:center; border:1px solid rgba(68,216,178,.25);
        border-radius:99px; padding:.42rem .8rem; color:#a2f2d6; font-size:.67rem; letter-spacing:.13em; background:rgba(20,105,81,.1); }
      .live-dot { width:.42rem; height:.42rem; border-radius:50%; background:#48e0b0; display:inline-block; box-shadow:0 0 12px #48e0b0; animation:pulse 2s infinite; }
      .monitor-copy { color:#7d89a3; font-size:.66rem; margin-top:.42rem; letter-spacing:.08em; }
      @keyframes pulse { 50% { opacity:.45; box-shadow:0 0 4px #48e0b0; } }
      [data-testid="stRadio"] [role="radiogroup"] { gap:.45rem; flex-wrap:wrap; }
      [data-testid="stRadio"] label { border:1px solid rgba(122,148,201,.12); border-radius:999px; padding:.34rem .9rem;
        background:rgba(15,21,37,.78); color:#aab6cf; transition:all .2s ease; }
      [data-testid="stRadio"] label:hover { border-color:rgba(88,147,255,.55); color:white; }
      [data-testid="stRadio"] label:has(input:checked) { background:linear-gradient(110deg,#2455a9,#4b3a9b); color:#fff; border-color:#588eff; box-shadow:0 0 22px rgba(62,111,237,.25); }
      [data-testid="stRadio"] label p { color:inherit; font-size:.79rem; }
      .hero { position:relative; overflow:hidden; box-sizing:border-box; display:flex;align-items:center; min-height:64vh; padding:clamp(2.5rem,7vh,5.2rem) clamp(2rem,6vw,5.2rem); margin:1.25rem 0 1.5rem;
        border:1px solid rgba(115,151,231,.22); border-radius:28px;
        background:radial-gradient(ellipse at 76% 48%,rgba(52,111,255,.26),transparent 27%),radial-gradient(ellipse at 88% 70%,rgba(130,77,255,.18),transparent 34%),linear-gradient(115deg,rgba(10,17,33,.97),rgba(8,10,22,.82));
        box-shadow:inset 0 1px rgba(255,255,255,.04),0 26px 90px rgba(20,49,112,.19); }
      .hero:before { content:""; position:absolute; inset:0; pointer-events:none; opacity:.28;
        background-image:linear-gradient(rgba(106,150,236,.12) 1px,transparent 1px),linear-gradient(90deg,rgba(106,150,236,.12) 1px,transparent 1px); background-size:42px 42px;
        mask-image:linear-gradient(90deg,black,transparent 90%); }
      .hero:after { content:""; position:absolute; width:290px;height:290px;right:8%;top:8%; border:1px solid rgba(92,163,255,.32); border-radius:50%;
        box-shadow:0 0 0 28px rgba(71,120,241,.035),0 0 0 58px rgba(71,120,241,.025),inset 0 0 65px rgba(62,132,255,.11),0 0 90px rgba(73,113,255,.2); animation:orbit 18s linear infinite; }
      @keyframes orbit { to { transform:rotate(360deg); } }
      .hero-copy { position:relative; z-index:1; max-width:760px; }
      .hero-visual { position:absolute;z-index:0;right:1.5%;top:50%;transform:translateY(-50%);width:min(47%,640px);height:auto;overflow:visible;pointer-events:none;filter:drop-shadow(0 0 28px rgba(63,127,255,.2)); }
      .hero-visual .orbit { fill:none;stroke:rgba(94,150,255,.2);stroke-width:1; }
      .hero-visual .wire { fill:none;stroke:url(#wire);stroke-width:1.4;opacity:.75; }
      .hero-visual .cube-line { fill:rgba(25,68,147,.13);stroke:#6dafff;stroke-width:1.6;filter:url(#glow); }
      .hero-visual .cube-core { fill:url(#core);stroke:#8edaff;stroke-width:1.2;filter:url(#glow); }
      .hero-visual .satellite { fill:#67d9ff;filter:url(#glow);animation:float 4s ease-in-out infinite; }
      .hero-visual .satellite:nth-of-type(even) { animation-delay:-2s; }
      @keyframes float { 50% { transform:translateY(-8px);opacity:.65; } }
      .hero-kicker { color:#82caff; font-size:.7rem; letter-spacing:.23em; text-transform:uppercase; margin-bottom:1.1rem; }
      .hero-title { font-size:clamp(3rem,7.2vw,7rem); line-height:.93; font-weight:820; letter-spacing:-.065em; margin:0; color:#f7f9ff; }
      .hero-title span { background:linear-gradient(90deg,#fff,#78b9ff 55%,#b19aff); -webkit-background-clip:text; color:transparent; }
      .hero-subtitle { color:#d2dcf2; font-size:clamp(1rem,2vw,1.35rem); letter-spacing:.02em; margin:1rem 0 .7rem; }
      .hero-description { max-width:650px; color:#8f9bb6; font-size:.92rem; line-height:1.7; }
      .hero-orb { position:absolute; width:8px;height:8px;right:20%;top:37%;border-radius:50%;background:#73dcff;box-shadow:0 0 20px 6px rgba(75,183,255,.7); }
      .section-kicker { color:#7ebaff; font-size:.68rem; letter-spacing:.18em; text-transform:uppercase; margin:.3rem 0 .7rem; }
      .section-title { font-size:1.48rem; font-weight:690; letter-spacing:-.035em; margin:.1rem 0 .35rem; }
      .section-note { color:var(--muted); font-size:.86rem; margin:0 0 1.15rem; }
      .metric-card { min-height:130px; padding:1.15rem 1.25rem; border:1px solid rgba(132,157,211,.17); border-radius:19px;
        background:linear-gradient(145deg,rgba(19,28,48,.82),rgba(10,14,25,.9)); box-shadow:inset 0 1px rgba(255,255,255,.035),0 12px 32px rgba(0,0,0,.16); transition:transform .2s,border-color .2s,box-shadow .2s; }
      .metric-card:hover { transform:translateY(-3px); border-color:rgba(95,151,255,.48); box-shadow:0 15px 38px rgba(30,83,178,.13); }
      .metric-label { color:#8e9bb7; text-transform:uppercase; letter-spacing:.13em; font-size:.66rem; }
      .metric-value { color:#f4f7ff; font-size:2.35rem; line-height:1.1; font-weight:720; margin:.75rem 0 .35rem; letter-spacing:-.045em; }
      .metric-detail { color:#74819b; font-size:.75rem; }
      .risk-gauge { width:160px;height:160px;border-radius:50%;display:grid;place-items:center;position:relative;
        background:conic-gradient(#5acbff calc(var(--risk) * 1%),#17223b 0); box-shadow:0 0 36px rgba(63,137,255,.18); }
      .risk-gauge:before { content:"";position:absolute;inset:10px;border-radius:50%;background:#0b1120;border:1px solid rgba(120,164,255,.2); }
      .risk-gauge-inner { position:relative;text-align:center;color:#f4f7ff;font-size:2rem;font-weight:750;letter-spacing:-.05em; }
      .risk-gauge-inner small { display:block;color:#8391ad;font-size:.61rem;letter-spacing:.16em;font-weight:600; }
      .insight-grid { display:grid;grid-template-columns:repeat(auto-fit,minmax(125px,1fr));gap:.7rem;margin-top:1.1rem; }
      .insight-cell { padding:.8rem .9rem;border:1px solid rgba(132,157,211,.13);border-radius:14px;background:rgba(9,15,28,.65); }
      .insight-label { color:#7e8ca8;font-size:.62rem;letter-spacing:.12em;text-transform:uppercase; }
      .insight-value { color:#e8efff;font-size:1.05rem;font-weight:650;margin-top:.35rem; }
      .flow-track { display:flex;align-items:center;justify-content:space-between;gap:.45rem;margin:1rem 0 1.5rem;padding:1rem 1.15rem;border:1px solid rgba(132,157,211,.13);border-radius:17px;background:rgba(9,15,28,.63); }
      .flow-node { color:#dce8ff;font-size:.73rem;letter-spacing:.08em;text-transform:uppercase;text-align:center; }
      .flow-node small { display:block;color:#7383a1;font-size:.59rem;letter-spacing:.12em;margin-top:.32rem; }
      .flow-arrow { color:#5b8eff;font-size:1.1rem; }
      .agent-state { display:inline-flex;align-items:center;gap:.55rem;border:1px solid rgba(77,157,255,.23);border-radius:99px;padding:.48rem .78rem;color:#b8dcff;background:rgba(31,76,138,.17);font-size:.68rem;letter-spacing:.12em; }
      .agent-pulse { width:.45rem;height:.45rem;border-radius:50%;background:#62cbff;box-shadow:0 0 12px #62cbff;animation:pulse 1.8s ease-in-out infinite; }
      .live-demo-panel { border:1px solid rgba(90,153,255,.25);border-radius:25px;padding:clamp(1.1rem,3vw,2rem);background:radial-gradient(ellipse at 90% 4%,rgba(63,86,190,.18),transparent 40%),linear-gradient(145deg,rgba(17,24,43,.95),rgba(7,11,21,.97));box-shadow:0 22px 65px rgba(10,34,89,.2); }
      .demo-event { display:grid;grid-template-columns:100px 1fr auto;gap:.9rem;align-items:center;padding:.85rem 1rem;margin:.55rem 0;border:1px solid rgba(132,157,211,.13);border-radius:14px;background:rgba(9,15,28,.72); }
      .demo-attempt { color:#8ebdff;font-size:.67rem;letter-spacing:.12em;text-transform:uppercase; }
      .demo-event-copy { color:#dce7fb;font-size:.85rem; }
      .demo-timestamp { color:#7786a3;font-size:.72rem;font-variant-numeric:tabular-nums; }
      .demo-risk { display:inline-flex;align-items:center;justify-content:center;min-width:92px;padding:.35rem .7rem;border-radius:999px;border:1px solid rgba(110,143,205,.25);font-size:.66rem;letter-spacing:.1em;animation:risk-in .35s ease-out; }
      @keyframes risk-in { from { transform:scale(.84);opacity:.3; } to { transform:scale(1);opacity:1; } }
      .demo-risk-low { color:#a5caff;background:rgba(42,94,169,.15); }
      .demo-risk-medium { color:#d0bcff;background:rgba(93,65,170,.2); }
      .demo-risk-high { color:#ffb4bb;background:rgba(145,44,66,.23);border-color:rgba(246,98,121,.42);box-shadow:0 0 20px rgba(194,59,91,.12); }
      .demo-flow { display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:1rem 0 1.3rem; }
      .demo-step { border:1px solid rgba(118,147,200,.15);border-radius:999px;padding:.45rem .7rem;color:#74839e;font-size:.64rem;letter-spacing:.08em;text-transform:uppercase; }
      .demo-step-active { color:#c7e2ff;border-color:rgba(94,161,255,.5);background:rgba(37,89,158,.21);box-shadow:0 0 17px rgba(72,141,246,.14); }
      .demo-step-done { color:#a8b8d4;border-color:rgba(110,145,205,.26); }
      .demo-threat-alert { border:1px solid rgba(239,92,117,.48);border-radius:17px;padding:1.1rem 1.25rem;color:#ffdbe0;background:linear-gradient(110deg,rgba(133,35,59,.28),rgba(75,24,49,.18));box-shadow:0 0 30px rgba(190,47,77,.13); }
      .demo-kpis { display:grid;grid-template-columns:1.45fr 1fr 1fr 1fr 1.45fr;gap:.7rem;margin:1.1rem 0; }
      .demo-kpi { min-width:0;padding:.9rem 1rem;border:1px solid rgba(132,157,211,.16);border-radius:16px;background:linear-gradient(145deg,rgba(19,28,48,.82),rgba(10,14,25,.9)); }
      .demo-kpi-label { color:#8291ad;text-transform:uppercase;letter-spacing:.12em;font-size:.61rem; }
      .demo-kpi-value { color:#eff5ff;font-size:clamp(1.05rem,2vw,1.55rem);font-weight:720;letter-spacing:-.035em;margin-top:.5rem;overflow-wrap:anywhere; }
      @media (max-width:850px) { .demo-kpis { grid-template-columns:repeat(3,minmax(0,1fr)); } }
      @media (max-width:560px) { .demo-kpis { grid-template-columns:repeat(2,minmax(0,1fr)); } }
      .feed-row { display:grid; grid-template-columns:1.15fr 1.35fr 1.75fr .72fr .78fr .85fr; gap:.8rem;
        align-items:center; padding:.9rem .85rem; border-bottom:1px solid rgba(122,144,187,.12); color:#d8e0f2; font-size:.8rem; }
      .feed-head { color:#7785a1; text-transform:uppercase; font-size:.63rem; letter-spacing:.1em; }
      .feed-ip { color:#f2f2f4; font-weight:600; font-variant-numeric:tabular-nums; }
      .feed-muted { color:#a0a2aa; overflow-wrap:anywhere; }
      .risk-label, .action-label { display:inline-block; border:1px solid #41434a; border-radius:999px;
        padding:.22rem .42rem; font-size:.67rem; letter-spacing:.06em; white-space:nowrap; }
      .risk-high, .risk-critical, .action-blocked { color:#f0aaa3; border-color:#70443f; background:#291a1a; }
      .risk-medium, .action-monitored { color:#e4c38f; border-color:#6b5737; background:#241e14; }
      .risk-low, .action-allowed { color:#c0c9d6; border-color:#45505e; background:#171c23; }
      .risk-unknown, .action-recorded { color:#c3c4ca; border-color:#494a50; background:#191a1f; }
      .path-chip { color:#d9dbe0; font-family:ui-monospace, SFMono-Regular, Consolas, monospace; }
      .stage-track { display:flex; align-items:center; gap:.6rem; flex-wrap:wrap; padding:1.15rem 0; }
      .stage { border:1px solid #363840; border-radius:6px; padding:.55rem .8rem; color:#bec0c6; font-size:.76rem; letter-spacing:.08em; }
      .stage-arrow { color:#6f727b; }
      .stage-contained { color:#f1b0a8; border-color:#70443f; background:#241819; }
      .panel { border:1px solid rgba(132,157,211,.15); border-radius:21px; background:linear-gradient(145deg,rgba(17,24,41,.83),rgba(9,13,24,.91)); padding:1.2rem 1.35rem; box-shadow:inset 0 1px rgba(255,255,255,.025); }
      .timeline-item { display:grid; grid-template-columns:125px 1fr; gap:1rem; padding:.7rem 0;
        border-bottom:1px solid #24262d; color:#c9cbd1; font-size:.84rem; }
      .timeline-time { color:#898c95; font-variant-numeric:tabular-nums; }
      .location-note { border-left:2px solid #58a8ff; padding:.65rem .85rem; color:#b7c5dd;
        background:rgba(14,22,39,.75); font-size:.84rem; }
      .footer-line { margin-top:2.2rem; padding-top:1rem; border-top:1px solid rgba(122,144,187,.14); color:#65718b;
        font-size:.72rem; display:flex; justify-content:space-between; gap:1rem; }
      [data-testid="stDataFrame"] { border:1px solid rgba(132,157,211,.16); border-radius:15px; background:#0b1020; }
      [data-testid="stAlert"] { background:rgba(17,25,43,.88); border:1px solid rgba(95,143,226,.2); border-radius:14px; }
      [data-testid="stButton"] button { border-radius:999px; border:1px solid rgba(124,164,255,.34); color:#eaf1ff; background:linear-gradient(110deg,#1c4d98,#41327f); padding:.68rem 1.35rem; font-weight:650; }
      [data-testid="stButton"] button:hover { border-color:#80c8ff; color:white; box-shadow:0 0 24px rgba(69,135,255,.3); }
      @media (prefers-reduced-motion:reduce) { *,*:before,*:after { animation-duration:.01ms !important; animation-iteration-count:1 !important; scroll-behavior:auto !important; transition-duration:.01ms !important; } }
      @media (max-width: 850px) {
        .block-container { padding:1.2rem 1rem 2rem; }
        .brand-row { flex-direction:column; }
        .status-stack { text-align:left; }
        .feed-row { grid-template-columns:1fr 1fr; gap:.45rem; }
        .feed-head { display:none; }
        .metric-card { min-height:120px; }
        .hero { min-height:62vh; padding:2rem 1.3rem; }
        .hero:after { width:150px;height:150px;right:-3%;top:8%;opacity:.55; }
        .hero-visual { width:58%;right:-7%;opacity:.25; }
        [data-testid="stHorizontalBlock"]:has(.metric-card) { display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.7rem; }
        [data-testid="stHorizontalBlock"]:has(.metric-card) > [data-testid="column"] { width:auto !important;flex:none !important;min-width:0; }
        .flow-track { flex-wrap:wrap;justify-content:center; }
      }
      @media (max-width: 650px) {
        [data-testid="stHorizontalBlock"]:has(.metric-card) { display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.65rem; }
        [data-testid="stHorizontalBlock"]:has(.metric-card) > [data-testid="column"] { width:auto !important;flex:none !important;min-width:0; }
        .metric-card { padding:.9rem; }
        .metric-value { font-size:1.9rem; }
        .flow-track { display:grid;grid-template-columns:1fr;justify-items:start;padding:.85rem; }
        .flow-arrow { transform:rotate(90deg);margin-left:.5rem; }
      }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(ttl=2)
def load_events(path: str, modified: float) -> list[dict[str, Any]]:
    """Read valid JSONL events; include mtime in the key for append refreshes."""
    del modified
    events: list[dict[str, Any]] = []
    try:
        with Path(path).open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        events.append(event)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return events


def _risk_class(level: str) -> str:
    return {"LOW": "risk-low", "MEDIUM": "risk-medium", "HIGH": "risk-high", "CRITICAL": "risk-critical"}.get(level, "risk-unknown")


def _action_class(action: str) -> str:
    return {"ALLOWED": "action-allowed", "MONITORED": "action-monitored", "BLOCKED": "action-blocked"}.get(action, "action-recorded")


def _safe(value: Any) -> str:
    if value is None:
        value = "—"
    else:
        try:
            if bool(pd.isna(value)) or value == "":
                value = "—"
        except (TypeError, ValueError):
            pass
    return html.escape(str(value))


def _metric_cards(summary: dict[str, int]) -> None:
    values = (
        ("Events", summary["total_interactions"], "Backend-recorded requests"),
        ("Active threats", summary["active_suspicious"], "Suspicious sources · last 15 min"),
        ("Attackers", summary["total_sources"], "Distinct observed sources"),
        ("High risk", summary["high_risk_attackers"], "Sources at HIGH / CRITICAL"),
        ("Contained", summary["currently_blocked"], "Active temporary containment"),
    )
    columns = st.columns(5)
    for column, (label, value, detail) in zip(columns, values):
        with column:
            st.markdown(
                f'<section class="metric-card"><div class="metric-label">{_safe(label)}</div>'
                f'<div class="metric-value">{value:,}</div><div class="metric-detail">{_safe(detail)}</div></section>',
                unsafe_allow_html=True,
            )


def _post_json(api_url: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        f"{api_url}{path}", data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read(64_000))


def _run_demo_flow() -> int:
    """Send the established loopback-only simulation sequence to the existing API."""
    sequence = (
        {"endpoint": "/", "method": "GET"},
        {"endpoint": "/login", "method": "POST", "authentication_failed": True},
        {"endpoint": "/login", "method": "POST", "authentication_failed": True},
        {"endpoint": "/wp-admin", "method": "GET", "user_agent": "nmap/7.95"},
        {"endpoint": "/.env", "method": "GET"},
        {"endpoint": "/api/v1/users", "method": "GET", "user_agent": "sqlmap"},
        {"endpoint": "/ssh/session", "method": "POST", "user_agent": "HoneyBotDemo/1.0"},
        {"endpoint": "/login", "method": "POST", "authentication_failed": True},
    )
    for item in sequence:
        _post_json(API_URL, "/api/simulation/event", {"source_ip": "127.0.0.42", **item})
    for source_ip in ("127.0.0.43", "127.0.0.44"):
        for endpoint, user_agent in (("/.env", "HoneyBotDemo/1.0"), ("/admin", "nmap/7.95")):
            _post_json(API_URL, "/api/simulation/event", {
                "source_ip": source_ip, "endpoint": endpoint, "user_agent": user_agent,
            })
    _post_json(API_URL, "/api/agent/analyze", {"source_ip": "127.0.0.42"})
    _post_json(API_URL, "/api/response/contain", {
        "source_ip": "127.0.0.42", "reason": "Demo policy after accumulated synthetic observations",
    })
    return len(sequence) + 4


def _render_hero() -> None:
    agent = _load_agent_status(API_URL)
    try:
        modified = EVENTS_FILE.stat().st_mtime
    except OSError:
        modified = 0.0
    event_data = prepare_dashboard_data(load_events(str(EVENTS_FILE), modified))
    demo_enabled = event_data["demo_mode"] or os.environ.get("DEMO_MODE", "false").lower() in {"1", "true", "yes", "on"}
    st.markdown(
        '<section class="hero"><div class="hero-orb"></div>'
        '<svg class="hero-visual" viewBox="0 0 620 470" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">'
        '<defs><linearGradient id="wire" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#57d9ff"/><stop offset="1" stop-color="#9274ff"/></linearGradient>'
        '<linearGradient id="core" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#17427e"/><stop offset=".55" stop-color="#302a76"/><stop offset="1" stop-color="#142d5b"/></linearGradient>'
        '<filter id="glow" x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation="5" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>'
        '<ellipse class="orbit" cx="337" cy="239" rx="220" ry="146" transform="rotate(-18 337 239)"/>'
        '<ellipse class="orbit" cx="337" cy="239" rx="176" ry="212" transform="rotate(34 337 239)"/>'
        '<path class="wire" d="M94 310 220 268 302 136 411 203 522 112M139 152 256 191 337 239 460 328 539 271M220 268 337 239 410 360"/>'
        '<path class="cube-line" d="m337 153 79 45v91l-79 45-79-45v-91z"/><path class="cube-line" d="m258 198 79 45 79-45M337 243v91"/>'
        '<path class="cube-core" d="m337 190 45 26v52l-45 26-45-26v-52z"/><path class="cube-line" d="m292 216 45 27 45-27M337 243v51"/>'
        '<path class="cube-line" d="m170 83 24 14v28l-24 14-24-14V97zM480 344l20 12v23l-20 12-20-12v-23zM505 178l15 9v18l-15 9-15-9v-18z"/>'
        '<circle class="satellite" cx="94" cy="310" r="5"/><circle class="satellite" cx="522" cy="112" r="5"/><circle class="satellite" cx="139" cy="152" r="4"/><circle class="satellite" cx="539" cy="271" r="4"/><circle class="satellite" cx="410" cy="360" r="4"/>'
        '</svg><div class="hero-copy">'
        '<div class="hero-kicker">AI SECURITY COMMAND CENTER · DEFENSIVE MONITORING</div>'
        '<h1 class="hero-title" aria-label="ADAPTIVE AI HONEYPOT">ADAPTIVE<br/><span>AI HONEYPOT</span></h1>'
        '<div class="hero-subtitle">Observe. Learn. Deceive. Contain.</div>'
        '<div class="hero-description">An intelligent defensive security system that learns attacker behavior, '
        'adapts deception, evaluates risk and applies controlled temporary containment.</div>'
        '</div></section>', unsafe_allow_html=True,
    )
    left, right = st.columns([1, 2])
    with left:
        if st.button("ENTER SECURITY CENTER", key="enter_security_center", use_container_width=True):
            # Threats is an existing navigation state that renders the overview
            # dashboard; selecting it makes this action a real state transition.
            st.session_state["dashboard_navigation"] = "Threats"
    with right:
        system_status = "SYSTEM ONLINE" if agent.get("status") == "online" else "API OFFLINE · LOCAL EVENT VIEW"
        demo_status = "DEMO MODE · SYNTHETIC DATA" if demo_enabled else "DEMO MODE OFF"
        assessment = agent.get("latest_assessment") or {}
        ai_status = "LLM ANALYSIS ACTIVE" if assessment.get("llm_used") is True else "LOCAL AI MODE"
        st.caption(f"{system_status} · {ai_status} · {demo_status}")
    demo_col, live_demo_col, note_col = st.columns([1, 1, 2])
    with demo_col:
        if st.button("▶  RUN DEMO", key="run_demo_flow", use_container_width=True):
            try:
                with st.spinner("Running loopback simulation · updating event history, analysis and response…"):
                    event_count = _run_demo_flow()
                st.success(f"Demo complete · {event_count} synthetic events sent to the backend. Refreshing live data.")
                st.rerun()
            except Exception as error:
                st.error(f"Demo could not reach the configured HoneyBot API ({API_URL}): {error}")
    with live_demo_col:
        if st.button("◉  LIVE DEMO", key="open_live_demo", use_container_width=True):
            st.session_state["live_demo_runtime"] = _new_live_demo_runtime()
            st.session_state["dashboard_navigation"] = "Live Demo"
            st.rerun()
    with note_col:
        st.caption("RUN DEMO sends synthetic events to the local API. LIVE DEMO is session-only and sends no traffic.")


@st.cache_data(ttl=5)
def _load_agent_status(api_url: str) -> dict[str, Any]:
    try:
        with urlopen(f"{api_url}/api/agent/status", timeout=1.5) as response:
            return json.loads(response.read(64_000))
    except Exception:
        return {"agent_mode": "local", "status": "backend unavailable", "llm_used": False}


def _status_chips(data: dict[str, Any]) -> None:
    agent = _load_agent_status(API_URL)
    demo = bool(data.get("demo_mode") or os.environ.get("DEMO_MODE", "false").lower() in {"1", "true", "yes", "on"})
    left, right = st.columns(2)
    with left:
        st.info(f"AI MODE: {str(agent.get('agent_mode', 'local')).upper()} · {agent.get('status', 'online')}")
    with right:
        if demo:
            st.warning("DEMO MODE: ON · simulated sources and map points are labelled")
        else:
            st.caption("DEMO MODE: OFF")


def _render_threat_map(data: dict[str, Any]) -> None:
    st.markdown('<div class="section-kicker">Threat map</div>', unsafe_allow_html=True)
    map_points = data.get("map_points", [])
    if not map_points:
        st.info("No geolocated events yet. Simulator events add clearly labelled synthetic map points.")
        return
    if any(item.get("is_synthetic") for item in map_points):
        st.caption("DEMO DATA — orange markers use fictional coordinates; they do not represent real attacker intelligence.")
    if any(not item.get("is_synthetic") for item in map_points):
        st.caption("Blue markers show approximate GeoIP estimates for observed source IPs.")
    records = [{**item,
        "attacker_id": _safe(item["attacker_id"]), "demo_label": _safe(item["demo_label"]),
        "location": _safe(item["location"]), "attack_type": _safe(item["attack_type"]),
        "country": _safe(item["country"]),
    } for item in map_points]
    layer = pdk.Layer(
        "ScatterplotLayer", data=records, id="demo-threat-markers", pickable=True, auto_highlight=True,
        get_position="[longitude, latitude]", get_radius=85_000,
        get_fill_color="marker_color", get_line_color=[250, 220, 190, 255], line_width_min_pixels=2,
    )
    view = pdk.ViewState(latitude=30, longitude=-15, zoom=1.15, min_zoom=0.5, max_zoom=12)
    deck = pdk.Deck(
        layers=[layer], initial_view_state=view,
        tooltip={"html": "<b>{demo_label}</b><br/>Attacker: {attacker_id}<br/>Location: {location}<br/>"
                          "Attack: {attack_type}<br/>Risk: {risk_score}<br/>Events: {event_count}<br/>Threat: {threat_level}",
                 "style": {"backgroundColor": "#17191f", "color": "#f2f3f5"}},
    )
    selection = st.pydeck_chart(deck, height=330, key="threat_map", on_select="rerun", selection_mode="single-object")
    selected = None
    try:
        picked = selection.selection.get("objects", {})
        selected = next((item for values in picked.values() for item in values), None)
    except (AttributeError, TypeError):
        selected = None
    choices = {f"{record['attacker_id']} · {record['location']}": record for record in records}
    selected_key = st.selectbox("Inspect map marker", list(choices), key="demo_map_attacker")
    selected_record = choices[selected_key]
    detail = selected or selected_record
    id_label = "Attacker ID" if detail.get("is_synthetic") else "Source IP"
    st.write(f"**{detail['demo_label']}** · **{id_label}:** {detail['attacker_id']} · **Location:** {detail['location']} · "
             f"**Attack type:** {detail['attack_type']} · **Risk:** {detail['risk_score']} · "
             f"**Events:** {detail['event_count']} · **Threat:** {detail['threat_level']}")


def _feed_row(row: Any, *, header: bool = False) -> None:
    if header:
        cells = ("SOURCE IP", "APPROX. LOCATION", "REQUEST", "RISK", "SCORE", "ACTION")
        class_name = "feed-row feed-head"
        markup = "".join(f"<span>{_safe(cell)}</span>" for cell in cells)
    else:
        level, action = str(row.risk_level), str(row.action)
        markup = (
            f'<span class="feed-ip">{_safe(row.source_ip)}</span>'
            f'<span class="feed-muted">{_safe(row.approximate_location)}</span>'
            f'<span><span class="path-chip">{_safe(row.method)} {_safe(row.endpoint)}</span>'
            f'<br><span class="feed-muted">{_safe(row.timestamp)}</span></span>'
            f'<span class="risk-label {_risk_class(level)}">{_safe(level)}</span>'
            f'<span>{int(row.risk_score):d}</span>'
            f'<span class="action-label {_action_class(action)}">{_safe(action)}</span>'
        )
        class_name = "feed-row"
    st.markdown(f'<div class="{class_name}">{markup}</div>', unsafe_allow_html=True)


def _render_overview(data: dict[str, Any]) -> None:
    events = data["events"]
    _status_chips(data)
    st.markdown('<div class="flow-track"><span class="flow-node">Attacker<small>observed source</small></span><span class="flow-arrow">→</span>'
                '<span class="flow-node">Honeypot<small>decoy interaction</small></span><span class="flow-arrow">→</span>'
                '<span class="flow-node">AI analysis<small>evidence + model</small></span><span class="flow-arrow">→</span>'
                '<span class="flow-node">Deception<small>adaptive tier</small></span><span class="flow-arrow">→</span>'
                '<span class="flow-node">Containment<small>policy evaluation</small></span></div>', unsafe_allow_html=True)
    map_col, feed_col = st.columns([1.3, 1], gap="large")
    with map_col:
        st.markdown('<div class="section-kicker">Network visualization</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-title">Live threat activity</div>', unsafe_allow_html=True)
        st.caption("Observed attacker sources and approximate locations from the event backend.")
        _render_threat_map(data)
    with feed_col:
        st.markdown('<div class="section-kicker">Event stream</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-title">Latest interactions</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-note">Requests, risk decisions and source signals.</div>', unsafe_allow_html=True)
        _feed_row(None, header=True)
        for row in events.sort_values("timestamp_dt", ascending=False).head(7).itertuples():
            _feed_row(row)

    with st.container(border=True):
        st.markdown('<div class="section-kicker">Risk intelligence</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-title">Risk progression & observed patterns</div>', unsafe_allow_html=True)
        left, right = st.columns([1, 1.3], gap="large")
        with left:
            if data["risk_distribution"]:
                st.bar_chart(pd.Series(data["risk_distribution"], name="Events"), color="#548eff")
            else:
                st.caption("No threat levels recorded.")
        with right:
            chart = events.tail(100).set_index("timestamp_dt")[["risk_score"]]
            st.line_chart(chart, height=220, color="#7e70ff")

    _render_agent_snapshot(data)


def _render_agent_snapshot(data: dict[str, Any]) -> None:
    latest = data["events"].sort_values("timestamp_dt").iloc[-1]
    history = data["events"][data["events"]["source_ip"].astype(str) == str(latest["source_ip"])].sort_values("timestamp_dt")
    ml = latest["ml"] if isinstance(latest["ml"], dict) else {}
    agent = _load_agent_status(API_URL)
    assessment = agent.get("latest_assessment") or {}
    mode_label = "LLM ANALYSIS ACTIVE" if assessment.get("llm_used") is True else "LOCAL AI MODE"
    with st.container(border=True):
        st.markdown('<div class="section-kicker">AI security agent</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-title">AI security agent · evidence-led analysis</div>', unsafe_allow_html=True)
        st.markdown(f'<span class="agent-state"><span class="agent-pulse"></span>{_safe(mode_label)}</span>', unsafe_allow_html=True)
        score = max(0, min(100, int(latest["risk_score"])))
        gauge_col, info_col = st.columns([.45, 1.55], gap="large")
        with gauge_col:
            st.markdown(f'<div class="risk-gauge" style="--risk:{score}"><div class="risk-gauge-inner">{score}<small>CURRENT RISK</small></div></div>', unsafe_allow_html=True)
        source_events = len(history)
        credential_attempts = sum(bool(json.loads(raw or "{}").get("authentication_failed")) for raw in history["features_json"])
        suspicious_requests = int(history["indicators"].map(bool).sum())
        elapsed = 1.0
        if source_events > 1:
            seconds = (history.iloc[-1]["timestamp_dt"] - history.iloc[0]["timestamp_dt"]).total_seconds()
            elapsed = max(seconds / 60.0, 1 / 60)
        frequency = source_events / elapsed
        pattern_confidence = f"{float(ml.get('confidence', 0)):.0%}" if ml else "Unavailable"
        with info_col:
            st.markdown('<div class="section-kicker">Attacker behavior · current source</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="insight-grid"><div class="insight-cell"><div class="insight-label">Behavior frequency</div><div class="insight-value">{frequency:.1f} / min</div></div>'
                f'<div class="insight-cell"><div class="insight-label">Credential attempts</div><div class="insight-value">{credential_attempts}</div></div>'
                f'<div class="insight-cell"><div class="insight-label">Suspicious requests</div><div class="insight-value">{suspicious_requests}</div></div>'
                f'<div class="insight-cell"><div class="insight-label">Pattern confidence</div><div class="insight-value">{pattern_confidence}</div></div>'
                f'<div class="insight-cell"><div class="insight-label">Historical peak</div><div class="insight-value">{int(history["risk_score"].max())} / 100</div></div></div>', unsafe_allow_html=True)
            a, b = st.columns(2)
            a.metric("ML classification", ml.get("label", "Unavailable"))
            b.metric("Current response", latest["action"])
        if assessment:
            st.caption(f"{str(assessment.get('agent_mode', 'local')).upper()} MODE · {_safe(assessment.get('evidence_summary', assessment.get('reason', 'Assessment available')))}")
        st.caption("EVENT DETECTED  →  BEHAVIOR ANALYZED  →  RISK UPDATED  →  DECEPTION ADAPTED  →  CONTAINMENT EVALUATED")


def _render_deception(data: dict[str, Any]) -> None:
    st.markdown('<div class="section-kicker">Adaptive response</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Adaptive deception</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-note">Current tier and transitions are read from the existing deception engine event history.</div>', unsafe_allow_html=True)
    st.markdown('<div class="flow-track"><span class="flow-node">Observe<small>collect signals</small></span><span class="flow-arrow">→</span>'
                '<span class="flow-node">Deceive<small>serve decoys</small></span><span class="flow-arrow">→</span>'
                '<span class="flow-node">Adapt<small>risk-based tier</small></span><span class="flow-arrow">→</span>'
                '<span class="flow-node">Contain<small>temporary policy</small></span></div>', unsafe_allow_html=True)
    history = data["events"].sort_values("timestamp_dt")
    transitions = [value for value in history["deception_change"] if isinstance(value, dict) and value]
    current = transitions[-1].get("new_mode") if transitions else "No transition recorded"
    tier_names = {"basic": "Tier 1 · Basic decoy", "expanded": "Tier 2 · Enhanced decoy",
                  "high_interaction": "Tier 3 · High-interaction decoy", "maximum_observation": "Tier 4 · Maximum observation"}
    st.markdown(f'<div class="panel"><div class="section-kicker">CURRENT DECEPTION TIER</div>'
                f'<div class="metric-value">{_safe(tier_names.get(current, current))}</div>'
                '<div class="metric-detail">Tier shown reflects the latest persisted deception transition.</div></div>', unsafe_allow_html=True)
    if transitions:
        rows = [{"Timestamp": row.timestamp, "Source": row.source_ip,
                 "Transition": f"{row.deception_change.get('previous_mode') or 'initial'} → {row.deception_change.get('new_mode')}",
                 "Reason": row.deception_change.get("reason", "—")} for row in history.itertuples()
                if isinstance(row.deception_change, dict) and row.deception_change]
        st.dataframe(pd.DataFrame(rows).sort_values("Timestamp", ascending=False), width="stretch", hide_index=True)
    else:
        st.info("No deception tier transition has been recorded yet. Tier changes appear as risk evolves.")


def _render_containment(data: dict[str, Any]) -> None:
    st.markdown('<div class="section-kicker">Controlled defensive response</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Temporary containment</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-note">Temporary source-IP containment is applied by backend policy after the existing suspicious-event threshold.</div>', unsafe_allow_html=True)
    active = data["latest_by_source"][data["latest_by_source"]["currently_blocked"]]
    if active.empty:
        st.info("No active temporary containment. The system continues to observe and assess incoming events.")
    else:
        for row in active.sort_values("risk_score", ascending=False).itertuples():
            block = row.block if isinstance(row.block, dict) else {}
            cols = st.columns(4)
            cols[0].metric("Source", row.source_ip)
            cols[1].metric("Risk", f"{row.risk_score} · {row.risk_level}")
            cols[2].metric("Started", _safe(block.get("first_seen", row.block_first_seen)))
            cols[3].metric("Expires", _safe(block.get("expires_at", row.block_expiry)))
            st.caption(f"Temporary and defensive · {_safe(block.get('reason', row.block_reason))}")
    _render_blocked(data)


def _source_table(data: dict[str, Any]) -> None:
    sources = data["latest_by_source"].copy()
    columns = [
        "source_ip", "approximate_location", "network", "asn", "first_seen", "last_seen",
        "request_count", "risk_score", "cumulative_risk_score", "risk_level", "current_status", "block_reason",
    ]
    display_sources = sources[columns].sort_values(["cumulative_risk_score", "risk_score"], ascending=False, na_position="last")
    selection = st.dataframe(
        display_sources,
        width="stretch", hide_index=True,
        key="source_table",
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "source_ip": "Source IP",
            "approximate_location": "Approximate location",
            "first_seen": "First seen",
            "last_seen": "Last seen",
            "request_count": "Requests",
            "cumulative_risk_score": "Cumulative risk",
            "risk_score": "Latest risk score",
            "risk_level": "Risk level",
            "current_status": "Status / action",
            "block_reason": "Block reason",
        },
    )
    selected_rows = selection.selection.rows
    if selected_rows:
        selected_ip = str(display_sources.iloc[selected_rows[0]]["source_ip"])
        st.button("Open selected source details", on_click=_open_source_details, args=(selected_ip,))


def _open_source_details(source_ip: str) -> None:
    st.session_state["selected_source_ip"] = source_ip
    st.session_state["dashboard_navigation"] = "Details"


def _render_sources(data: dict[str, Any]) -> None:
    st.markdown('<div class="section-kicker">Source intelligence</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Observed sources</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-note">Latest state per source, with approximate network geography where configured.</div>', unsafe_allow_html=True)
    _source_table(data)
    st.markdown('<div class="section-kicker">Risk score by source IP</div>', unsafe_allow_html=True)
    st.bar_chart(data["latest_by_source"].set_index("source_ip")[["risk_score"]], color="#c8a879")


def _render_blocked(data: dict[str, Any]) -> None:
    st.markdown('<div class="section-kicker">Containment</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Blocked sources</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-note">Temporary blocks expire automatically. HIGH requests without an active IP block are listed as rejected attempts below.</div>', unsafe_allow_html=True)
    blocks = data["blocked_sources"]
    if blocks.empty:
        st.info("No temporary IP blocks have been recorded.")
    else:
        now = pd.Timestamp.now(tz="UTC")
        expiry = pd.to_datetime(blocks["block_expiry"], utc=True, errors="coerce")
        blocks = blocks.assign(status=(expiry > now).map({True: "ACTIVE", False: "EXPIRED"}))
        st.dataframe(
            blocks[["source_ip", "risk_score", "block_reason", "block_first_seen", "block_expiry", "status"]]
            .sort_values("block_first_seen", ascending=False),
            width="stretch", hide_index=True,
            column_config={"source_ip": "IP", "risk_score": "Risk score", "block_reason": "Reason",
                           "block_first_seen": "First detected", "block_expiry": "Blocked until", "status": "Status"},
        )

    st.markdown('<div class="section-kicker">Recent blocked attempts</div>', unsafe_allow_html=True)
    attempts = data["recent_blocked"].head(50)
    if attempts.empty:
        st.caption("No rejected requests in the event history.")
    else:
        st.dataframe(
            attempts[["timestamp", "source_ip", "endpoint", "method", "risk_score", "risk_level", "indicators_text", "block_expiry"]],
            width="stretch", hide_index=True,
            column_config={"timestamp": "Timestamp", "source_ip": "Source IP", "endpoint": "Endpoint",
                           "risk_score": "Risk score", "risk_level": "Risk level", "indicators_text": "Matched indicators",
                           "block_expiry": "Block expiry"},
        )


def _render_details(data: dict[str, Any]) -> None:
    sources = data["latest_by_source"]
    st.markdown('<div class="section-kicker">Investigation</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Source detail</div>', unsafe_allow_html=True)
    options = sorted(sources["source_ip"].dropna().astype(str).unique())
    if not options:
        st.info("No sources are available to inspect yet.")
        return
    selected = st.selectbox("Select source IP", options, key="selected_source_ip")
    latest = sources[sources["source_ip"].astype(str) == selected].iloc[-1]
    history = data["events"][data["events"]["source_ip"].astype(str) == selected].sort_values("timestamp_dt")
    geo = latest["source_geo"]
    info_left, info_right = st.columns(2)
    with info_left:
        st.markdown('<div class="section-kicker">IP and network</div>', unsafe_allow_html=True)
        st.write(f"**Source IP:** {selected}")
        st.write(f"**Location:** {latest['approximate_location']}")
        st.write(f"**ASN / network:** {_safe(latest['asn'])} · {_safe(latest['network'])}")
        st.write(f"**First / last seen:** {_safe(latest['first_seen'])} · {_safe(latest['last_seen'])}")
        st.write(f"**Requests / cumulative risk:** {_safe(latest['request_count'])} · {_safe(latest['cumulative_risk_score'])}")
    with info_right:
        st.markdown('<div class="section-kicker">Current decision</div>', unsafe_allow_html=True)
        st.write(f"**Status:** {latest['current_status']}")
        st.write(f"**Risk:** {latest['risk_score']} / 100 · {latest['risk_level']}")
        st.write(f"**Block reason:** {_safe(latest['block_reason'])}")
        st.write(f"**Block expiry:** {_safe(latest['block_expiry'])}")
        st.caption("Geographic estimates are approximate and do not indicate a person's physical location.")

    st.markdown('<div class="section-kicker">Risk progression and request history</div>', unsafe_allow_html=True)
    chart = history.set_index("timestamp_dt")[["risk_score"]]
    st.line_chart(chart, height=230, color="#c8a879")
    st.dataframe(
        history[["timestamp", "method", "endpoint", "risk_score", "risk_level", "indicators_text", "action"]],
        width="stretch", hide_index=True,
    )

    st.markdown('<div class="section-kicker">Attack / behavior timeline</div>', unsafe_allow_html=True)
    for row in history.itertuples():
        action = f" · {row.action}" + (" · IP TEMPORARILY BLOCKED" if row.block else "")
        st.markdown(
            f'<div class="timeline-item"><span class="timeline-time">{_safe(row.timestamp)}</span>'
            f'<span><span class="path-chip">{_safe(row.method)} {_safe(row.endpoint)}</span>'
            f' &nbsp; <span class="risk-label {_risk_class(row.risk_level)}">{_safe(row.risk_level)} · {row.risk_score}</span>'
            f' &nbsp; {_safe(action)}<br><span class="feed-muted">{_safe(row.indicators_text)}</span></span></div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="section-kicker">Indicators and endpoints</div>', unsafe_allow_html=True)
    indicators = history["indicators"].explode().dropna().value_counts()
    endpoints = sorted(history["endpoint"].dropna().astype(str).unique())
    st.write("**Detected indicators**")
    if indicators.empty:
        st.caption("No indicators recorded.")
    else:
        st.dataframe(indicators.rename("count").rename_axis("indicator"), width="stretch")
    st.write("**Endpoints accessed:** " + (", ".join(f"`{endpoint}`" for endpoint in endpoints) if endpoints else "—"))
    observed_commands = []
    for raw in history["details_json"]:
        try:
            command = (json.loads(raw).get("body") or {}).get("command")
            if command:
                observed_commands.append(str(command)[:160])
        except (TypeError, json.JSONDecodeError):
            continue
    st.write("**Observed SSH-style commands:** " + (", ".join(f"`{_safe(command)}`" for command in observed_commands) if observed_commands else "—"))
    latest_ml = history.iloc[-1]["ml"] if isinstance(history.iloc[-1]["ml"], dict) else {}
    if latest_ml:
        st.write(f"**ML behavior label:** {latest_ml.get('label')} · confidence {float(latest_ml.get('confidence', 0)):.0%}")
    deception_changes = [value for value in history["deception_change"] if isinstance(value, dict) and value]
    if deception_changes:
        st.write("**Deception transitions:** " + " · ".join(
            f"{value.get('previous_mode') or 'none'} → {value.get('new_mode')}" for value in deception_changes))

    block_history = history[history["block"].map(bool)]
    st.write("**Block history**")
    if block_history.empty:
        st.caption("No temporary IP block recorded for this source.")
    else:
        block_rows = []
        for block in block_history["block"]:
            block_rows.append({key: block.get(key) for key in ("source_ip", "risk_score", "reason", "first_seen", "last_seen", "expires_at")})
        st.dataframe(pd.DataFrame(block_rows), width="stretch", hide_index=True)


def _render_agent(data: dict[str, Any]) -> None:
    events = data["events"].sort_values("timestamp_dt")
    latest = events.iloc[-1]
    ml = latest["ml"] if isinstance(latest["ml"], dict) else {}
    st.markdown('<div class="section-kicker">AI security agent</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Evidence-led behavior assessment</div>', unsafe_allow_html=True)
    agent = _load_agent_status(API_URL)
    st.markdown(f'<div class="section-note">AI MODE: {_safe(str(agent.get("agent_mode", "local")).upper())}. '
        'Random Forest and clustering are triage hints, not ground truth. The LLM can return recommendations only; '
        'the backend policy remains the authority and no shell tools are available.</div>', unsafe_allow_html=True)
    assessment = agent.get("latest_assessment")
    if assessment:
        st.info(f"Latest agent assessment · {_safe(assessment.get('agent_mode', 'local')).upper()} · "
                f"{_safe(assessment.get('threat_type', 'unknown'))} · "
                f"{_safe(assessment.get('evidence_summary', assessment.get('reason', 'No summary')))}")
    cols = st.columns(4)
    for col, (label, value) in zip(cols, (("STATUS", "ONLINE"), ("CLASS", ml.get("label", "Unavailable")),
                                          ("CONFIDENCE", f"{float(ml.get('confidence', 0)):.0%}"),
                                          ("CURRENT RISK", f"{int(latest['risk_score'])} · {latest['risk_level']}"))):
        with col:
            st.metric(label, value)
    st.markdown('<div class="section-kicker">Latest evidence and response</div>', unsafe_allow_html=True)
    evidence = latest["indicators"] if isinstance(latest["indicators"], list) else []
    if evidence:
        for item in evidence:
            st.markdown(f"- {_safe(item)}")
    else:
        st.caption("No suspicious indicators in the latest interaction.")
    deception = latest["deception_change"] if isinstance(latest["deception_change"], dict) else {}
    st.write(f"**Recommended response:** {latest['action']} · **Deception mode:** {deception.get('new_mode', 'current mode unchanged')}")
    st.write(f"**Evidence summary:** {int(latest['risk_score'])}/100 from {len(events)} logged interactions for this source.")
    st.markdown('<div class="section-kicker">Recent decisions</div>', unsafe_allow_html=True)
    st.dataframe(events.sort_values("timestamp_dt", ascending=False).head(30)[
        ["timestamp", "source_ip", "endpoint", "risk_score", "risk_level", "action", "indicators_text"]
    ], width="stretch", hide_index=True)


def _new_live_demo_runtime() -> dict[str, Any]:
    """Create a session-only risk run using the same analyzer and response policy classes."""
    medium = int(os.environ.get("RISK_THRESHOLD_MEDIUM", "30"))
    high = int(os.environ.get("RISK_THRESHOLD_HIGH", "60"))
    critical = int(os.environ.get("RISK_THRESHOLD_CRITICAL", "80"))
    minimum = max(3, int(os.environ.get("MIN_SUSPICIOUS_EVENTS", "3")))
    auth_threshold = max(3, minimum, int(os.environ.get("HONEYPOT_AUTH_BLOCK_AFTER", "3")))
    high_threshold = max(3, minimum, int(os.environ.get("HONEYPOT_BLOCK_AFTER_HIGH_RISK", "3")))
    duration = int(os.environ.get("HONEYPOT_BLOCK_DURATION_SECONDS", os.environ.get("CONTAINMENT_DURATION", "300")))
    manager = RiskResponseManager(
        store=InMemoryRiskStore(),
        block_duration_seconds=duration,
        auth_block_after=auth_threshold,
        block_after_high_risk=high_threshold,
        min_suspicious_events_before_containment=minimum,
        medium_risk_threshold=medium,
        high_risk_threshold=high,
        critical_risk_threshold=critical,
    )
    return {"manager": manager, "analyzer": RuleBasedAnalyzer(
        medium_threshold=medium, high_threshold=high, critical_threshold=critical),
        "events": [], "last_attempt_monotonic": 0.0}


def _advance_live_demo(runtime: dict[str, Any]) -> None:
    """Advance the synthetic failed-login sequence through the production policy."""
    manager: RiskResponseManager = runtime["manager"]
    history: list[dict[str, Any]] = runtime["events"]
    if history and (history[-1]["block"] or len(history) >= manager.auth_block_after):
        return
    now = time.monotonic()
    if history and now - runtime["last_attempt_monotonic"] < 2.0:
        return

    attempt = len(history) + 1
    features = extract_behavior_features(
        "POST", "/login", "AI-Honeybot-Live-Demo/1.0", {},
        prior_requests_from_ip=len(history), authentication_failed=True,
    )
    baseline = runtime["analyzer"].analyze(features)
    evaluated_at = datetime.now(timezone.utc)
    result = manager.evaluate(
        "203.0.113.10", "/login", "POST", baseline, features,
        authentication_failed=True, now=evaluated_at,
    )
    history.append({
        "attempt": attempt,
        "source_ip": "203.0.113.10",
        "timestamp": evaluated_at.isoformat(),
        "activity": "Simulated failed sign-in against the honeypot decoy",
        "risk_score": result["risk_score"],
        # The demo presents the requested three-tier scale; CRITICAL is grouped
        # into HIGH while the exact score and production decision remain intact.
        "risk_level": "HIGH" if result["risk_level"] == "CRITICAL" else result["risk_level"],
        "indicators": result["indicators"],
        "action": result["action"],
        "block": result["block"],
        "source_risk": result["source_risk"],
    })
    runtime["last_attempt_monotonic"] = now


def _render_live_demo_panel(runtime: dict[str, Any]) -> None:
    _advance_live_demo(runtime)
    history: list[dict[str, Any]] = runtime["events"]
    last = history[-1] if history else None
    blocked = bool(last and last["block"])
    ip = "203.0.113.10"
    score = int(last["risk_score"]) if last else 0
    level = str(last["risk_level"]) if last else "LOW"
    if level == "CRITICAL":
        level = "HIGH"
    manager: RiskResponseManager = runtime["manager"]
    target = manager.auth_block_after
    st.markdown('<div class="section-kicker">Live demo · synthetic traffic only</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Honeypot response simulation</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-note">A session-local run uses the existing rule analyzer and temporary containment policy. No packets are sent and no project events or database rows are written.</div>', unsafe_allow_html=True)

    kpis = (("Source IP", ip), ("Attempts", f"{len(history)} / {target}"),
            ("Risk score", f"{score} / 100"), ("Risk level", level),
            ("Block status", "TEMPORARY BLOCK" if blocked else "NOT BLOCKED"))
    kpi_markup = "".join(
        f'<div class="demo-kpi"><div class="demo-kpi-label">{_safe(label)}</div>'
        f'<div class="demo-kpi-value">{_safe(value)}</div></div>' for label, value in kpis
    )
    st.markdown(f'<div class="demo-kpis">{kpi_markup}</div>', unsafe_allow_html=True)

    completed_steps = 0 if not history else (3 + max(0, (len(history) - 1) * 2))
    if blocked:
        completed_steps = 8
    steps = ("Attack attempt 1", "IP captured", "Risk updated", "Attack attempt 2",
             "Risk increased", "Attack attempt 3", "High risk", "Temporary block")
    step_markup = []
    for index, step in enumerate(steps):
        state_class = "demo-step-done" if index < completed_steps else "demo-step-active" if index == completed_steps else ""
        step_markup.append(f'<span class="demo-step {state_class}">{_safe(step)}</span>')
        if index < len(steps) - 1:
            step_markup.append('<span class="flow-arrow">→</span>')
    st.markdown(f'<div class="demo-flow">{"".join(step_markup)}</div>', unsafe_allow_html=True)

    st.markdown('<div class="section-kicker">Simulated event log</div>', unsafe_allow_html=True)
    if not history:
        st.caption("Preparing the first synthetic attempt…")
    for event in reversed(history):
        risk_class = {"LOW": "demo-risk-low", "MEDIUM": "demo-risk-medium"}.get(event["risk_level"], "demo-risk-high")
        st.markdown(
            f'<div class="demo-event"><span class="demo-attempt">Attempt {event["attempt"]}</span>'
            f'<span class="demo-event-copy">{_safe(event["activity"])} · {_safe(event["action"])} · {_safe(event["risk_score"])} / 100</span>'
            f'<span class="demo-risk {risk_class}">{_safe(event["risk_level"])}</span></div>'
            f'<div class="demo-timestamp">{_safe(event["timestamp"])} · {_safe("; ".join(event["indicators"]) or "No suspicious indicators")}</div>',
            unsafe_allow_html=True,
        )
    if blocked and last:
        st.markdown('<div class="demo-threat-alert"><strong>Threat detected — source temporarily blocked due to repeated suspicious activity.</strong></div>', unsafe_allow_html=True)
        st.caption(f"Containment reason: {_safe(last['block']['reason'])} · Expires: {_safe(last['block']['expires_at'])}")
    elif last and len(history) >= 3 and level == "HIGH":
        st.info("High risk reached. The configured attempt threshold has not yet been met; monitoring continues.")

    action_col, back_col = st.columns([1, 1])
    with action_col:
        if st.button("↻  RESTART LIVE DEMO", key="restart_live_demo"):
            st.session_state["live_demo_runtime"] = _new_live_demo_runtime()
            st.rerun()
    with back_col:
        if st.button("←  BACK TO COMMAND CENTER", key="leave_live_demo"):
            st.session_state["dashboard_navigation"] = "Overview"
            st.rerun()


@st.fragment(run_every=1)
def render_live_demo() -> None:
    runtime = st.session_state.get("live_demo_runtime")
    if runtime is None:
        runtime = _new_live_demo_runtime()
        st.session_state["live_demo_runtime"] = runtime
    _render_live_demo_panel(runtime)


st.markdown(
    '<div class="brand-row"><div><div class="brand-name"><span class="brand-mark">◈</span>AI—HONEYBOT</div>'
    '<div class="brand-tagline">Detect. Understand. Contain.</div></div>'
    '<div class="status-stack"><div class="live-pill"><span class="live-dot"></span>LIVE VIEW</div>'
    '<div class="monitor-copy">LOCAL EVENT FEED · AUTO-REFRESH EVERY 5 SECONDS</div></div></div>',
    unsafe_allow_html=True,
)
_render_hero()
st.radio("Dashboard navigation", NAVIGATION, horizontal=True, label_visibility="collapsed", key="dashboard_navigation")


@st.fragment(run_every=5)
def render_live_dashboard() -> None:
    try:
        modified = EVENTS_FILE.stat().st_mtime
    except OSError:
        modified = 0.0
    data = prepare_dashboard_data(load_events(str(EVENTS_FILE), modified))
    summary = data["summary"]
    st.markdown('<div class="section-kicker">Security command center</div><div class="section-title">Operational overview</div>', unsafe_allow_html=True)
    _metric_cards(summary)
    if st.session_state.get("dashboard_navigation", "Overview") != "Overview":
        _status_chips(data)
    st.markdown('<div style="height:1.7rem"></div>', unsafe_allow_html=True)

    view = st.session_state.get("dashboard_navigation", "Overview")
    if data["events"].empty:
        st.markdown('<div class="section-title">No interactions recorded</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-note">Start the local Flask service and visit http://127.0.0.1:5000 to populate this view.</div>', unsafe_allow_html=True)
    elif view == "Overview":
        _render_overview(data)
    elif view == "Threats":
        _render_overview(data)
    elif view == "Attackers":
        _render_sources(data)
    elif view == "Containment":
        _render_containment(data)
    elif view == "AI Analysis":
        _render_agent(data)
    elif view == "Deception":
        _render_deception(data)
    else:
        _render_details(data)

    st.markdown(
        f'<div class="footer-line"><span>AI—HONEYBOT · LOCAL DEFENSIVE MONITOR</span>'
        f'<span>Event log: {_safe(EVENTS_FILE)}</span></div>',
        unsafe_allow_html=True,
    )


if st.session_state.get("dashboard_navigation") == "Live Demo":
    render_live_demo()
else:
    render_live_dashboard()
