"""Public WSGI entry point for the decoy-only hosted demonstration.

This gate intentionally keeps the Flask/FastAPI analyst APIs private. It also
uses Render's Cloudflare client-IP header (never X-Forwarded-For) for request
attribution and applies in-memory request ceilings before entering the app.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from ipaddress import ip_address
from typing import Callable, Iterable

from app import app as honeypot_app

_WINDOW_SECONDS = 60.0
_PER_IP_LIMIT = 60
_GLOBAL_LIMIT = 300
_MAX_TRACKED_IPS = 4096
_lock = threading.Lock()
_recent_by_ip: dict[str, deque[float]] = {}
_recent_global: deque[float] = deque()
_last_cleanup = 0.0

_PRIVATE_ROOTS = {"api", "docs", "redoc", "openapi.json", "dashboard", "metrics"}
_ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "TRACE", "OPTIONS"}
_SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
]

_PUBLIC_DASHBOARD = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#080d18"><title>AI Honeybot · Public Demo</title>
<style>
:root{color-scheme:dark;--bg:#080d18;--panel:#101a2a;--line:#24334a;--text:#edf4ff;--muted:#91a2bb;--blue:#68a8ff;--cyan:#57dfd0;--red:#ff7588;--amber:#f9c96b}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 70% -10%,#16335a 0,transparent 42%),var(--bg);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:#9ccaff;text-decoration:none}a:hover{text-decoration:underline}.wrap{max-width:1180px;margin:auto;padding:28px 24px 56px}.top{display:flex;justify-content:space-between;align-items:center;gap:18px;border-bottom:1px solid var(--line);padding-bottom:18px}.brand{font-weight:800;letter-spacing:.04em}.brand b{color:var(--blue);font-size:1.3rem;margin-right:9px}.badge{border:1px solid #3f755e;color:#8df0bd;background:#10271f;border-radius:999px;padding:6px 11px;font-size:.72rem;letter-spacing:.1em}.hero{padding:45px 0 24px}.kicker{color:var(--cyan);font-size:.72rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase}.hero h1{font-size:clamp(2.2rem,6vw,4.2rem);line-height:1.04;letter-spacing:-.06em;margin:12px 0}.hero p{max-width:690px;color:#b5c4d9;font-size:1.05rem}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}.btn{display:inline-block;padding:10px 15px;border-radius:10px;background:#235da0;color:white;font-weight:700;border:1px solid #4984ca;cursor:pointer}.btn.secondary{background:#121c2d;border-color:#30445f;color:#c9d8ec}.notice{margin:14px 0 22px;padding:12px 15px;border:1px solid #29415e;border-left:3px solid var(--amber);border-radius:10px;color:#c7d5e7;background:#101a29;font-size:.9rem}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px}.card{border:1px solid var(--line);border-radius:14px;background:linear-gradient(145deg,#111d30,#0d1523);padding:17px}.label{color:var(--muted);font-size:.7rem;letter-spacing:.12em;text-transform:uppercase}.value{font-size:1.8rem;font-weight:750;letter-spacing:-.04em;margin-top:5px}.hint{color:#8193ad;font-size:.78rem;margin-top:2px}.section{margin-top:22px}.section-head{display:flex;align-items:end;justify-content:space-between;gap:12px;margin-bottom:10px}.section h2{font-size:1.05rem;margin:0}.section-head span{font-size:.75rem;color:var(--muted)}.cols{display:grid;grid-template-columns:1fr 1.15fr;gap:14px}.bars{display:grid;gap:13px;margin-top:14px}.barline{display:grid;grid-template-columns:90px 1fr 25px;gap:10px;align-items:center;color:#bfcee2;font-size:.82rem}.track{height:9px;background:#1d2b40;border-radius:9px;overflow:hidden}.fill{height:100%;border-radius:9px;background:linear-gradient(90deg,#447dd0,#68b9ff)}.fill.medium{background:linear-gradient(90deg,#9272d6,#c7a2ff)}.fill.high{background:linear-gradient(90deg,#d26a79,#ff9a8b)}.fill.critical{background:linear-gradient(90deg,#cf405b,#ff7189)}.flow{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}.step{border:1px solid #2b405b;color:#c0d4ed;border-radius:999px;padding:6px 10px;font-size:.72rem}.events{display:grid;gap:8px}.event{display:grid;grid-template-columns:130px 1fr auto;gap:12px;align-items:center;border:1px solid #1f2d42;background:#0b1320;border-radius:10px;padding:11px 12px;font-size:.82rem}.ip{color:#89baff;font-variant-numeric:tabular-nums}.path{color:#d5e0ef}.risk{font-size:.65rem;letter-spacing:.1em;border-radius:999px;padding:4px 8px;border:1px solid #38587d;color:#a9d0ff}.risk.MEDIUM{color:#d3baff;border-color:#67508a}.risk.HIGH{color:#ffb7aa;border-color:#8a4a4b}.risk.CRITICAL{color:#ff9da9;border-color:#a74258}.foot{margin-top:28px;padding-top:17px;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;color:#8293aa;font-size:.78rem}.map{height:154px;position:relative;overflow:hidden;border-radius:10px;background:radial-gradient(ellipse at 28% 45%,#1b3958 0 12%,transparent 13%),radial-gradient(ellipse at 68% 40%,#183856 0 18%,transparent 19%),radial-gradient(ellipse at 83% 72%,#20324b 0 8%,transparent 9%),linear-gradient(135deg,#0a1421,#111d2c)}.dot{position:absolute;width:9px;height:9px;border-radius:50%;background:var(--red);box-shadow:0 0 0 7px #ff758822,0 0 18px var(--red)}.d1{left:28%;top:38%}.d2{left:56%;top:59%;background:var(--amber);box-shadow:0 0 0 7px #f9c96b22,0 0 18px var(--amber)}.d3{left:71%;top:31%}.mapnote{margin-top:9px;color:#8496ae;font-size:.73rem}
@media(max-width:760px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.cols{grid-template-columns:1fr}.hero{padding-top:30px}}@media(max-width:480px){.wrap{padding:18px 14px 40px}.event{grid-template-columns:1fr auto;gap:5px}.ip{grid-column:1/-1}.barline{grid-template-columns:78px 1fr 20px}}
</style></head><body><main class="wrap">
<header class="top"><div class="brand"><b>◈</b>AI—HONEYBOT</div><span class="badge">PUBLIC SYNTHETIC DEMO</span></header>
<section class="hero"><div class="kicker">Defensive security prototype</div><h1>Adaptive honeypot<br>command center</h1>
<p>A safe, interactive preview of request scoring, behavior signals, deception, and temporary containment. Every event below is fictional demo data; this page does not read the live event store or send requests to the backend.</p>
<div class="actions"><button class="btn" id="play">▶ Play synthetic attack sequence</button><a class="btn secondary" href="/login">Open decoy sign-in</a><a class="btn secondary" href="https://github.com/manya-pri/AI-honeybot">View source on GitHub</a></div></section>
<div class="notice"><strong>Demo only.</strong> The simulated feed is generated in your browser and is not real attacker intelligence. The decoy sign-in is separate; never enter real credentials.</div>
<section class="grid" aria-label="Synthetic demo metrics"><article class="card"><div class="label">Demo events</div><div class="value" id="events">6</div><div class="hint">Synthetic sequence</div></article><article class="card"><div class="label">Demo sources</div><div class="value">3</div><div class="hint">Fictional test-network IPs</div></article><article class="card"><div class="label">High risk</div><div class="value" id="high">3</div><div class="hint">Illustrative rule scores</div></article><article class="card"><div class="label">Containment</div><div class="value" id="blocked">1</div><div class="hint">Simulated temporary response</div></article></section>
<div class="cols section"><section class="card"><div class="section-head"><h2>Risk signal distribution</h2><span>synthetic fixture</span></div><div class="bars"><div class="barline"><span>LOW</span><div class="track"><div class="fill" style="width:38%"></div></div><b>2</b></div><div class="barline"><span>MEDIUM</span><div class="track"><div class="fill medium" style="width:25%"></div></div><b>1</b></div><div class="barline"><span>HIGH</span><div class="track"><div class="fill high" style="width:52%"></div></div><b>2</b></div><div class="barline"><span>CRITICAL</span><div class="track"><div class="fill critical" style="width:26%"></div></div><b>1</b></div></div><div class="flow"><span class="step">Request observed</span><span class="step">Features scored</span><span class="step">Decoy adapted</span><span class="step">Policy evaluated</span></div></section>
<section class="card"><div class="section-head"><h2>Source activity map</h2><span>fictional markers</span></div><div class="map" role="img" aria-label="Abstract illustration with fictional source markers"><i class="dot d1"></i><i class="dot d2"></i><i class="dot d3"></i></div><div class="mapnote">Illustrative only · no geolocation or live IP lookup</div></section></div>
<section class="section"><div class="section-head"><h2>Recent synthetic events</h2><span id="feedState">DEMO DATA · SIMULATION ONLY</span></div><div class="events" id="feed" aria-live="polite">
<div class="event"><span class="ip">203.0.113.24</span><span class="path">GET /</span><span class="risk LOW">LOW · 0</span></div>
<div class="event"><span class="ip">203.0.113.24</span><span class="path">GET /login</span><span class="risk MEDIUM">MEDIUM · 30</span></div>
<div class="event"><span class="ip">198.51.100.42</span><span class="path">GET /.env</span><span class="risk HIGH">HIGH · 72</span></div>
<div class="event"><span class="ip">198.51.100.42</span><span class="path">POST /login</span><span class="risk HIGH">HIGH · 78</span></div>
<div class="event"><span class="ip">192.0.2.17</span><span class="path">GET /admin</span><span class="risk MEDIUM">MEDIUM · 45</span></div>
<div class="event"><span class="ip">198.51.100.42</span><span class="path">POST /login · simulated block</span><span class="risk CRITICAL">CRITICAL · 92</span></div></div></section>
<footer class="foot"><span>Local prototype · synthetic preview · no live records shown</span><span><a href="https://github.com/manya-pri/AI-honeybot">GitHub source</a> · <a href="/login">Decoy surface</a></span></footer>
</main><script>
const sequence=[
 {ip:"203.0.113.31",path:"GET /",risk:"LOW",score:0},
 {ip:"203.0.113.31",path:"GET /login",risk:"MEDIUM",score:30},
 {ip:"203.0.113.31",path:"POST /login · synthetic failure",risk:"HIGH",score:64},
 {ip:"203.0.113.31",path:"GET /.env",risk:"HIGH",score:78},
 {ip:"203.0.113.31",path:"POST /login · simulated block",risk:"CRITICAL",score:92}
];let run=0;
document.getElementById("play").addEventListener("click",()=>{run++;const feed=document.getElementById("feed");feed.replaceChildren();sequence.forEach((event,index)=>{const row=document.createElement("div");row.className="event";const ip=document.createElement("span");ip.className="ip";ip.textContent=event.ip;const path=document.createElement("span");path.className="path";path.textContent=event.path;const risk=document.createElement("span");risk.className="risk "+event.risk;risk.textContent=event.risk+" · "+event.score;row.append(ip,path,risk);setTimeout(()=>feed.prepend(row),index*420)});document.getElementById("events").textContent=String(6+sequence.length*run);document.getElementById("high").textContent=String(3+3*run);document.getElementById("blocked").textContent=String(1+run);document.getElementById("feedState").textContent="SIMULATED IN THIS BROWSER · NO NETWORK REQUESTS";});
</script></body></html>"""


def _send(start_response: Callable, status: str, body: str) -> list[bytes]:
    encoded = body.encode("utf-8")
    start_response(status, [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(encoded))),
        ("Cache-Control", "no-store"),
        *_SECURITY_HEADERS,
    ])
    return [encoded]


def _send_dashboard(start_response: Callable) -> list[bytes]:
    encoded = _PUBLIC_DASHBOARD.encode("utf-8")
    start_response("200 OK", [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Length", str(len(encoded))),
        ("Cache-Control", "no-store"),
        *_SECURITY_HEADERS,
    ])
    return [encoded]


def _client_ip(environ: dict) -> str:
    # Render's edge sets CF-Connecting-IP. Do not use X-Forwarded-For: client
    # supplied values can be preserved by some proxy chains.
    candidate = (environ.get("HTTP_CF_CONNECTING_IP") or environ.get("REMOTE_ADDR") or "unknown").strip()
    try:
        return str(ip_address(candidate))
    except ValueError:
        return "unknown"


def _limited(client: str, now: float) -> bool:
    global _last_cleanup
    cutoff = now - _WINDOW_SECONDS
    with _lock:
        while _recent_global and _recent_global[0] <= cutoff:
            _recent_global.popleft()

        if now - _last_cleanup >= _WINDOW_SECONDS:
            for source, history in list(_recent_by_ip.items()):
                while history and history[0] <= cutoff:
                    history.popleft()
                if not history:
                    del _recent_by_ip[source]
            _last_cleanup = now

        history = _recent_by_ip.get(client)
        if history is None:
            if len(_recent_by_ip) >= _MAX_TRACKED_IPS:
                return True
            history = _recent_by_ip[client] = deque()
        while history and history[0] <= cutoff:
            history.popleft()

        if len(history) >= _PER_IP_LIMIT or len(_recent_global) >= _GLOBAL_LIMIT:
            return True
        history.append(now)
        _recent_global.append(now)
        return False


def _with_security_headers(start_response: Callable) -> Callable:
    def secured(status: str, headers: list[tuple[str, str]], exc_info=None):
        existing = {name.lower() for name, _value in headers}
        headers.extend((name, value) for name, value in _SECURITY_HEADERS if name.lower() not in existing)
        return start_response(status, headers, exc_info)

    return secured


def application(environ: dict, start_response: Callable) -> Iterable[bytes]:
    path = environ.get("PATH_INFO", "/") or "/"
    segments = [segment.casefold() for segment in path.split("/") if segment and segment not in {".", ".."}]
    first_segment = segments[0] if segments else ""

    if path == "/healthz" and environ.get("REQUEST_METHOD", "GET").upper() == "GET":
        return _send(start_response, "200 OK", "ok\n")
    if first_segment in _PRIVATE_ROOTS:
        return _send(start_response, "404 Not Found", "Not found\n")
    if environ.get("REQUEST_METHOD", "GET").upper() not in _ALLOWED_METHODS:
        return _send(start_response, "405 Method Not Allowed", "Method not allowed\n")
    if _limited(_client_ip(environ), time.monotonic()):
        return _send(start_response, "429 Too Many Requests", "Rate limit exceeded\n")
    if path in {"/", "/demo"} and environ.get("REQUEST_METHOD", "GET").upper() in {"GET", "HEAD"}:
        return _send_dashboard(start_response)

    # The source address is replaced with the validated edge address so the
    # existing event logger and temporary containment policy see the requester.
    public_environ = dict(environ)
    public_environ["REMOTE_ADDR"] = _client_ip(environ)
    return honeypot_app(public_environ, _with_security_headers(start_response))


app = application
