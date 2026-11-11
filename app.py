"""Local-only Flask honeypot demonstration. Run with ``python app.py``."""

from __future__ import annotations

import json
import os
import threading
import uuid
from ipaddress import ip_address
from collections import Counter
from functools import lru_cache
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from agent import agent_status as get_agent_status, assess as agent_assess
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from analyzer import AnomalyDetector, RuleBasedAnalyzer, extract_behavior_features
from geo_enrichment import GeoIPEnricher, MaxMindGeoIPEnricher, enrich_source_ip
from risk_response import RiskResponseManager
from database import HoneybotDatabase, SQLiteRiskStore
from behaviour import engineer_features
from ml_engine import FEATURE_ORDER, get_model
from deception import synthetic_admin, synthetic_endpoint, transition as deception_transition
from ssh_honeypot import fake_ssh_login, fake_ssh_session

load_dotenv()

app = Flask(__name__)
if os.environ.get("HONEYPOT_TRUST_PROXY", "false").lower() == "true":
    # Enable only for the private Docker bridge where Nginx overwrites client IP headers.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
# Future detector plugins can implement AnomalyDetector and be assigned here.
# The MVP deliberately leaves this unset: no trained ML model is included.
app.config["ANOMALY_DETECTOR"] = None
# Set a GeoIPEnricher here for tests/custom local providers, or configure the
# optional local MMDB paths through environment variables.
app.config["GEO_ENRICHER"] = None
_database_url = os.environ.get("DATABASE_URL", "sqlite:///data/honeybot.sqlite")
if not _database_url.startswith("sqlite:///"):
    raise RuntimeError("This build supports SQLite DATABASE_URL values only.")
DATABASE_PATH = os.environ.get("HONEYPOT_DATABASE", _database_url.removeprefix("sqlite:///"))
DATABASE = HoneybotDatabase(DATABASE_PATH)
app.config["DATABASE"] = DATABASE
MEDIUM_THRESHOLD = int(os.environ.get("RISK_THRESHOLD_MEDIUM", "30"))
HIGH_THRESHOLD = int(os.environ.get("RISK_THRESHOLD_HIGH", "60"))
CRITICAL_THRESHOLD = int(os.environ.get("RISK_THRESHOLD_CRITICAL", "80"))
app.config["RULE_ANALYZER"] = RuleBasedAnalyzer(medium_threshold=MEDIUM_THRESHOLD,
    high_threshold=HIGH_THRESHOLD, critical_threshold=CRITICAL_THRESHOLD)
app.config["RISK_RESPONSE_MANAGER"] = RiskResponseManager(
    store=SQLiteRiskStore(DATABASE),
    block_duration_seconds=int(os.environ.get("HONEYPOT_BLOCK_DURATION_SECONDS", os.environ.get("CONTAINMENT_DURATION", "300"))),
    block_after_high_risk=max(3, int(os.environ.get("MIN_SUSPICIOUS_EVENTS", "3")),
                              int(os.environ.get("HONEYPOT_BLOCK_AFTER_HIGH_RISK", "3"))),
    auth_block_after=max(3, int(os.environ.get("MIN_SUSPICIOUS_EVENTS", "3")),
                         int(os.environ.get("HONEYPOT_AUTH_BLOCK_AFTER", "3"))),
    min_suspicious_events_before_containment=max(3, int(os.environ.get("MIN_SUSPICIOUS_EVENTS", "3"))),
    medium_risk_threshold=MEDIUM_THRESHOLD, high_risk_threshold=HIGH_THRESHOLD,
    critical_risk_threshold=CRITICAL_THRESHOLD,
)
EVENTS_FILE = Path(os.environ.get("HONEYPOT_EVENTS_FILE", "data/events.jsonl"))
_write_lock = threading.Lock()
_counts_lock = threading.Lock()
_ip_counts: dict[str, int] = {}
_SENSITIVE_KEYS = {"password", "passwd", "pwd", "token", "secret", "authorization", "credential"}


@lru_cache(maxsize=4)
def _local_geo_enricher(city_database: str, asn_database: str) -> GeoIPEnricher | None:
    if not city_database and not asn_database:
        return None
    try:
        return MaxMindGeoIPEnricher(city_database or None, asn_database or None)
    except Exception as error:
        app.logger.warning("Optional local GeoIP enrichment unavailable (%s).", type(error).__name__)
        return None


def _configured_geo_enricher() -> GeoIPEnricher | None:
    configured = app.config.get("GEO_ENRICHER")
    if configured is not None:
        return configured
    city_database = os.environ.get("HONEYPOT_GEOIP_CITY_DB", "")
    asn_database = os.environ.get("HONEYPOT_GEOIP_ASN_DB", "")
    return _local_geo_enricher(city_database, asn_database)


def _safe_mapping(values: Any) -> dict[str, Any]:
    """Bound captured fields and mask values under credential-like keys."""
    safe: dict[str, Any] = {}
    for index, (key, value) in enumerate(values.items()):
        if index >= 50:
            safe["_truncated"] = True
            break
        clean_key = str(key)[:100]
        is_sensitive = any(marker in clean_key.lower() for marker in _SENSITIVE_KEYS)
        if is_sensitive:
            safe[clean_key] = "[REDACTED]"
        elif isinstance(value, (list, tuple)):
            safe[clean_key] = [str(item)[:500] for item in value[:10]]
        else:
            safe[clean_key] = str(value)[:500]
    return safe


def _request_details() -> dict[str, Any]:
    details: dict[str, Any] = {"query": _safe_mapping(request.args)}
    if request.is_json:
        body = request.get_json(silent=True)
        details["body"] = _safe_mapping(body) if isinstance(body, dict) else {"type": "json"}
    elif request.form:
        details["body"] = _safe_mapping(request.form)
    elif request.get_data(cache=True):
        # Never store arbitrary raw bodies; retain only size and content type.
        details["body"] = {"type": request.mimetype or "unknown", "bytes": request.content_length or 0}
    return details


def _record_interaction(*, authentication_failed: bool = False) -> dict[str, Any]:
    source_ip = request.remote_addr or "unknown"
    with _counts_lock:
        prior = _ip_counts.get(source_ip, 0)
        _ip_counts[source_ip] = prior + 1
    details = _request_details()
    features = extract_behavior_features(
        request.method, request.path, request.headers.get("User-Agent", ""), details, prior,
        authentication_failed=authentication_failed,
    )
    # Keep the existing transparent rules as the active baseline. An optional
    # future detector receives the same feature contract and remains separate.
    analysis = app.config["RULE_ANALYZER"].analyze(features)
    detector: AnomalyDetector | None = app.config.get("ANOMALY_DETECTOR")
    anomaly = None
    if detector is not None:
        anomaly_score = float(detector.score(features))
        if not 0.0 <= anomaly_score <= 1.0:
            raise ValueError("AnomalyDetector.score must return a value from 0 to 1.")
        anomaly = {"score": anomaly_score, "detector": type(detector).__name__}
    try:
        response = app.config["RISK_RESPONSE_MANAGER"].evaluate(
        source_ip=source_ip,
        endpoint=request.path[:500],
        method=request.method,
        baseline_risk=analysis,
        features=features,
        authentication_failed=authentication_failed,
        )
    except Exception as error:
        app.logger.error("Persistent risk store unavailable; using safe in-memory fallback (%s).", type(error).__name__)
        fallback = app.config.setdefault("RISK_FALLBACK_MANAGER", RiskResponseManager(
            block_after_high_risk=3, auth_block_after=3,
            block_duration_seconds=int(os.environ.get("HONEYPOT_BLOCK_DURATION_SECONDS", os.environ.get("CONTAINMENT_DURATION", "300"))),
            medium_risk_threshold=MEDIUM_THRESHOLD, high_risk_threshold=HIGH_THRESHOLD,
            critical_risk_threshold=CRITICAL_THRESHOLD,
            min_suspicious_events_before_containment=max(3, int(os.environ.get("MIN_SUSPICIOUS_EVENTS", "3")))))
        response = fallback.evaluate(source_ip, request.path[:500], request.method, analysis, features,
                                     authentication_failed=authentication_failed)
    deception_change = None
    try:
        database = app.config["DATABASE"]
        previous_deception = database.get_deception(source_ip)
        deception_change = deception_transition(previous_deception, response["risk_score"])
        if deception_change:
            deception_change["timestamp"] = datetime.now(timezone.utc).isoformat()
            database.set_deception(source_ip, deception_change["new_mode"], deception_change["timestamp"], deception_change["reason"])
    except Exception as error:
        app.logger.warning("Deception memory unavailable (%s).", type(error).__name__)
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "service": "ssh" if request.path.startswith("/ssh/") else "http",
        "event_type": "login_attempt" if request.path.rstrip("/") in {"/login", "/ssh/login"} and request.method == "POST"
                     else "command_observed" if request.path.rstrip("/") == "/ssh/session"
                     else "decoy_access" if request.path.lower() in {"/.env", "/credentials.txt", "/database_backup.sql", "/api_keys.txt", "/admin_config.json", "/fake_customer_records.csv"}
                     else "http_request",
        "source_geo": enrich_source_ip(source_ip, _configured_geo_enricher()),
        "method": request.method,
        "endpoint": request.path[:500],
        "user_agent": request.headers.get("User-Agent", "")[:500],
        "details": details,
        "features": features,
        "baseline_risk": analysis,
        "risk": {
            "score": response["risk_score"],
            "level": response["risk_level"],
            "indicators": response["indicators"],
        },
        "action": response["action"],
        "source_risk": response["source_risk"],
        "block": response["block"],
        "block_expiry": (response["block"] or {}).get("expires_at"),
        "anomaly": anomaly,
        "deception_change": deception_change,
    }
    try:
        prior_history = app.config["DATABASE"].list_events(limit=200, source_ip=source_ip)
        model = get_model()
        event["ml"] = model.classify(engineer_features(prior_history + [event]))
        app.config["DATABASE"].record_model_version(
            "rf-synthetic-v1" if getattr(model, "algorithm", "").startswith("RandomForest") else "rule-fallback-v1",
            getattr(model, "algorithm", "transparent-rule-fallback"), datetime.now(timezone.utc).isoformat(),
            getattr(model, "training_data", "not applicable"), FEATURE_ORDER)
    except Exception as error:
        app.logger.warning("Optional ML classification unavailable (%s).", type(error).__name__)
        event["ml"] = {"label": "unavailable", "confidence": 0.0, "model": None}
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        app.config["DATABASE"].save_event(event)
    except Exception as error:
        app.logger.error("SQLite event/profile persistence unavailable (%s); JSONL remains available.", type(error).__name__)
    with _write_lock, EVENTS_FILE.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=True) + "\n")
    return event


@app.before_request
def capture_request() -> tuple[str, int] | None:
    # The route's decoy response determines whether an auth attempt failed, so
    # record POST /login in the view once its outcome is known.
    if request.path.rstrip("/") in {"/login", "/ssh/login", "/ssh/session"} and request.method == "POST":
        return None
    event = _record_interaction()
    if event["action"] == "BLOCKED":
        return "Request blocked by AI-Honeybot", 403


@app.get("/")
def index():
    return """<!doctype html><title>Northstar Portal · AI-Honeybot demo</title><h1>Northstar Portal</h1>
    <p>Welcome to the fictional portal used by the AI-Honeybot security demo.
    <a href='/login'>Open the decoy sign-in</a></p>
    <hr><p><strong>Security research demonstration.</strong> This is not a real account portal.
    Do not submit real credentials. Requests and basic connection details may be recorded
    for defensive analysis.</p><p><a href='https://github.com/manya-pri/AI-honeybot'>View source code</a></p>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """<!doctype html><title>Sign in</title><h1>Sign in</h1>
        <p>Demonstration only. Do not enter a real username or password.</p>
        <form method='post'><label>User <input name='username'></label>
        <label>Password <input name='password' type='password'></label>
        <button>Sign in</button></form>"""
    # This decoy has no authentication backend; every submitted login is a
    # simulated failure. A future successful auth route must pass False.
    event = _record_interaction(authentication_failed=True)
    if event["action"] == "BLOCKED":
        return "Request blocked by AI-Honeybot", 403
    return "Sign-in unavailable in this demonstration.", 401


@app.post("/ssh/login")
def record_fake_ssh_login():
    event = _record_interaction(authentication_failed=True)
    if event["action"] == "BLOCKED":
        return "Request blocked by AI-Honeybot", 403
    return fake_ssh_login()


@app.post("/ssh/session")
def record_fake_ssh_command():
    event = _record_interaction()
    if event["action"] == "BLOCKED":
        return "Request blocked by AI-Honeybot", 403
    return fake_ssh_session()


@app.get("/admin")
def admin():
    mode = _current_deception_mode(request.remote_addr or "unknown")
    status = 200 if mode in {"deep_admin", "high_interaction"} else 401
    return synthetic_admin(mode), status


# Synthetic-only decoys. The values are deliberately fictional and are not
# loaded from host files or configuration secrets.
_DECOYS = {
    "/.env": ("text/plain", "APP_ENV=demo\nDB_USER=demo_user\nDB_PASSWORD=FAKE_ONLY\n"),
    "/credentials.txt": ("text/plain", "demo@example.invalid:FAKE_PASSWORD\n"),
    "/database_backup.sql": ("text/plain", "-- SYNTHETIC SAMPLE\nCREATE TABLE demo_records (id INTEGER);\n"),
    "/api_keys.txt": ("text/plain", "DEMO_API_KEY=not-a-real-key\n"),
    "/admin_config.json": ("application/json", '{"environment":"synthetic","debug":false}'),
    "/fake_customer_records.csv": ("text/csv", "id,name,email\n1,Sample Person,sample@example.invalid\n"),
}


@app.route("/<path:decoy_path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "TRACE"])
def decoy_surface(decoy_path: str):
    """Small fake API/file surface; all returned material is synthetic."""
    normalized = "/" + decoy_path
    adaptive = synthetic_endpoint(normalized, _current_deception_mode(request.remote_addr or "unknown"))
    if adaptive:
        content_type, body = adaptive
        return app.response_class(body, status=200, content_type=content_type)
    if normalized in _DECOYS:
        content_type, body = _DECOYS[normalized]
        return app.response_class(body, status=200, content_type=content_type)
    if normalized.startswith("/api/"):
        return jsonify(service="synthetic-decoy", status="unavailable", request_id=str(uuid.uuid4())), 200
    return "Not found", 404


def _current_deception_mode(source_ip: str) -> str:
    try:
        state = app.config["DATABASE"].get_deception(source_ip)
        return state["mode"] if state else "basic"
    except Exception:
        return "basic"


def _read_events() -> list[dict[str, Any]]:
    database = app.config.get("DATABASE")
    if database is not None:
        try:
            persisted = database.list_events(limit=10000)
            if persisted:
                return persisted
        except Exception as error:
            app.logger.warning("SQLite event history unavailable; reading JSONL (%s).", type(error).__name__)
    try:
        with EVENTS_FILE.open(encoding="utf-8") as stream:
            events = []
            for line in stream:
                try:
                    if line.strip():
                        events.append(json.loads(line))
                except json.JSONDecodeError:
                    app.logger.warning("Skipping malformed event history line.")
            return events
    except OSError:
        return []


@app.get("/api/health")
def api_health():
    return jsonify(service="adaptive-ai-honeybot", status="ok",
                   mode="demo" if os.environ.get("DEMO_MODE", "false").lower() == "true" else "local",
                   agent="random-forest-and-persistent-memory", events_file=str(EVENTS_FILE))


@app.get("/api/attacks")
def api_attacks():
    limit = min(500, max(1, request.args.get("limit", default=100, type=int)))
    return jsonify(events=_read_events()[-limit:])


@app.get("/api/attackers")
def api_attackers():
    database = app.config["DATABASE"]
    try:
        profiles = database.list_attackers()
        histories = {profile["source_ip"]: database.list_events(limit=200, source_ip=profile["source_ip"]) for profile in profiles}
        clusters = get_model().cluster_profiles([{"source_ip": ip, "events": history} for ip, history in histories.items()])
        database.save_clusters(clusters, datetime.now(timezone.utc).isoformat())
        membership = {ip: item["description"] for item in clusters for ip in item["member_ips"]}
        for profile in profiles:
            history = histories[profile["source_ip"]]
            profile["behaviour_features"] = engineer_features(history)
            profile["behavioural_cluster"] = membership.get(profile["source_ip"])
            profile["timeline"] = history
        return jsonify(attackers=profiles, clusters=clusters)
    except Exception as error:
        app.logger.warning("SQLite attacker profile unavailable; deriving profile from event history (%s).", type(error).__name__)
    profiles: dict[str, dict[str, Any]] = {}
    for event in _read_events():
        ip = event.get("source_ip", "unknown")
        p = profiles.setdefault(ip, {"source_ip": ip, "first_seen": event.get("timestamp"), "total_events": 0,
                                    "endpoints": set(), "services": set(), "risk_score": 0, "threat_level": "LOW"})
        p["total_events"] += 1
        p["last_seen"] = event.get("timestamp")
        p["endpoints"].add(event.get("endpoint", ""))
        p["services"].add("http")
        p["risk_score"] = max(p["risk_score"], event.get("risk", {}).get("score", 0))
        p["threat_level"] = event.get("risk", {}).get("level", "LOW")
    return jsonify(attackers=[{**p, "endpoints": sorted(p["endpoints"]), "services": sorted(p["services"])} for p in profiles.values()])


@app.get("/api/attackers/<path:source_ip>")
def api_attacker_profile(source_ip: str):
    profile_response = api_attackers().get_json()
    profile = next((item for item in profile_response["attackers"] if item.get("source_ip") == source_ip), None)
    if profile is None:
        return jsonify(error="attacker not found"), 404
    try:
        profile["behavioural_cluster"] = next((c for c in app.config["DATABASE"].list_clusters()
                                                if source_ip in c["member_ips"]), None)
    except Exception:
        pass
    return jsonify(profile=profile)


@app.get("/api/attackers/<path:source_ip>/timeline")
def api_attacker_timeline(source_ip: str):
    return jsonify(source_ip=source_ip, events=[e for e in _read_events() if e.get("source_ip") == source_ip])


@app.get("/api/dashboard/summary")
def api_dashboard_summary():
    events = _read_events()
    sources = {e.get("source_ip") for e in events}
    high = sum(e.get("risk", {}).get("level") in {"HIGH", "CRITICAL"} for e in events)
    blocked = len(app.config["RISK_RESPONSE_MANAGER"].active_blocks())
    return jsonify(total_events=len(events), active_attackers=len(sources), high_risk_events=high,
                   contained_sources=blocked, top_endpoints=Counter(e.get("endpoint", "") for e in events).most_common(8))


@app.get("/api/deception")
def api_deception():
    try:
        return jsonify(states=app.config["DATABASE"].list_deception())
    except Exception:
        return jsonify(states=[])


@app.get("/api/threats")
def api_threats():
    return jsonify(threats=[e for e in _read_events() if e.get("risk", {}).get("level") in {"HIGH", "CRITICAL"}][-200:])


@app.get("/api/metrics")
def api_metrics():
    events = _read_events()
    return jsonify(events=len(events), sources=len({e.get("source_ip") for e in events}),
                   by_level=dict(Counter(e.get("risk", {}).get("level", "UNKNOWN") for e in events)),
                   by_action=dict(Counter(e.get("action", "UNKNOWN") for e in events)))


@app.get("/api/agent/status")
def api_agent_status():
    return jsonify(status="online", **get_agent_status(),
                   latest_event=_read_events()[-1] if _read_events() else None)


@app.get("/api/agent/decisions")
def api_agent_decisions():
    return jsonify(decisions=[{"timestamp": e.get("timestamp"), "source_ip": e.get("source_ip"),
                              "risk": e.get("risk"), "action": e.get("action"), "evidence": e.get("risk", {}).get("indicators", [])}
                             for e in _read_events() if e.get("risk", {}).get("indicators")][-200:])


@app.post("/api/agent/analyze")
def api_agent_analyze():
    data = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip")
    if not isinstance(source_ip, str) or len(source_ip) > 64:
        return jsonify(error="source_ip must be a string of at most 64 characters"), 400
    try:
        source_ip = str(ip_address(source_ip))
    except ValueError:
        return jsonify(error="source_ip must be a valid IP address"), 400
    history = [e for e in _read_events() if e.get("source_ip") == source_ip]
    latest = history[-1] if history else None
    score = latest.get("risk", {}).get("score", 0) if latest else 0
    indicators = sorted({i for event in history for i in event.get("risk", {}).get("indicators", [])})
    ml = (latest or {}).get("ml") or {}
    threat = ml.get("label") or ("credential_attack" if any("authentication" in x.lower() for x in indicators) else "suspicious_access" if indicators else "normal")
    features = engineer_features(history)
    reason = f"Derived from {len(history)} recorded events and {len(indicators)} distinct indicators."
    local_result = {"threat_type": threat, "risk_score": score,
        "confidence": ml.get("confidence", min(.95, .5 + .05 * len(indicators))), "behaviours": indicators,
        "recommended_action": "temporary_containment" if score >= CRITICAL_THRESHOLD else "monitor" if score >= MEDIUM_THRESHOLD else "observe",
        "evidence": {"event_count": len(history), "distinct_indicators": len(indicators), "features": features},
        "reason": reason, "model": ml.get("model", "transparent-rule-memory")}
    profile = app.config["DATABASE"].get_attacker(source_ip) or {"source_ip": source_ip, "total_events": len(history),
        "risk_score": score, "historical_max_risk": max((e.get("risk", {}).get("score", 0) for e in history), default=0),
        "attack_categories": indicators, "responses": [e.get("action") for e in history]}
    assessment = agent_assess({
        "attacker_profile": profile, "recent_events": [{key: event.get(key) for key in ("timestamp", "method", "endpoint", "risk", "action", "ml")}
                          for event in history[-12:]], "risk_score": score, "behavioural_features": features,
        "ml_classification": ml, "behavioural_cluster": profile.get("behavioural_cluster"),
        "deception_state": app.config["DATABASE"].get_deception(source_ip),
        "previous_response": profile.get("responses", [])[-1:] if profile.get("responses") else None,
    }, local_result)
    if history:
        app.config["DATABASE"].save_agent_assessment(source_ip, datetime.now(timezone.utc).isoformat(), assessment)
    assessment.setdefault("model", ml.get("model", "transparent-rule-memory"))
    return jsonify(assessment)


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="Request body too large (16 KB limit)."), 413


if __name__ == "__main__":
    # Bind explicitly to loopback; do not expose this demonstration to a network.
    app.run(host=os.environ.get("HONEYPOT_HOST", "127.0.0.1"), port=int(os.environ.get("HONEYPOT_PORT", "5000")), debug=False)
