"""FastAPI read/response API backed by the same SQLite honeypot memory.

Run with ``python -m uvicorn api_server:app --host 127.0.0.1 --port 8000``.
Containment affects only this application's temporary honeypot policy.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from analyzer import RuleBasedAnalyzer, extract_behavior_features
from agent import agent_status as get_agent_status, assess as agent_assess
from app import EVENTS_FILE, app as flask_app
from behaviour import engineer_features
from deception import transition
from demo_geo import synthetic_demo_geo
from ml_engine import FEATURE_ORDER, get_model

app = FastAPI(title="Adaptive AI HoneyBot", version="0.2.0", description="Loopback-only defensive honeypot API")
db = flask_app.config["DATABASE"]
policy = flask_app.config["RISK_RESPONSE_MANAGER"]


def _trained_model():
    model = get_model()
    db.record_model_version("rf-synthetic-v1" if getattr(model, "algorithm", "").startswith("RandomForest") else "rule-fallback-v1",
        getattr(model, "algorithm", "transparent-rule-fallback"), datetime.now(timezone.utc).isoformat(),
        getattr(model, "training_data", "not applicable"), FEATURE_ORDER)
    return model


class SimulationEvent(BaseModel):
    source_ip: str = "127.0.0.1"
    method: str = Field(default="GET", max_length=10)
    endpoint: str = Field(default="/", max_length=300)
    user_agent: str = Field(default="HoneyBotDemo/1.0", max_length=200)
    authentication_failed: bool = False

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        parsed = ip_address(value)
        if not parsed.is_loopback:
            raise ValueError("simulation source must be a loopback IP")
        return str(parsed)

    @field_validator("method")
    @classmethod
    def allowed_method(cls, value: str) -> str:
        value = value.upper()
        if value not in {"GET", "POST", "PUT", "PATCH", "DELETE", "TRACE"}:
            raise ValueError("unsupported HTTP method")
        return value

    @field_validator("endpoint")
    @classmethod
    def local_path_only(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//"):
            raise ValueError("endpoint must be a local absolute path")
        return value


class ContainmentRequest(BaseModel):
    source_ip: str
    reason: str = Field(default="Analyst requested temporary honeypot containment", max_length=500)

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ip_address(value))


def _event_jsonl(event: dict[str, Any]) -> None:
    path = Path(EVENTS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(event, ensure_ascii=True) + "\n")


def _ingest_simulated(data: SimulationEvent) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    details: dict[str, Any] = {}
    features = extract_behavior_features(data.method, data.endpoint, data.user_agent, details,
                                         authentication_failed=data.authentication_failed)
    features["simulation"] = True
    baseline = flask_app.config["RULE_ANALYZER"].analyze(features)
    result = policy.evaluate(data.source_ip, data.endpoint, data.method, baseline, features,
                             authentication_failed=data.authentication_failed)
    previous = db.get_deception(data.source_ip)
    change = transition(previous, result["risk_score"])
    if change:
        db.set_deception(data.source_ip, change["new_mode"], now, change["reason"])
        change["timestamp"] = now
    history = db.list_events(limit=200, source_ip=data.source_ip)
    event = {"event_id": str(uuid4()), "timestamp": now, "source_ip": data.source_ip,
        "service": "http", "event_type": "simulation", "method": data.method, "endpoint": data.endpoint,
        "user_agent": data.user_agent, "details": details, "features": features,
        "source_geo": synthetic_demo_geo(data.source_ip),
        "baseline_risk": baseline, "risk": {"score": result["risk_score"], "level": result["risk_level"],
        "indicators": result["indicators"]}, "action": result["action"], "source_risk": result["source_risk"],
        "block": result["block"], "block_expiry": (result["block"] or {}).get("expires_at"),
        "deception_change": change, "ml": _trained_model().classify(engineer_features(history + [{
            "timestamp": now, "endpoint": data.endpoint, "method": data.method,
            "service": "http", "features": features, "risk": result}]))}
    db.save_event(event)
    _event_jsonl(event)
    return event


@app.get("/api/health")
def health():
    return {"service": "adaptive-ai-honeybot", "status": "ok", "database": "sqlite",
            "ml": "random_forest", "containment": "honeypot-local"}


@app.get("/api/dashboard/summary")
def summary():
    events = db.list_events(limit=10000)
    return {"total_events": len(events), "active_attackers": len(db.list_attackers()),
            "high_risk_events": sum(e.get("risk", {}).get("level") in {"HIGH", "CRITICAL"} for e in events),
            "contained_sources": len(policy.active_blocks()),
            "risk_distribution": dict(Counter(e.get("risk", {}).get("level", "UNKNOWN") for e in events))}


@app.get("/api/attacks")
def attacks(limit: int = Query(default=100, ge=1, le=1000)):
    return {"events": list(reversed(db.list_events(limit=limit)))}


@app.get("/api/attacks/{event_id}")
def attack(event_id: str):
    event = db.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return event


@app.get("/api/attackers")
def attackers():
    profiles = db.list_attackers()
    for profile in profiles:
        history = db.list_events(limit=500, source_ip=profile["source_ip"])
        profile["behaviour_features"] = engineer_features(history)
        profile["timeline"] = history
    clusters = _trained_model().cluster_profiles([{"source_ip": p["source_ip"], "events": p["timeline"]} for p in profiles])
    db.save_clusters(clusters, datetime.now(timezone.utc).isoformat())
    membership = {ip: c["description"] for c in clusters for ip in c["member_ips"]}
    for profile in profiles:
        profile["behavioural_cluster"] = membership.get(profile["source_ip"])
    return {"attackers": profiles, "clusters": clusters}


@app.get("/api/attackers/{source_ip}")
def attacker(source_ip: str):
    try:
        source_ip = str(ip_address(source_ip))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="source_ip must be an IP address") from error
    profile = db.get_attacker(source_ip)
    if not profile:
        raise HTTPException(status_code=404, detail="attacker not found")
    history = db.list_events(limit=1000, source_ip=source_ip)
    profile["timeline"] = history
    profile["behaviour_features"] = engineer_features(history)
    profile["ml"] = history[-1].get("ml") if history else None
    profile["deception"] = db.get_deception(source_ip)
    profile["behavioural_cluster"] = next((c for c in db.list_clusters() if source_ip in c["member_ips"]), None)
    profile["response_history"] = db.list_response_actions(source_ip)
    return profile


@app.get("/api/attackers/{source_ip}/timeline")
def timeline(source_ip: str):
    try:
        source_ip = str(ip_address(source_ip))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="source_ip must be an IP address") from error
    return {"source_ip": source_ip, "events": db.list_events(limit=1000, source_ip=source_ip)}


@app.get("/api/threats")
def threats():
    return {"events": [e for e in db.list_events(limit=10000)
                        if e.get("risk", {}).get("level") in {"HIGH", "CRITICAL"}][-500:]}


@app.post("/api/threats/report/{source_ip}")
def create_threat_report(source_ip: str):
    try:
        source_ip = str(ip_address(source_ip))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="source_ip must be an IP address") from error
    profile = db.get_attacker(source_ip)
    if not profile:
        raise HTTPException(status_code=404, detail="attacker not found")
    events = db.list_events(limit=1000, source_ip=source_ip)
    report = {"report_id": str(uuid4()), "source_ip": source_ip,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "threat_level": profile["threat_level"], "risk_score": profile["risk_score"],
        "historical_max_risk": profile["historical_max_risk"], "event_count": len(events),
        "attack_categories": profile["attack_categories"], "endpoints": profile["endpoints"],
        "services": profile["services"], "responses": profile["responses"],
        "classification": events[-1].get("ml") if events else None,
        "evidence": profile["suspicious_actions"], "synthetic_or_real": "observed local honeypot event history"}
    db.save_threat_report(report)
    return report


@app.get("/api/threats/reports")
def threat_reports(source_ip: str | None = None):
    return {"reports": db.list_threat_reports(source_ip)}


@app.get("/api/metrics")
def metrics():
    events = db.list_events(limit=10000)
    return {"events": len(events), "sources": len(db.list_attackers()),
            "by_level": dict(Counter(e.get("risk", {}).get("level", "UNKNOWN") for e in events)),
            "by_action": dict(Counter(e.get("action", "UNKNOWN") for e in events))}


@app.get("/api/models")
def models():
    return {"models": db.list_model_versions()}


@app.get("/api/agent/status")
def agent_status():
    _trained_model()
    return {"status": "online", **get_agent_status(), "ml_model": getattr(_trained_model(), "algorithm", "fallback"),
            "latest_decision": db.list_events(limit=1)[-1] if db.list_events(limit=1) else None,
            "latest_assessment": next(iter(db.list_agent_assessments(limit=1)), None)}


@app.get("/api/agent/decisions")
def agent_decisions():
    return {"decisions": db.list_agent_assessments() + [{"timestamp": e["timestamp"], "source_ip": e["source_ip"],
        "risk": e.get("risk"), "ml": e.get("ml"), "action": e.get("action"),
        "evidence": e.get("risk", {}).get("indicators", [])}
        for e in db.list_events(limit=1000) if e.get("risk", {}).get("indicators")][-200:]}


@app.post("/api/simulation/event")
def simulate_event(data: SimulationEvent):
    return _ingest_simulated(data)


@app.post("/api/agent/analyze")
def analyze(data: ContainmentRequest):
    profile = db.get_attacker(data.source_ip)
    if not profile:
        raise HTTPException(status_code=404, detail="no recorded history for source")
    events = db.list_events(limit=500, source_ip=data.source_ip)
    features = engineer_features(events)
    ml = _trained_model().classify(features)
    clusters = db.list_clusters()
    if not clusters:
        profiles = db.list_attackers()
        grouped = [{"source_ip": item["source_ip"],
                    "events": db.list_events(limit=500, source_ip=item["source_ip"])} for item in profiles]
        clusters = _trained_model().cluster_profiles(grouped)
        db.save_clusters(clusters, datetime.now(timezone.utc).isoformat())
    profile["behavioural_cluster"] = next((cluster for cluster in clusters
                                           if data.source_ip in cluster["member_ips"]), None)
    local_result = {"threat_type": ml["label"], "risk_score": profile["risk_score"],
            "confidence": ml["confidence"], "behaviours": profile["suspicious_actions"],
            "recommended_action": "temporary_containment" if profile["risk_score"] >= 60 else "monitor",
            "reason": f"{len(events)} persisted events; max observed risk {profile['historical_max_risk']}.",
            "ml": ml}
    context = {
        "attacker_profile": {key: profile.get(key) for key in (
            "source_ip", "total_events", "login_attempts", "failed_logins", "endpoints",
            "services", "risk_score", "historical_max_risk", "threat_level", "attack_categories")},
        "recent_events": [{key: event.get(key) for key in ("timestamp", "method", "endpoint", "risk", "action", "ml")}
                          for event in events[-12:]],
        "risk_score": profile["risk_score"], "behavioural_features": features,
        "ml_classification": ml, "behavioural_cluster": profile.get("behavioural_cluster"),
        "deception_state": db.get_deception(data.source_ip),
        "previous_response": profile.get("responses", [])[-1:] if profile.get("responses") else None,
    }
    assessment = agent_assess(context, local_result)
    assessment.update({"risk_score": profile["risk_score"], "reason": assessment.get("evidence_summary", local_result["reason"]),
                       "ml": ml})
    db.save_agent_assessment(data.source_ip, datetime.now(timezone.utc).isoformat(), assessment)
    return assessment


@app.post("/api/response/contain")
def contain(data: ContainmentRequest):
    result = policy.request_temporary_containment(data.source_ip, data.reason)
    if not result["allowed"]:
        raise HTTPException(status_code=409, detail=result)
    block = result["block"]
    with db.session() as connection:
        connection.execute("INSERT INTO response_actions(source_ip,timestamp,action,payload) VALUES(?,?,?,?)",
            (data.source_ip, block["first_seen"], "temporary_containment", json.dumps(block)))
    return {"status": "temporarily_contained", **block}


@app.delete("/api/response/contain/{source_ip}")
def release_containment(source_ip: str):
    try:
        source_ip = str(ip_address(source_ip))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="source_ip must be an IP address") from error
    block = policy.store.get_block(source_ip)
    if block is None or not policy.release_temporary_containment(source_ip):
        raise HTTPException(status_code=404, detail="no active containment for source")
    timestamp = datetime.now(timezone.utc).isoformat()
    with db.session() as connection:
        connection.execute("INSERT INTO response_actions(source_ip,timestamp,action,payload) VALUES(?,?,?,?)",
            (source_ip, timestamp, "containment_released", json.dumps({"previous_block": block.snapshot()})))
    return {"status": "released", "source_ip": source_ip, "released_at": timestamp}
