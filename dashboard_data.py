"""Presentation-only transformations for the Streamlit event dashboard."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd


def prepare_dashboard_data(events: list[dict[str, Any]], now: datetime | None = None) -> dict[str, Any]:
    """Normalize event history into activity, source, and block views.

    This module derives UI summaries from captured events; risk decisions remain
    exclusively in the Flask analyzer and response manager.
    """
    rows: list[dict[str, Any]] = []
    for event in events:
        risk = event.get("risk") or {}
        geo = event.get("source_geo") or {}
        state = event.get("source_risk") or {}
        block = event.get("block") or {}
        location_status = geo.get("status")
        location = geo.get("approximate_location")
        if location_status in {"invalid_ip", "lookup_error", "no_match", "not_configured"}:
            location = "Location unavailable"
        elif not location:
            location = "Location unavailable"
        rows.append({
            "timestamp": event.get("timestamp"),
            "source_ip": event.get("source_ip", "Unknown"),
            "method": event.get("method", "—"),
            "endpoint": event.get("endpoint", "—"),
            "user_agent": event.get("user_agent", "—"),
            "risk_score": risk.get("score", 0),
            "risk_level": risk.get("level", "UNKNOWN"),
            "indicators": list(risk.get("indicators", [])),
            "indicators_text": "; ".join(risk.get("indicators", [])),
            "action": event.get("action", "RECORDED"),
            "ml": event.get("ml") or {},
            "deception_change": event.get("deception_change") or {},
            "service": event.get("service", "http"),
            "source_geo": geo,
            "demo_attacker_id": geo.get("demo_attacker_id"),
            "demo_label": geo.get("demo_label"),
            "synthetic_location": bool(geo.get("synthetic")),
            "approximate_location": location,
            "country": geo.get("country"),
            "region": geo.get("region"),
            "city": geo.get("city"),
            "network": geo.get("network"),
            "asn": geo.get("asn"),
            "latitude": geo.get("latitude"),
            "longitude": geo.get("longitude"),
            "source_risk": state,
            "first_seen": state.get("first_seen"),
            "last_seen": state.get("last_seen"),
            "request_count": state.get("request_count"),
            "suspicious_request_count": state.get("suspicious_request_count"),
            "cumulative_risk_score": state.get("cumulative_risk_score"),
            "block": block,
            "block_reason": block.get("reason"),
            "block_first_seen": block.get("first_seen"),
            "block_last_seen": block.get("last_seen"),
            "block_expiry": event.get("block_expiry") or block.get("expires_at"),
            "details_json": json.dumps(event.get("details", {}), ensure_ascii=False),
            "features_json": json.dumps(event.get("features", {}), ensure_ascii=False),
            "anomaly_score": (event.get("anomaly") or {}).get("score", "Not configured"),
            "attack_type": (event.get("ml") or {}).get("label") or
                ((risk.get("indicators") or ["normal activity"])[0]),
        })

    frame = pd.DataFrame(rows)
    if frame.empty:
        return {
            "events": frame,
            "latest_by_source": frame,
            "blocked_sources": frame,
            "recent_blocked": frame,
            "summary": {"total_interactions": 0, "high_risk": 0, "high_risk_attackers": 0,
                        "total_sources": 0, "active_sources": 0, "active_suspicious": 0,
                        "currently_blocked": 0},
            "risk_distribution": {}, "attack_type_distribution": {}, "demo_map": [], "map_points": [],
            "demo_mode": False,
        }

    frame["timestamp_dt"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame.sort_values("timestamp_dt", na_position="first").reset_index(drop=True)
    latest = frame.drop_duplicates("source_ip", keep="last").copy()
    current_time = pd.Timestamp(now or datetime.now(timezone.utc))
    if current_time.tzinfo is None:
        current_time = current_time.tz_localize("UTC")
    else:
        current_time = current_time.tz_convert("UTC")
    expiries = pd.to_datetime(latest["block_expiry"], utc=True, errors="coerce")
    latest["currently_blocked"] = expiries > current_time
    latest["current_status"] = latest.apply(
        lambda row: "TEMPORARILY BLOCKED" if row["currently_blocked"] else
        "REQUEST REJECTED" if row["action"] == "BLOCKED" else
        "MONITORED" if row["action"] == "MONITORED" else
        "ALLOWED" if row["action"] == "ALLOWED" else "RECORDED",
        axis=1,
    )
    blocks = frame[frame["block"].map(bool)].copy()
    blocks = blocks.drop_duplicates("source_ip", keep="last")
    recent_blocked = frame[frame["action"] == "BLOCKED"].sort_values("timestamp_dt", ascending=False)
    active_cutoff = current_time.to_pydatetime() - timedelta(minutes=15)
    active_sources = latest[latest["timestamp_dt"] >= active_cutoff]
    summary = {
        "total_interactions": len(frame),
        "high_risk": int(frame["risk_level"].isin(["HIGH", "CRITICAL"]).sum()),
        "high_risk_attackers": int(latest["risk_level"].isin(["HIGH", "CRITICAL"]).sum()),
        "total_sources": int(frame["source_ip"].nunique()),
        "active_sources": int(len(active_sources)),
        "active_suspicious": int(active_sources["risk_level"].isin(["MEDIUM", "HIGH", "CRITICAL"]).sum()),
        "currently_blocked": int(latest["currently_blocked"].sum()),
    }
    risk_distribution = frame["risk_level"].value_counts().to_dict()
    attack_type_distribution = frame["attack_type"].value_counts().head(8).to_dict()
    demo_map = []
    synthetic = frame[frame["synthetic_location"]].copy()
    if not synthetic.empty:
        counts = frame.groupby("source_ip").size().to_dict()
        for source_ip, history in synthetic.groupby("source_ip", sort=True):
            last = history.iloc[-1]
            demo_map.append({
                "attacker_id": last["demo_attacker_id"] or f"DEMO-{source_ip}",
                "source_ip": source_ip,
                "demo_label": last["demo_label"] or "DEMO DATA — SIMULATED ATTACK",
                "location": last["approximate_location"],
                "country": last["country"],
                "latitude": last["latitude"], "longitude": last["longitude"],
                "attack_type": last["attack_type"], "risk_score": int(history["risk_score"].max()),
                "event_count": int(counts[source_ip]), "threat_level": last["risk_level"],
                "is_synthetic": True,
            })
    map_points = []
    counts = frame.groupby("source_ip").size().to_dict()
    for _, last in latest.iterrows():
        if pd.isna(last["latitude"]) or pd.isna(last["longitude"]):
            continue
        is_synthetic = bool(last["synthetic_location"])
        map_points.append({
            "attacker_id": last["demo_attacker_id"] or str(last["source_ip"]),
            "source_ip": last["source_ip"],
            "demo_label": last["demo_label"] or "APPROXIMATE GEOIP DATA — OBSERVED SOURCE IP",
            "location": last["approximate_location"], "country": last["country"],
            "latitude": float(last["latitude"]), "longitude": float(last["longitude"]),
            "attack_type": last["attack_type"],
            "risk_score": int(frame[frame["source_ip"] == last["source_ip"]]["risk_score"].max()),
            "event_count": int(counts.get(last["source_ip"], 0)), "threat_level": last["risk_level"],
            "is_synthetic": is_synthetic,
            "marker_color": [221, 111, 80, 210] if is_synthetic else [70, 150, 210, 210],
        })
    latest_simulated = latest[latest["synthetic_location"] & (latest["timestamp_dt"] >= active_cutoff)]
    return {
        "events": frame,
        "latest_by_source": latest,
        "blocked_sources": blocks,
        "recent_blocked": recent_blocked,
        "summary": summary,
        "risk_distribution": risk_distribution,
        "attack_type_distribution": attack_type_distribution,
        "demo_map": demo_map,
        "map_points": map_points,
        "demo_mode": bool(latest_simulated.shape[0]),
    }
