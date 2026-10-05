"""Derive attacker behavior features from observed, persisted event history."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any


def engineer_features(events: list[dict[str, Any]], *, now: datetime | None = None) -> dict[str, float]:
    if not events:
        return {key: 0.0 for key in (
            "events_per_minute", "failed_login_count", "unique_endpoints", "unique_ports",
            "command_count", "suspicious_command_count", "decoy_resource_access", "session_duration",
            "repeated_action_ratio", "attack_frequency", "historical_risk", "previous_attack_count",
            "service_diversity", "suspicious_event_count", "login_attempt_count")}
    timestamps = []
    for event in events:
        try:
            timestamps.append(datetime.fromisoformat(str(event.get("timestamp", "")).replace("Z", "+00:00")))
        except ValueError:
            pass
    elapsed_minutes = max(1.0, (timestamps[-1] - timestamps[0]).total_seconds() / 60) if len(timestamps) > 1 else 1.0
    endpoints = [str(event.get("endpoint", "")) for event in events]
    actions = Counter(endpoints)
    repeated = sum(n - 1 for n in actions.values())
    duration = max(0.0, (timestamps[-1] - timestamps[0]).total_seconds()) if len(timestamps) > 1 else 0.0
    risk_values = [int((event.get("risk") or {}).get("score", 0)) for event in events]
    commands = [str(command) for event in events for command in (
        (event.get("details") or {}).get("commands") or
        [((event.get("details") or {}).get("body") or {}).get("command", "")]) if command]
    services = {str(event.get("service", "http")) for event in events}
    unique_ports = {event.get("destination_port") for event in events if event.get("destination_port")}
    failed = sum(bool((event.get("features") or {}).get("authentication_failed")) for event in events)
    decoys = sum(bool((event.get("features") or {}).get("decoy_resource_access")) for event in events)
    suspicious = sum(bool((event.get("risk") or {}).get("indicators")) for event in events)
    login_attempts = sum(str(event.get("endpoint", "")).rstrip("/") == "/login" and event.get("method") == "POST" for event in events)
    suspicious_terms = ("sudo", "wget", "curl", "bash", "powershell", "rm ", "nc ", "chmod")
    suspicious_commands = sum(any(term in command.lower() for term in suspicious_terms) for command in commands)
    return {
        "events_per_minute": len(events) / elapsed_minutes,
        "failed_login_count": float(failed),
        "unique_endpoints": float(len(set(endpoints))),
        "unique_ports": float(len(unique_ports)),
        "command_count": float(len(commands)),
        "suspicious_command_count": float(suspicious_commands),
        "decoy_resource_access": float(decoys),
        "session_duration": duration,
        "repeated_action_ratio": repeated / max(1, len(events)),
        "attack_frequency": suspicious / elapsed_minutes,
        "historical_risk": float(max(risk_values, default=0)),
        "previous_attack_count": float(max(0, len(events) - 1)),
        "service_diversity": float(len(services)),
        "suspicious_event_count": float(suspicious),
        "login_attempt_count": float(login_attempts),
    }
