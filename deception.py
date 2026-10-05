"""Risk-tiered synthetic web deception state; never launches commands."""
from __future__ import annotations

from typing import Any


MODES = ("basic", "expanded", "deep_admin", "high_interaction")


def mode_for_risk(score: int) -> str:
    score = max(0, min(100, int(score)))
    if score >= 80:
        return "high_interaction"
    if score >= 60:
        return "deep_admin"
    if score >= 30:
        return "expanded"
    return "basic"


def transition(previous: dict[str, Any] | None, score: int) -> dict[str, Any] | None:
    new_mode = mode_for_risk(score)
    old_mode = previous.get("mode") if previous else None
    if old_mode == new_mode:
        return None
    return {"previous_mode": old_mode, "new_mode": new_mode, "risk_score": score,
            "reason": f"risk score {score} selected {new_mode} deception tier"}


def synthetic_admin(mode: str) -> str:
    if mode == "high_interaction":
        return """<title>Northstar Operations Console</title><h1>Operations Console</h1>
        <p>Environment: synthetic demonstration</p><p>Queue: 4 sample jobs · Nodes: 3 mock nodes</p>
        <a href='/api/v1/users'>User service</a> · <a href='/backup'>Backup service</a>"""
    if mode == "deep_admin":
        return "<title>Admin Console</title><h1>Administrative Console</h1><p>Synthetic access audit enabled.</p>"
    return "Administrative area. Sign in required."


def synthetic_endpoint(path: str, mode: str) -> tuple[str, str] | None:
    if path == "/backup" and mode in {"expanded", "deep_admin", "high_interaction"}:
        return "text/plain", "SYNTHETIC BACKUP\nrecord_id,display_name\n1,Example Record\n"
    if path == "/api/v1/users" and mode in {"expanded", "deep_admin", "high_interaction"}:
        return "application/json", '{"users":[{"id":"demo-1","name":"Example User","email":"user@example.invalid"}],"synthetic":true}'
    if path == "/system/status" and mode in {"deep_admin", "high_interaction"}:
        return "application/json", '{"status":"operational","environment":"synthetic","synthetic":true}'
    return None
