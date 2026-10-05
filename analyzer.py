"""Feature extraction and explainable baseline scoring for the local decoy.

The feature schema and ``AnomalyDetector`` protocol are extension points for a
future anomaly detector. This module currently includes no trained ML model.
"""

from __future__ import annotations

import re
from typing import Any, Protocol, TypedDict


class BehaviorFeatures(TypedDict):
    """Stable, model-friendly per-interaction fields (no labels or risk score)."""

    method: str
    endpoint_category: str
    endpoint_length: int
    unusual_method: bool
    has_query_parameters: bool
    query_parameter_count: int
    body_field_count: int
    has_user_agent: bool
    user_agent_length: int
    scanner_user_agent: bool
    suspicious_pattern: bool
    prior_requests_from_ip: int
    request_number_from_ip: int
    authentication_failed: bool
    decoy_resource_access: bool
    suspicious_command: bool


class AnomalyDetector(Protocol):
    """Contract for a future detector; score must be normalized from 0 to 1."""

    def score(self, features: BehaviorFeatures) -> float:
        """Return an anomaly score without changing the baseline rule result."""


_UNUSUAL_METHODS = {"PUT", "PATCH", "DELETE", "TRACE"}
_SUSPICIOUS_TOKENS = ("../", "%2e%2e", "..\\", "<script", "union select", " or 1=1")
_SCANNER_USER_AGENT = re.compile(r"(sqlmap|nikto|nmap|masscan|acunetix|burp|zgrab)", re.IGNORECASE)


def extract_behavior_features(
    method: str,
    endpoint: str,
    user_agent: str = "",
    details: dict[str, Any] | None = None,
    prior_requests_from_ip: int = 0,
    authentication_failed: bool = False,
) -> BehaviorFeatures:
    """Extract a stable feature record before any scoring layer runs."""
    normalized_method = method.upper()
    normalized_path = endpoint.lower()
    safe_details = details or {}
    query = safe_details.get("query", {})
    body = safe_details.get("body", {})
    query_count = len(query) if isinstance(query, dict) else 0
    body_count = len(body) if isinstance(body, dict) else 0
    command_value = body.get("command", "") if isinstance(body, dict) else ""
    suspicious_command = any(token in str(command_value).lower() for token in
                             ("sudo", "wget", "curl", "bash", "powershell", "rm ", "nc ", "chmod", "passwd"))
    searchable = f"{normalized_path} {safe_details}".lower()
    category = (
        "login" if normalized_path.rstrip("/") == "/login"
        else "admin" if normalized_path.rstrip("/") == "/admin"
        else "root" if normalized_path == "/"
        else "other"
    )

    return {
        "method": normalized_method,
        "endpoint_category": category,
        "endpoint_length": len(endpoint),
        "unusual_method": normalized_method in _UNUSUAL_METHODS,
        "has_query_parameters": query_count > 0,
        "query_parameter_count": query_count,
        "body_field_count": body_count,
        "has_user_agent": bool(user_agent.strip()),
        "user_agent_length": len(user_agent),
        "scanner_user_agent": bool(_SCANNER_USER_AGENT.search(user_agent)),
        "suspicious_pattern": any(token in searchable for token in _SUSPICIOUS_TOKENS),
        "prior_requests_from_ip": max(0, int(prior_requests_from_ip)),
        "request_number_from_ip": max(0, int(prior_requests_from_ip)) + 1,
        "authentication_failed": bool(authentication_failed),
        "decoy_resource_access": normalized_path in {"/.env", "/credentials.txt", "/database_backup.sql", "/api_keys.txt", "/admin_config.json", "/fake_customer_records.csv"},
        "suspicious_command": suspicious_command,
    }


class RuleBasedAnalyzer:
    """Current baseline: transparent indicators with fixed point values."""

    def __init__(self, *, medium_threshold: int = 30, high_threshold: int = 60, critical_threshold: int = 80):
        if not 0 <= medium_threshold < high_threshold < critical_threshold <= 100:
            raise ValueError("risk thresholds must satisfy 0 <= medium < high < critical <= 100")
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.critical_threshold = critical_threshold

    def analyze(self, features: BehaviorFeatures) -> dict[str, Any]:
        score = 0
        indicators: list[str] = []

        if features["endpoint_category"] in {"login", "admin"}:
            score += 15
            indicators.append("Sensitive decoy endpoint visited")
        if features["unusual_method"]:
            score += 20
            indicators.append(f"Unusual HTTP method: {features['method']}")
        if features["suspicious_pattern"]:
            score += 35
            indicators.append("Common injection or path-traversal pattern")
        if features["scanner_user_agent"]:
            score += 25
            indicators.append("Scanner-like user-agent")
        if not features["has_user_agent"]:
            score += 5
            indicators.append("Missing user-agent")
        if features.get("decoy_resource_access", False):
            score += 25
            indicators.append("Synthetic decoy resource accessed")
        if features.get("suspicious_command", False):
            score += 25
            indicators.append("Suspicious command observed in synthetic SSH session")
        prior_requests = features["prior_requests_from_ip"]
        if prior_requests >= 10:
            score += 20
            indicators.append("High request volume from this source during this run")
        elif prior_requests >= 5:
            score += 10
            indicators.append("Repeated requests from this source during this run")

        score = min(score, 100)
        level = ("CRITICAL" if score >= self.critical_threshold else "HIGH" if score >= self.high_threshold
                 else "MEDIUM" if score >= self.medium_threshold else "LOW")
        return {"score": score, "level": level, "indicators": indicators}


def analyze_request(
    method: str,
    endpoint: str,
    user_agent: str = "",
    details: dict[str, Any] | None = None,
    prior_requests_from_ip: int = 0,
) -> dict[str, Any]:
    """Compatibility helper: extract features, then run baseline rules only."""
    features = extract_behavior_features(method, endpoint, user_agent, details, prior_requests_from_ip)
    return RuleBasedAnalyzer().analyze(features)
