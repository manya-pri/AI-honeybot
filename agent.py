"""Controlled LLM-assisted triage with a deterministic local fallback.

The provider can only return a validated assessment. Response enforcement stays
in the risk/containment policy; this module has no shell or command tools.
"""
from __future__ import annotations

import json
import os
from typing import Any, Literal, Protocol
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ThreatAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threat_type: str = Field(min_length=1, max_length=80)
    confidence: float = Field(ge=0, le=1)
    behaviours: list[str] = Field(max_length=20)
    risk_assessment: str = Field(min_length=1, max_length=500)
    recommended_action: Literal["observe", "monitor", "adaptive_deception", "temporary_containment"]
    evidence_summary: str = Field(min_length=1, max_length=700)

    @field_validator("behaviours")
    @classmethod
    def bound_behaviours(cls, values: list[str]) -> list[str]:
        return [value[:160] for value in values if value.strip()][:20]


class AssessmentProvider(Protocol):
    def assess(self, context: dict[str, Any]) -> ThreatAssessment: ...


class OpenAICompatibleProvider:
    """Chat Completions-compatible JSON provider configured only by environment."""

    def __init__(self, api_key: str, model: str, base_url: str, timeout: float = 12.0):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def assess(self, context: dict[str, Any]) -> ThreatAssessment:
        allowed_event_fields = ("timestamp", "method", "endpoint", "risk", "action", "ml")
        recent_events = [
            {key: event.get(key) for key in allowed_event_fields if key in event}
            for event in context.get("recent_events", [])[-12:] if isinstance(event, dict)
        ]
        compact_context = {
            "attacker_profile": context.get("attacker_profile", {}),
            "recent_events": recent_events,
            "risk_score": context.get("risk_score", 0),
            "behavioural_features": context.get("behavioural_features", {}),
            "ml_classification": context.get("ml_classification", {}),
            "behavioural_cluster": context.get("behavioural_cluster"),
            "deception_state": context.get("deception_state"),
            "previous_response": context.get("previous_response"),
        }
        body = json.dumps({
            "model": self.model,
            "temperature": 0,
            "max_tokens": 450,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": (
                    "You are a defensive honeypot triage assistant. Assess only the supplied evidence. "
                    "Return one JSON object with threat_type, confidence, behaviours, risk_assessment, "
                    "recommended_action, evidence_summary. Do not include chain-of-thought. "
                    "Never propose shell commands, external actions, retaliation, or destructive actions. "
                    "Allowed recommended_action values: observe, monitor, adaptive_deception, temporary_containment."
                )},
                {"role": "user", "content": json.dumps(compact_context, ensure_ascii=True)},
            ],
        }).encode("utf-8")
        request = Request(
            f"{self.base_url}/chat/completions", data=body,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout) as response:
            payload = json.loads(response.read(256_000))
        content = payload["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise ValueError("provider returned no JSON content")
        return ThreatAssessment.model_validate_json(content)


def configured_provider() -> tuple[AssessmentProvider | None, str | None]:
    if os.environ.get("LLM_ENABLED", "false").strip().lower() not in {"1", "true", "yes", "on"}:
        return None, "LLM is disabled; using the local agent."
    api_key = os.environ.get("LLM_API_KEY", "").strip()
    model = os.environ.get("LLM_MODEL", "").strip()
    if not api_key:
        return None, "LLM_ENABLED is true but LLM_API_KEY is missing; using the local agent."
    if not model:
        return None, "LLM_ENABLED is true but LLM_MODEL is missing; using the local agent."
    base_url = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").strip()
    parsed = urlsplit(base_url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or (parsed.scheme != "https" and not
            (parsed.scheme == "http" and parsed.hostname.lower() in {"127.0.0.1", "localhost", "::1"})):
        return None, "LLM_BASE_URL must use HTTPS (HTTP is allowed only on loopback); using the local agent."
    return OpenAICompatibleProvider(api_key, model, base_url), None


def agent_status() -> dict[str, Any]:
    provider, fallback_reason = configured_provider()
    return {
        "agent_mode": "llm" if provider else "local",
        "llm_used": False,
        "llm_configured": provider is not None,
        "model": os.environ.get("LLM_MODEL") if provider else None,
        "fallback_reason": fallback_reason,
    }


def assess(context: dict[str, Any], local_result: dict[str, Any],
           provider: AssessmentProvider | None = None) -> dict[str, Any]:
    """Return validated provider output or a clear, safe local fallback."""
    reason: str | None = None
    if provider is None:
        provider, reason = configured_provider()
    if provider is not None:
        try:
            result = provider.assess(context)
            if not isinstance(result, ThreatAssessment):
                result = ThreatAssessment.model_validate(result)
            return {**result.model_dump(), "agent_mode": "llm", "llm_used": True,
                    "model": os.environ.get("LLM_MODEL", "configured-provider")}
        except Exception as error:  # Network, provider schema, and validation errors must never take down the API.
            reason = f"LLM unavailable ({type(error).__name__}); using the local agent."
    return {**local_result, "agent_mode": "local", "llm_used": False,
            "risk_assessment": local_result.get("risk_assessment", local_result.get("reason", "Local assessment.")),
            "evidence_summary": local_result.get("evidence_summary", local_result.get("reason", "Evidence from stored honeypot events.")),
            "fallback_reason": reason or "LLM is disabled; using the local agent."}
