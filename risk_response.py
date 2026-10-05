"""In-memory adaptive risk tracking and honeypot-local response policy."""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from geo_enrichment import _LOCAL_PRIVATE_NETWORKS


def is_local_or_private_ip(source_ip: str) -> bool:
    """Return true for loopback, link-local, RFC1918, and IPv6 ULA sources."""
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return bool(
        address.is_loopback
        or address.is_link_local
        or any(address.version == network.version and address in network for network in _LOCAL_PRIVATE_NETWORKS)
    )


def is_public_ip(source_ip: str) -> bool:
    """Return whether an address qualifies for a general high-risk temp block.

    The explicit failed-authentication threshold is allowed to create its
    short-lived block for local/private addresses as well.
    """
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not is_local_or_private_ip(str(address))


@dataclass
class SourceRiskState:
    source_ip: str
    first_seen: str
    last_seen: str
    request_count: int = 0
    suspicious_request_count: int = 0
    cumulative_risk_score: int = 0
    triggered_indicators: set[str] = field(default_factory=set)
    high_risk_streak: int = 0
    authentication_attempts: int = 0
    sensitive_endpoints: set[str] = field(default_factory=set)
    indicator_counts: dict[str, int] = field(default_factory=dict)
    saw_normal_browsing: bool = False
    last_request_at: datetime | None = None

    def snapshot(self) -> dict[str, Any]:
        value = asdict(self)
        value["triggered_indicators"] = sorted(self.triggered_indicators)
        value["sensitive_endpoints"] = sorted(self.sensitive_endpoints)
        value["last_request_at"] = self.last_request_at.isoformat() if self.last_request_at else None
        return value


@dataclass
class TemporaryBlock:
    source_ip: str
    risk_score: int
    reason: str
    first_seen: str
    last_seen: str
    expires_at: str

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class RiskStateStore(Protocol):
    """Storage contract for replacing the MVP's in-memory store later."""

    def get_source(self, source_ip: str) -> SourceRiskState | None: ...
    def save_source(self, state: SourceRiskState) -> None: ...
    def list_sources(self) -> list[SourceRiskState]: ...
    def get_block(self, source_ip: str) -> TemporaryBlock | None: ...
    def save_block(self, block: TemporaryBlock) -> None: ...
    def delete_block(self, source_ip: str) -> None: ...
    def list_blocks(self) -> list[TemporaryBlock]: ...


class InMemoryRiskStore:
    """Small storage adapter; replace with a Redis/DB adapter when needed."""

    def __init__(self):
        self.sources: dict[str, SourceRiskState] = {}
        self.blocks: dict[str, TemporaryBlock] = {}

    def get_source(self, source_ip: str) -> SourceRiskState | None:
        return self.sources.get(source_ip)

    def save_source(self, state: SourceRiskState) -> None:
        self.sources[state.source_ip] = state

    def list_sources(self) -> list[SourceRiskState]:
        return list(self.sources.values())

    def get_block(self, source_ip: str) -> TemporaryBlock | None:
        return self.blocks.get(source_ip)

    def save_block(self, block: TemporaryBlock) -> None:
        self.blocks[block.source_ip] = block

    def delete_block(self, source_ip: str) -> None:
        self.blocks.pop(source_ip, None)

    def list_blocks(self) -> list[TemporaryBlock]:
        return list(self.blocks.values())


class RiskResponseManager:
    """Accumulate per-source risk, detect escalation, and apply temporary blocks."""

    def __init__(
        self,
        store: RiskStateStore | None = None,
        *,
        block_duration_seconds: int = 300,
        block_after_high_risk: int = 3,
        auth_block_after: int = 3,
        min_suspicious_events_before_containment: int = 3,
        medium_risk_threshold: int = 30,
        high_risk_threshold: int = 60,
        critical_risk_threshold: int = 80,
        rapid_request_seconds: float = 1.0,
        clock: Callable[[], datetime] | None = None,
    ):
        self.store = store or InMemoryRiskStore()
        self.block_duration_seconds = max(1, int(block_duration_seconds))
        # Temporary containment is always a multi-event response. Environment
        # settings may raise, but cannot weaken, the three-observation floor.
        self.block_after_high_risk = max(3, int(block_after_high_risk))
        self.auth_block_after = max(3, int(auth_block_after))
        self.min_suspicious_events_before_containment = max(3, int(min_suspicious_events_before_containment))
        if not 0 <= medium_risk_threshold < high_risk_threshold < critical_risk_threshold <= 100:
            raise ValueError("risk thresholds must satisfy 0 <= medium < high < critical <= 100")
        self.medium_risk_threshold = medium_risk_threshold
        self.high_risk_threshold = high_risk_threshold
        self.critical_risk_threshold = critical_risk_threshold
        self.rapid_request_seconds = max(0.0, float(rapid_request_seconds))
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()

    def _now(self, now: datetime | None) -> datetime:
        value = now or self.clock()
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    def _expire_blocks(self, now: datetime) -> None:
        for block in self.store.list_blocks():
            if datetime.fromisoformat(block.expires_at) <= now:
                self.store.delete_block(block.source_ip)
                state = self.store.get_source(block.source_ip)
                if state is not None:
                    # Expiry also releases accumulated policy pressure so a
                    # temporary block cannot silently become a permanent ban.
                    state.cumulative_risk_score = 0
                    state.high_risk_streak = 0
                    state.authentication_attempts = 0
                    state.sensitive_endpoints.clear()
                    state.indicator_counts.clear()
                    state.last_request_at = None
                    self.store.save_source(state)

    def evaluate(
        self,
        source_ip: str,
        endpoint: str,
        method: str,
        baseline_risk: dict[str, Any],
        features: dict[str, Any],
        *,
        authentication_failed: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Return effective risk, action, per-source state, and optional block."""
        instant = self._now(now)
        timestamp = instant.isoformat()
        with self._lock:
            self._expire_blocks(instant)
            state = self.store.get_source(source_ip)
            if state is None:
                state = SourceRiskState(source_ip=source_ip, first_seen=timestamp, last_seen=timestamp)
            prior_requests = state.request_count
            state.request_count += 1
            state.last_seen = timestamp

            active_block = self.store.get_block(source_ip)
            if active_block is not None:
                state.suspicious_request_count += 1
                state.triggered_indicators.add("Active temporary source-IP block")
                active_block.last_seen = timestamp
                state.last_request_at = instant
                self.store.save_source(state)
                self.store.save_block(active_block)
                return {
                    "risk_score": active_block.risk_score,
                    "risk_level": "CRITICAL" if active_block.risk_score >= self.critical_risk_threshold else "HIGH",
                    "indicators": ["Active temporary source-IP block"],
                    "action": "BLOCKED",
                    "block": active_block.snapshot(),
                    "source_risk": state.snapshot(),
                }

            indicators = list(baseline_risk.get("indicators", []))
            base_score = max(0, min(100, int(baseline_risk.get("score", 0))))
            bonus = 0
            category: str = str(features.get("endpoint_category", "other"))
            sensitive: bool = category in {"login", "admin"}
            current_sensitive_endpoint: str | None = endpoint if sensitive else None

            if sensitive and state.saw_normal_browsing:
                indicators.append("Sensitive endpoint probing after normal browsing")
                bonus += 15

            is_auth_attempt = authentication_failed and category == "login" and method.upper() == "POST"
            auth_attempt_number = state.authentication_attempts + (1 if is_auth_attempt else 0)
            if is_auth_attempt and state.authentication_attempts >= 1:
                indicators.append("Repeated authentication attempts")
                bonus += 15

            if (
                state.last_request_at is not None
                and prior_requests >= 2
                and 0 <= (instant - state.last_request_at).total_seconds() <= self.rapid_request_seconds
            ):
                indicators.append("Rapid requests from the same source")
                bonus += 25

            if sensitive and current_sensitive_endpoint not in state.sensitive_endpoints and state.sensitive_endpoints:
                indicators.append("Multiple sensitive endpoints accessed")
                bonus += 20

            repeated_indicators = 0
            for indicator in baseline_risk.get("indicators", []):
                if state.indicator_counts.get(indicator, 0) and repeated_indicators < 2:
                    indicators.append(f"Repeated indicator: {indicator}")
                    bonus += 15
                    repeated_indicators += 1

            request_score = min(100, base_score + bonus)
            # A half-life per interaction preserves escalation while allowing
            # later benign behavior to lower the accumulated source score.
            decayed_score = state.cumulative_risk_score // 2
            state.cumulative_risk_score = min(100, decayed_score + request_score)
            # Real loopback browsing keeps the login form usable; the explicit
            # synthetic event API opts into accumulated risk for demonstrations.
            local_demo = is_local_or_private_ip(source_ip) and not features.get("simulation", False)
            effective_score = request_score if local_demo else max(request_score, state.cumulative_risk_score)
            if effective_score > request_score:
                indicators.append("Cumulative risk across this source's requests")

            auth_threshold_reached = is_auth_attempt and auth_attempt_number >= self.auth_block_after
            # Repeated ordinary failed logins remain a monitored condition up
            # to the configured threshold. Independent strong signals (e.g.
            # scanner UA, suspicious payload or unusual method) retain normal
            # high-risk behavior throughout.
            high_confidence_signals: set[str] = {
                "Common injection or path-traversal pattern",
                "Scanner-like user-agent",
                "Unusual HTTP method: PUT",
                "Unusual HTTP method: PATCH",
                "Unusual HTTP method: DELETE",
                "Unusual HTTP method: TRACE",
            }
            has_high_confidence_signal = bool(high_confidence_signals.intersection(indicators))
            # Keep the decoy login form reachable in a normal browser session.
            # Generic cumulative signals (request count, rapid page loads, and
            # repeated endpoint visits) are still logged and monitored here;
            # strong scanner/payload/method signals keep their normal policy.
            interactive_login_page = category == "login" and method.upper() == "GET"
            ordinary_pre_threshold_login = is_auth_attempt and not auth_threshold_reached
            if (
                (interactive_login_page or ordinary_pre_threshold_login)
                and base_score < 60
                and not has_high_confidence_signal
            ):
                effective_score = min(effective_score, self.high_risk_threshold - 1)

            if auth_threshold_reached:
                effective_score = max(self.high_risk_threshold, effective_score)
                indicators.append(f"{self.auth_block_after} failed authentication attempts")
            level = ("CRITICAL" if effective_score >= self.critical_risk_threshold else
                     "HIGH" if effective_score >= self.high_risk_threshold else
                     "MEDIUM" if effective_score >= self.medium_risk_threshold else "LOW")
            if level != "LOW" or indicators:
                state.suspicious_request_count += 1
            state.triggered_indicators.update(indicators)
            for indicator in baseline_risk.get("indicators", []):
                state.indicator_counts[indicator] = state.indicator_counts.get(indicator, 0) + 1
            if is_auth_attempt:
                state.authentication_attempts += 1
            if sensitive and current_sensitive_endpoint:
                state.sensitive_endpoints.add(current_sensitive_endpoint)
            if category in {"root", "other"} and base_score < 25:
                state.saw_normal_browsing = True
            state.high_risk_streak = state.high_risk_streak + 1 if level in {"HIGH", "CRITICAL"} else 0
            state.last_request_at = instant

            action = "ALLOWED" if level == "LOW" else "MONITORED" if level == "MEDIUM" else "BLOCKED"
            block_snapshot = None
            if (
                level in {"HIGH", "CRITICAL"}
                and (
                    auth_threshold_reached
                    or state.high_risk_streak >= self.block_after_high_risk
                )
            ):
                block = TemporaryBlock(
                    source_ip=source_ip,
                    risk_score=effective_score,
                    reason=(
                        f"{self.auth_block_after} failed authentication attempts"
                        if auth_threshold_reached
                        else "; ".join(dict.fromkeys(indicators))[:500] or "Repeated high-risk behavior"
                    ),
                    first_seen=timestamp,
                    last_seen=timestamp,
                    expires_at=(instant + timedelta(seconds=self.block_duration_seconds)).isoformat(),
                )
                self.store.save_block(block)
                block_snapshot = block.snapshot()

            self.store.save_source(state)
            return {
                "risk_score": effective_score,
                "risk_level": level,
                "indicators": list(dict.fromkeys(indicators)),
                "action": action,
                "block": block_snapshot,
                "source_risk": state.snapshot(),
            }

    def source_states(self) -> list[dict[str, Any]]:
        with self._lock:
            return [state.snapshot() for state in self.store.list_sources()]

    def active_blocks(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        instant = self._now(now)
        with self._lock:
            self._expire_blocks(instant)
            return [block.snapshot() for block in self.store.list_blocks()]

    def request_temporary_containment(self, source_ip: str, reason: str = "Analyst-approved local containment",
                                      *, now: datetime | None = None) -> dict[str, Any]:
        """Create a reversible block only after repeated suspicious evidence.

        This changes only the honeypot's own request policy. It never invokes
        firewall, shell, or external network controls.
        """
        instant = self._now(now)
        with self._lock:
            self._expire_blocks(instant)
            state = self.store.get_source(source_ip)
            if state is None or state.suspicious_request_count < self.min_suspicious_events_before_containment:
                return {"allowed": False, "reason": "minimum suspicious event threshold not met",
                        "required": self.min_suspicious_events_before_containment,
                        "observed": state.suspicious_request_count if state else 0}
            if state.cumulative_risk_score < self.high_risk_threshold:
                return {"allowed": False, "reason": "risk score below containment threshold",
                        "risk_score": state.cumulative_risk_score}
            timestamp = instant.isoformat()
            block = TemporaryBlock(source_ip=source_ip, risk_score=state.cumulative_risk_score,
                reason=str(reason)[:500], first_seen=timestamp, last_seen=timestamp,
                expires_at=(instant + timedelta(seconds=self.block_duration_seconds)).isoformat())
            self.store.save_block(block)
            return {"allowed": True, "block": block.snapshot()}

    def release_temporary_containment(self, source_ip: str) -> bool:
        """Release a honeypot-only block and reset its escalation streak."""
        with self._lock:
            block = self.store.get_block(source_ip)
            if block is None:
                return False
            self.store.delete_block(source_ip)
            state = self.store.get_source(source_ip)
            if state is not None:
                state.high_risk_streak = 0
                state.cumulative_risk_score = 0
                state.authentication_attempts = 0
                self.store.save_source(state)
            return True
