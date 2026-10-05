"""SQLite event and attacker memory for the local honeypot.

The API is intentionally small and uses only SQLite's standard-library driver.
Each operation opens its own connection, which is safe for Flask's threaded
development server and keeps the storage replaceable behind this boundary.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from risk_response import SourceRiskState, TemporaryBlock


class HoneybotDatabase:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def session(self):
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._lock, self.session() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source_ip TEXT NOT NULL,
                    service TEXT NOT NULL, event_type TEXT NOT NULL, severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL, payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_source_time ON events(source_ip, timestamp);
                CREATE TABLE IF NOT EXISTS attackers (
                    source_ip TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    total_events INTEGER NOT NULL DEFAULT 0, login_attempts INTEGER NOT NULL DEFAULT 0,
                    failed_logins INTEGER NOT NULL DEFAULT 0, decoy_access INTEGER NOT NULL DEFAULT 0,
                    risk_score INTEGER NOT NULL DEFAULT 0, max_risk INTEGER NOT NULL DEFAULT 0,
                    profile TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS risk_states (source_ip TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS temporary_blocks (source_ip TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS response_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT NOT NULL,
                    timestamp TEXT NOT NULL, action TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deception_state (
                    source_ip TEXT PRIMARY KEY, mode TEXT NOT NULL, updated_at TEXT NOT NULL,
                    reason TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT NOT NULL,
                    timestamp TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS threat_reports (
                    report_id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS behaviour_clusters (
                    cluster_id INTEGER PRIMARY KEY, description TEXT NOT NULL, member_ips TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS model_versions (
                    version TEXT PRIMARY KEY, algorithm TEXT NOT NULL, trained_at TEXT NOT NULL,
                    training_data TEXT NOT NULL, feature_order TEXT NOT NULL
                );
            """)

    @staticmethod
    def _profile_event(event: dict[str, Any]) -> dict[str, Any]:
        risk = event.get("risk") or {}
        features = event.get("features") or {}
        geo = event.get("source_geo") or {}
        ml = event.get("ml") or {}
        endpoint = str(event.get("endpoint", ""))[:500]
        command_value = ((event.get("details") or {}).get("body") or {}).get("command")
        return {
            "source_ip": str(event.get("source_ip", "unknown")),
            "country": geo.get("country") or "UNKNOWN", "region": geo.get("region") or "UNKNOWN",
            "city": geo.get("city") or "UNKNOWN", "asn": geo.get("asn") or "UNKNOWN",
            "organization": geo.get("organization") or "UNKNOWN",
            "latitude": geo.get("latitude"), "longitude": geo.get("longitude"),
            "synthetic_location": bool(geo.get("synthetic")),
            "demo_attacker_id": geo.get("demo_attacker_id"),
            "demo_label": geo.get("demo_label"),
            "first_seen": event.get("timestamp", ""), "last_seen": event.get("timestamp", ""),
            "total_events": 1,
            "login_attempts": int(endpoint.rstrip("/") == "/login" and event.get("method") == "POST"),
            "failed_logins": int(bool(features.get("authentication_failed"))),
            "decoy_credential_access": int(bool(features.get("decoy_resource_access"))),
            "endpoints": [endpoint], "services": [event.get("service", "http")],
            "commands": [str(command_value)[:160]] if command_value else [], "suspicious_actions": list(risk.get("indicators", [])),
            "attack_categories": [str(c) for c in (risk.get("indicators", []) or [])],
            "risk_score": int(risk.get("score", 0)), "historical_max_risk": int(risk.get("score", 0)),
            "threat_level": str(risk.get("level", "LOW")), "responses": [event.get("action", "RECORDED")],
            "behaviour_classification": ml.get("label", "unknown"),
            "behavioural_cluster": None, "confidence": float(ml.get("confidence", 0.0)),
        }

    def save_event(self, event: dict[str, Any]) -> None:
        payload = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        profile = self._profile_event(event)
        risk = event.get("risk") or {}
        event_id = str(event.get("event_id") or f"{event.get('timestamp')}:{event.get('source_ip')}:{event.get('endpoint')}:{event.get('method')}")
        with self._lock, self.session() as db:
            db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?)", (
                event_id, event.get("timestamp", ""), profile["source_ip"], event.get("service", "http"),
                event.get("event_type", "http_request"), risk.get("level", "LOW"), risk.get("score", 0), payload))
            row = db.execute("SELECT profile FROM attackers WHERE source_ip=?", (profile["source_ip"],)).fetchone()
            if row:
                current = json.loads(row["profile"])
                current["total_events"] += 1
                current["last_seen"] = profile["last_seen"]
                current["login_attempts"] += profile["login_attempts"]
                current["failed_logins"] += profile["failed_logins"]
                current["decoy_credential_access"] += profile["decoy_credential_access"]
                current["risk_score"] = profile["risk_score"]
                for key in ("country", "region", "city", "asn", "organization", "latitude", "longitude"):
                    if profile.get(key) not in (None, "UNKNOWN"):
                        current[key] = profile[key]
                for key in ("synthetic_location", "demo_attacker_id", "demo_label"):
                    if profile.get(key):
                        current[key] = profile[key]
                current["historical_max_risk"] = max(current["historical_max_risk"], profile["historical_max_risk"])
                current["threat_level"] = profile["threat_level"]
                current["behaviour_classification"] = profile["behaviour_classification"]
                current["confidence"] = profile["confidence"]
                current["endpoints"] = sorted(set(current["endpoints"] + profile["endpoints"]))
                current["services"] = sorted(set(current["services"] + profile["services"]))
                current["commands"] = (current["commands"] + profile["commands"])[-100:]
                current["suspicious_actions"] = sorted(set(current["suspicious_actions"] + profile["suspicious_actions"]))
                current["attack_categories"] = sorted(set(current["attack_categories"] + profile["attack_categories"]))
                current["responses"] = (current["responses"] + profile["responses"])[-100:]
                profile = current
            db.execute("""INSERT INTO attackers(source_ip,first_seen,last_seen,total_events,login_attempts,
                failed_logins,decoy_access,risk_score,max_risk,profile) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(source_ip) DO UPDATE SET last_seen=excluded.last_seen,total_events=excluded.total_events,
                login_attempts=excluded.login_attempts,failed_logins=excluded.failed_logins,
                decoy_access=excluded.decoy_access,risk_score=excluded.risk_score,max_risk=excluded.max_risk,
                profile=excluded.profile""", (profile["source_ip"], profile["first_seen"], profile["last_seen"],
                profile["total_events"], profile["login_attempts"], profile["failed_logins"],
                profile["decoy_credential_access"], profile["risk_score"], profile["historical_max_risk"],
                json.dumps(profile)))
            block = event.get("block")
            if block:
                db.execute("INSERT INTO response_actions(source_ip,timestamp,action,payload) VALUES(?,?,?,?)",
                           (profile["source_ip"], event.get("timestamp", ""), "temporary_containment", json.dumps(block)))
            db.execute("INSERT INTO agent_decisions(source_ip,timestamp,payload) VALUES(?,?,?)",
                       (profile["source_ip"], event.get("timestamp", ""), payload))

    def list_events(self, limit: int = 5000, source_ip: str | None = None) -> list[dict[str, Any]]:
        with self.session() as db:
            if source_ip is None:
                rows = db.execute("SELECT payload FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = db.execute("SELECT payload FROM events WHERE source_ip=? ORDER BY timestamp DESC LIMIT ?", (source_ip, limit)).fetchall()
        return [json.loads(row["payload"]) for row in reversed(rows)]

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self.session() as db:
            row = db.execute("SELECT payload FROM events WHERE event_id=?", (event_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def list_attackers(self) -> list[dict[str, Any]]:
        with self.session() as db:
            rows = db.execute("SELECT profile FROM attackers ORDER BY last_seen DESC").fetchall()
        return [json.loads(row["profile"]) for row in rows]

    def get_attacker(self, source_ip: str) -> dict[str, Any] | None:
        with self.session() as db:
            row = db.execute("SELECT profile FROM attackers WHERE source_ip=?", (source_ip,)).fetchone()
        return json.loads(row["profile"]) if row else None

    def get_deception(self, source_ip: str) -> dict[str, Any] | None:
        with self.session() as db:
            row = db.execute("SELECT mode,updated_at,reason FROM deception_state WHERE source_ip=?", (source_ip,)).fetchone()
        return dict(row) if row else None

    def set_deception(self, source_ip: str, mode: str, updated_at: str, reason: str) -> None:
        with self.session() as db:
            db.execute("INSERT INTO deception_state VALUES(?,?,?,?) ON CONFLICT(source_ip) DO UPDATE SET "
                       "mode=excluded.mode,updated_at=excluded.updated_at,reason=excluded.reason",
                       (source_ip, mode, updated_at, reason))
            db.execute("INSERT INTO response_actions(source_ip,timestamp,action,payload) VALUES(?,?,?,?)",
                       (source_ip, updated_at, "deception_changed", json.dumps({"mode": mode, "reason": reason})))

    def list_deception(self) -> list[dict[str, Any]]:
        with self.session() as db:
            rows = db.execute("SELECT source_ip,mode,updated_at,reason FROM deception_state").fetchall()
        return [dict(row) for row in rows]

    def save_threat_report(self, report: dict[str, Any]) -> None:
        with self.session() as db:
            db.execute("INSERT INTO threat_reports VALUES(?,?,?,?)", (report["report_id"], report["source_ip"],
                       report["created_at"], json.dumps(report)))
            db.execute("INSERT INTO response_actions(source_ip,timestamp,action,payload) VALUES(?,?,?,?)",
                       (report["source_ip"], report["created_at"], "threat_report_generated", json.dumps({"report_id": report["report_id"]})))

    def list_threat_reports(self, source_ip: str | None = None) -> list[dict[str, Any]]:
        with self.session() as db:
            if source_ip:
                rows = db.execute("SELECT payload FROM threat_reports WHERE source_ip=? ORDER BY created_at DESC", (source_ip,)).fetchall()
            else:
                rows = db.execute("SELECT payload FROM threat_reports ORDER BY created_at DESC LIMIT 200").fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def save_clusters(self, clusters: list[dict[str, Any]], updated_at: str) -> None:
        with self.session() as db:
            db.execute("DELETE FROM behaviour_clusters")
            for cluster in clusters:
                db.execute("INSERT INTO behaviour_clusters VALUES(?,?,?,?)", (cluster["cluster_id"],
                    cluster["description"], json.dumps(cluster["member_ips"]), updated_at))

    def list_clusters(self) -> list[dict[str, Any]]:
        with self.session() as db:
            rows = db.execute("SELECT cluster_id,description,member_ips,updated_at FROM behaviour_clusters").fetchall()
        return [{**dict(row), "member_ips": json.loads(row["member_ips"])} for row in rows]

    def record_model_version(self, version: str, algorithm: str, trained_at: str,
                             training_data: str, feature_order: list[str]) -> None:
        with self.session() as db:
            db.execute("INSERT OR IGNORE INTO model_versions VALUES(?,?,?,?,?)",
                       (version, algorithm, trained_at, training_data, json.dumps(feature_order)))

    def list_model_versions(self) -> list[dict[str, Any]]:
        with self.session() as db:
            rows = db.execute("SELECT * FROM model_versions ORDER BY trained_at DESC").fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["feature_order"] = json.loads(value["feature_order"])
            result.append(value)
        return result

    def list_response_actions(self, source_ip: str) -> list[dict[str, Any]]:
        with self.session() as db:
            rows = db.execute("SELECT timestamp,action,payload FROM response_actions WHERE source_ip=? ORDER BY id", (source_ip,)).fetchall()
        return [{"timestamp": row["timestamp"], "action": row["action"], "details": json.loads(row["payload"])}
                for row in rows]

    def save_agent_assessment(self, source_ip: str, timestamp: str, assessment: dict[str, Any]) -> None:
        payload = {"record_type": "agent_assessment", **assessment}
        with self.session() as db:
            db.execute("INSERT INTO agent_decisions(source_ip,timestamp,payload) VALUES(?,?,?)",
                       (source_ip, timestamp, json.dumps(payload)))

    def list_agent_assessments(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.session() as db:
            rows = db.execute("SELECT timestamp,payload FROM agent_decisions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        values = [{**json.loads(row["payload"]), "timestamp": row["timestamp"]} for row in rows]
        return [value for value in values if value.get("record_type") == "agent_assessment"]


class SQLiteRiskStore:
    """Persistent adapter implementing RiskResponseManager's state-store contract."""
    def __init__(self, database: HoneybotDatabase):
        self.database = database

    def get_source(self, source_ip: str) -> SourceRiskState | None:
        with self.database.session() as db:
            row = db.execute("SELECT payload FROM risk_states WHERE source_ip=?", (source_ip,)).fetchone()
        if not row: return None
        data = json.loads(row["payload"])
        from datetime import datetime
        data["triggered_indicators"] = set(data.get("triggered_indicators", []))
        data["sensitive_endpoints"] = set(data.get("sensitive_endpoints", []))
        data["last_request_at"] = datetime.fromisoformat(data["last_request_at"]) if data.get("last_request_at") else None
        return SourceRiskState(**data)

    def save_source(self, state: SourceRiskState) -> None:
        payload = state.snapshot()
        with self.database.session() as db:
            db.execute("INSERT INTO risk_states VALUES(?,?) ON CONFLICT(source_ip) DO UPDATE SET payload=excluded.payload",
                       (state.source_ip, json.dumps(payload)))

    def list_sources(self) -> list[SourceRiskState]:
        with self.database.session() as db:
            ips = [r[0] for r in db.execute("SELECT source_ip FROM risk_states")]
        return [state for ip in ips if (state := self.get_source(ip)) is not None]

    def get_block(self, source_ip: str) -> TemporaryBlock | None:
        with self.database.session() as db:
            row = db.execute("SELECT payload FROM temporary_blocks WHERE source_ip=?", (source_ip,)).fetchone()
        return TemporaryBlock(**json.loads(row["payload"])) if row else None

    def save_block(self, block: TemporaryBlock) -> None:
        with self.database.session() as db:
            db.execute("INSERT INTO temporary_blocks VALUES(?,?) ON CONFLICT(source_ip) DO UPDATE SET payload=excluded.payload",
                       (block.source_ip, json.dumps(block.snapshot())))

    def delete_block(self, source_ip: str) -> None:
        with self.database.session() as db:
            db.execute("DELETE FROM temporary_blocks WHERE source_ip=?", (source_ip,))

    def list_blocks(self) -> list[TemporaryBlock]:
        with self.database.session() as db:
            rows = db.execute("SELECT payload FROM temporary_blocks").fetchall()
        return [TemporaryBlock(**json.loads(row["payload"])) for row in rows]
