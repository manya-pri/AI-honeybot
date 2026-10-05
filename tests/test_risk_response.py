import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import app as honeypot
from risk_response import RiskResponseManager
from database import HoneybotDatabase


class FakeClock:
    def __init__(self):
        self.now = datetime(2026, 10, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def assessment(score=0, indicators=None):
    return {"score": score, "indicators": indicators or []}


def features(category="root"):
    return {"endpoint_category": category}


class RiskResponseTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.manager = RiskResponseManager(clock=self.clock)

    def evaluate(self, source="8.8.8.8", score=0, indicators=None, category="root", endpoint="/"):
        return self.manager.evaluate(
            source,
            endpoint,
            "GET",
            assessment(score, indicators),
            features(category),
        )

    def test_low_risk_is_allowed(self):
        result = self.evaluate()
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["action"], "ALLOWED")

    def test_medium_risk_is_monitored(self):
        result = self.evaluate(score=30, indicators=["Sensitive decoy endpoint visited"], category="admin")
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(result["action"], "MONITORED")

    def test_high_risk_is_rejected_without_immediate_persistent_block(self):
        result = self.evaluate(score=60, indicators=["Suspicious probe"])
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["action"], "BLOCKED")
        self.assertIsNone(result["block"])
        self.assertEqual(self.manager.active_blocks(), [])

    def test_repeated_high_risk_creates_temporary_block_and_expires(self):
        manager = RiskResponseManager(block_after_high_risk=3, block_duration_seconds=30, clock=self.clock)
        first = manager.evaluate("8.8.8.8", "/probe", "GET", assessment(60, ["probe"]), features("other"))
        second = manager.evaluate("8.8.8.8", "/probe", "GET", assessment(60, ["probe"]), features("other"))
        third = manager.evaluate("8.8.8.8", "/probe", "GET", assessment(60, ["probe"]), features("other"))
        self.assertIsNone(first["block"])
        self.assertIsNone(second["block"])
        self.assertEqual(third["action"], "BLOCKED")
        block = third["block"]
        self.assertEqual(block["source_ip"], "8.8.8.8")
        self.assertEqual(block["risk_score"], 100)
        self.assertTrue(block["reason"])
        self.assertTrue(block["first_seen"])
        self.assertTrue(block["last_seen"])
        self.assertEqual(datetime.fromisoformat(block["expires_at"]), self.clock.now + timedelta(seconds=30))
        blocked_attempt = manager.evaluate("8.8.8.8", "/", "GET", assessment(), features())
        self.assertEqual(blocked_attempt["indicators"], ["Active temporary source-IP block"])

        self.clock.now += timedelta(seconds=31)
        self.assertEqual(manager.active_blocks(), [])
        after_expiry = manager.evaluate("8.8.8.8", "/", "GET", assessment(), features())
        self.assertEqual(after_expiry["action"], "ALLOWED")
        self.assertEqual(after_expiry["source_risk"]["cumulative_risk_score"], 0)

    def test_failed_authentication_threshold_is_three_attempts(self):
        manager = RiskResponseManager(clock=self.clock)
        results = []
        for attempt in range(1, 4):
            results.append(manager.evaluate(
                "8.8.8.8", "/login", "POST", assessment(15, ["Sensitive decoy endpoint visited"]),
                features("login"), authentication_failed=True,
            ))
            self.assertEqual(results[-1]["source_risk"]["authentication_attempts"], attempt)
        self.assertNotEqual(results[0]["action"], "BLOCKED")
        self.assertNotEqual(results[1]["action"], "BLOCKED")
        self.assertEqual(results[0]["block"], None)
        self.assertEqual(results[1]["block"], None)
        self.assertEqual(results[1]["risk_level"], "MEDIUM")
        self.assertIn(results[2]["risk_level"], {"HIGH", "CRITICAL"})
        self.assertEqual(results[2]["action"], "BLOCKED")
        self.assertEqual(results[2]["block"]["reason"], "3 failed authentication attempts")
        fourth = manager.evaluate(
            "8.8.8.8", "/login", "POST", assessment(), features("login"), authentication_failed=True,
        )
        self.assertEqual(fourth["action"], "BLOCKED")
        self.assertEqual(fourth["indicators"], ["Active temporary source-IP block"])

    def test_requested_containment_requires_three_suspicious_events_and_high_risk(self):
        manager = RiskResponseManager(clock=self.clock)
        for _ in range(2):
            manager.evaluate("127.0.0.1", "/probe", "GET", assessment(40, ["probe"]), features("other"))
        too_early = manager.request_temporary_containment("127.0.0.1")
        self.assertFalse(too_early["allowed"])
        manager.evaluate("127.0.0.1", "/probe", "GET", assessment(40, ["probe"]), features("other"))
        contained = manager.request_temporary_containment("127.0.0.1")
        self.assertTrue(contained["allowed"])
        self.assertEqual(manager.active_blocks()[0]["source_ip"], "127.0.0.1")

    def test_successful_or_unclassified_login_does_not_increment_failures(self):
        manager = RiskResponseManager(clock=self.clock)
        result = manager.evaluate(
            "8.8.8.8", "/login", "POST", assessment(15, ["Sensitive decoy endpoint visited"]),
            features("login"), authentication_failed=False,
        )
        self.assertEqual(result["source_risk"]["authentication_attempts"], 0)
        self.assertEqual(result["action"], "ALLOWED")

    def test_auth_threshold_uses_expiring_block_for_loopback_demo(self):
        manager = RiskResponseManager(clock=self.clock, block_duration_seconds=20)
        outcomes = [manager.evaluate(
            "127.0.0.1", "/login", "POST", assessment(15, ["Sensitive decoy endpoint visited"]),
            features("login"), authentication_failed=True,
        ) for _ in range(3)]
        self.assertIsNone(outcomes[0]["block"])
        self.assertIsNone(outcomes[1]["block"])
        self.assertEqual(outcomes[2]["block"]["reason"], "3 failed authentication attempts")
        fourth = manager.evaluate("127.0.0.1", "/", "GET", assessment(), features())
        self.assertEqual(fourth["action"], "BLOCKED")
        self.assertEqual(fourth["indicators"], ["Active temporary source-IP block"])

    def test_different_ips_have_independent_risk_states(self):
        self.evaluate(source="8.8.8.8", score=35, indicators=["signal"])
        clean = self.evaluate(source="1.1.1.1")
        states = {state["source_ip"]: state for state in self.manager.source_states()}
        self.assertEqual(clean["action"], "ALLOWED")
        self.assertEqual(states["8.8.8.8"]["cumulative_risk_score"], 35)
        self.assertEqual(states["1.1.1.1"]["cumulative_risk_score"], 0)
        self.assertEqual(states["8.8.8.8"]["request_count"], 1)
        self.assertEqual(states["1.1.1.1"]["request_count"], 1)

    def test_local_private_ip_can_be_rejected_per_request_before_three_strikes(self):
        manager = RiskResponseManager(block_after_high_risk=1, clock=self.clock)
        for address in ("127.0.0.1", "10.0.0.4", "192.168.1.20", "::1"):
            result = manager.evaluate(address, "/probe", "GET", assessment(80, ["probe"]), features("other"))
            self.assertEqual(result["action"], "BLOCKED")
            self.assertIsNone(result["block"])
        self.assertEqual(manager.active_blocks(), [])
        local_clean = manager.evaluate("127.0.0.1", "/", "GET", assessment(), features())
        self.assertEqual(local_clean["action"], "ALLOWED")

    def test_local_repeated_high_risk_can_be_temporarily_contained_inside_honeypot(self):
        manager = RiskResponseManager(clock=self.clock)
        outcomes = [manager.evaluate("127.0.0.8", "/probe", "GET", assessment(80, ["probe"]), features("other"))
                    for _ in range(3)]
        self.assertIsNone(outcomes[0]["block"])
        self.assertIsNone(outcomes[1]["block"])
        self.assertIsNotNone(outcomes[2]["block"])

    def test_behavioral_escalation_indicators_are_detected(self):
        manager = RiskResponseManager(clock=self.clock)
        normal = manager.evaluate("8.8.8.8", "/", "GET", assessment(), features())
        sensitive = manager.evaluate(
            "8.8.8.8", "/admin", "GET", assessment(15, ["Sensitive decoy endpoint visited"]), features("admin")
        )
        self.assertEqual(normal["action"], "ALLOWED")
        self.assertIn("Sensitive endpoint probing after normal browsing", sensitive["indicators"])

        auth_manager = RiskResponseManager(clock=self.clock)
        auth_manager.evaluate("1.1.1.1", "/login", "POST", assessment(15, ["Sensitive decoy endpoint visited"]), features("login"), authentication_failed=True)
        repeated_auth = auth_manager.evaluate(
            "1.1.1.1", "/login", "POST", assessment(15, ["Sensitive decoy endpoint visited"]), features("login"), authentication_failed=True
        )
        self.assertIn("Repeated authentication attempts", repeated_auth["indicators"])

        rapid_manager = RiskResponseManager(clock=self.clock)
        rapid_manager.evaluate("8.8.4.4", "/", "GET", assessment(), features())
        rapid_manager.evaluate("8.8.4.4", "/", "GET", assessment(), features())
        rapid = rapid_manager.evaluate("8.8.4.4", "/", "GET", assessment(), features())
        self.assertIn("Rapid requests from the same source", rapid["indicators"])

        endpoints_manager = RiskResponseManager(clock=self.clock)
        endpoints_manager.evaluate("9.9.9.9", "/login", "GET", assessment(15, ["Sensitive decoy endpoint visited"]), features("login"))
        multiple = endpoints_manager.evaluate(
            "9.9.9.9", "/admin", "GET", assessment(15, ["Sensitive decoy endpoint visited"]), features("admin")
        )
        self.assertIn("Multiple sensitive endpoints accessed", multiple["indicators"])

    def test_flask_returns_generic_403_and_logs_response_action(self):
        manager = RiskResponseManager(block_after_high_risk=2)
        with tempfile.TemporaryDirectory() as directory:
            events_file = Path(directory) / "events.jsonl"
            database = HoneybotDatabase(Path(directory) / "events.sqlite")
            with patch.object(honeypot, "EVENTS_FILE", events_file), patch.dict(
                honeypot.app.config, {"DATABASE": database, "RISK_RESPONSE_MANAGER": manager}
            ):
                client = honeypot.app.test_client()
                allowed = client.get("/", headers={"User-Agent": "Browser"}, environ_base={"REMOTE_ADDR": "203.0.113.20"})
                rejected = client.get(
                    "/?q=../demo",
                    headers={"User-Agent": "sqlmap"},
                    environ_base={"REMOTE_ADDR": "203.0.113.20"},
                )
            self.assertEqual(allowed.status_code, 200)
            self.assertEqual(rejected.status_code, 403)
            self.assertIn(b"Request blocked by AI-Honeybot", rejected.data)
            events = [json.loads(line) for line in events_file.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([event["action"] for event in events], ["ALLOWED", "BLOCKED"])
            self.assertEqual(events[1]["method"], "GET")
            self.assertEqual(events[1]["risk"]["level"], "HIGH")

    def test_flask_login_logs_each_failed_attempt_and_blocks_on_third(self):
        manager = RiskResponseManager(block_after_high_risk=3)
        with tempfile.TemporaryDirectory() as directory:
            events_file = Path(directory) / "events.jsonl"
            database = HoneybotDatabase(Path(directory) / "events.sqlite")
            with patch.object(honeypot, "EVENTS_FILE", events_file), patch.dict(
                honeypot.app.config, {"DATABASE": database, "RISK_RESPONSE_MANAGER": manager}
            ), patch.dict(honeypot._ip_counts, {}, clear=True):
                client = honeypot.app.test_client()
                browser_headers = {"User-Agent": "Mozilla/5.0 Chrome/130.0"}
                # Reproduce a browser visit after prior ordinary browsing.
                # This builds up generic volume/rapid indicators but must not
                # prevent the decoy login form from being reached.
                for _ in range(12):
                    client.get("/", headers=browser_headers, environ_base={"REMOTE_ADDR": "127.0.0.1"})
                login_page = client.get(
                    "/login", headers=browser_headers, environ_base={"REMOTE_ADDR": "127.0.0.1"}
                )
                responses = [client.post(
                    "/login", data={"username": "demo", "password": "not-stored"}, headers=browser_headers,
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                ) for _ in range(4)]
            self.assertEqual(login_page.status_code, 200)
            self.assertEqual([response.status_code for response in responses], [401, 401, 403, 403])
            self.assertIn(b"Request blocked by AI-Honeybot", responses[2].data)
            events = [json.loads(line) for line in events_file.read_text(encoding="utf-8").splitlines()]
            login_events = [event for event in events if event["method"] == "POST" and event["endpoint"] == "/login"]
            self.assertEqual([event["source_ip"] for event in login_events], ["127.0.0.1"] * 4)
            self.assertEqual([event["features"]["authentication_failed"] for event in login_events], [True] * 4)
            self.assertEqual([event["source_risk"]["authentication_attempts"] for event in login_events], [1, 2, 3, 3])
            self.assertEqual([event["action"] for event in login_events], ["MONITORED", "MONITORED", "BLOCKED", "BLOCKED"])


if __name__ == "__main__":
    unittest.main()
