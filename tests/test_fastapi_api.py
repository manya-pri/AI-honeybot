import tempfile
import unittest
import json
import os
from pathlib import Path
from io import BytesIO
from unittest.mock import patch

from fastapi.testclient import TestClient

import api_server
from database import HoneybotDatabase, SQLiteRiskStore
from risk_response import RiskResponseManager


class FastApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = HoneybotDatabase(Path(self.temp.name) / "api.sqlite")
        self.policy = RiskResponseManager(store=SQLiteRiskStore(self.database))
        self.stack = patch.multiple(api_server, db=self.database, policy=self.policy,
                                    EVENTS_FILE=Path(self.temp.name) / "events.jsonl")
        self.stack.start()
        self.client = TestClient(api_server.app)

    def tearDown(self):
        self.stack.stop()
        self.temp.cleanup()

    def test_simulation_agent_profile_and_containment_threshold(self):
        invalid = self.client.post("/api/simulation/event", json={"source_ip": "8.8.8.8"})
        self.assertEqual(invalid.status_code, 422)
        scores = []
        for _ in range(2):
            response = self.client.post("/api/simulation/event", json={
                "source_ip": "127.0.0.61", "endpoint": "/../../etc/passwd", "user_agent": "nmap demo"})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["source_geo"]["synthetic"])
            self.assertIn("DEMO DATA", response.json()["source_geo"]["demo_label"])
            scores.append(response.json()["risk"]["score"])
            self.assertIsNotNone(response.json()["deception_change"])
        early = self.client.post("/api/response/contain", json={"source_ip": "127.0.0.61"})
        self.assertEqual(early.status_code, 409)
        event = self.client.post("/api/simulation/event", json={
            "source_ip": "127.0.0.61", "endpoint": "/../../etc/passwd", "user_agent": "nmap demo"})
        self.assertIn(event.json()["risk"]["level"], {"HIGH", "CRITICAL"})
        self.assertGreaterEqual(event.json()["risk"]["score"], scores[0])
        event_record = self.client.get("/api/attacks/" + event.json()["event_id"])
        self.assertEqual(event_record.status_code, 200)
        contained = self.client.post("/api/response/contain", json={"source_ip": "127.0.0.61"})
        self.assertEqual(contained.status_code, 200)
        released = self.client.delete("/api/response/contain/127.0.0.61")
        self.assertEqual(released.status_code, 200)
        self.assertEqual(released.json()["status"], "released")
        profile = self.client.get("/api/attackers/127.0.0.61")
        self.assertEqual(profile.json()["total_events"], 3)
        self.assertIn("ml", profile.json())
        self.assertEqual(self.client.get("/api/attackers/127.0.0.61/timeline").status_code, 200)
        report = self.client.post("/api/threats/report/127.0.0.61")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.json()["event_count"], 3)
        self.assertEqual(len(self.client.get("/api/threats/reports").json()["reports"]), 1)

    def test_agent_api_exposes_local_mode_and_uses_validated_llm_when_configured(self):
        for _ in range(3):
            response = self.client.post("/api/simulation/event", json={
                "source_ip": "127.0.0.63", "endpoint": "/.env", "user_agent": "nmap demo"})
            self.assertEqual(response.status_code, 200)
        with patch.dict(os.environ, {"LLM_ENABLED": "false"}):
            local_status = self.client.get("/api/agent/status").json()
            local = self.client.post("/api/agent/analyze", json={"source_ip": "127.0.0.63"}).json()
        self.assertEqual(local_status["agent_mode"], "local")
        self.assertEqual(local["agent_mode"], "local")
        self.assertFalse(local["llm_used"])
        llm_payload = {"threat_type": "credential_attack", "confidence": 0.9,
            "behaviours": ["Synthetic credential endpoint accessed"],
            "risk_assessment": "Repeated requests indicate decoy hunting.",
            "recommended_action": "adaptive_deception", "evidence_summary": "Three suspicious events recorded."}
        response_payload = {"choices": [{"message": {"content": json.dumps(llm_payload)}}]}

        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _limit=-1): return json.dumps(response_payload).encode()

        with patch.dict(os.environ, {"LLM_ENABLED": "true", "LLM_API_KEY": "unit-test-key", "LLM_MODEL": "unit-test-model"}):
            with patch("agent.urlopen", return_value=FakeResponse()):
                result = self.client.post("/api/agent/analyze", json={"source_ip": "127.0.0.63"}).json()
        self.assertEqual(result["agent_mode"], "llm")
        self.assertTrue(result["llm_used"])
        self.assertEqual(result["threat_type"], "credential_attack")
        self.assertIn("risk_assessment", result)
        self.assertEqual(len(self.database.list_agent_assessments()), 2)


if __name__ == "__main__":
    unittest.main()
