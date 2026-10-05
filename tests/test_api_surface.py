import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as honeypot
from risk_response import RiskResponseManager
from database import HoneybotDatabase


class ApiSurfaceTests(unittest.TestCase):
    def test_decoy_files_are_synthetic_and_profile_api_uses_event_history(self):
        with tempfile.TemporaryDirectory() as directory:
            events_file = Path(directory) / "events.jsonl"
            database = HoneybotDatabase(Path(directory) / "events.sqlite")
            with patch.object(honeypot, "EVENTS_FILE", events_file), patch.dict(
                honeypot.app.config, {"DATABASE": database, "RISK_RESPONSE_MANAGER": RiskResponseManager()}
            ), patch.dict(honeypot._ip_counts, {}, clear=True):
                client = honeypot.app.test_client()
                response = client.get("/credentials.txt", environ_base={"REMOTE_ADDR": "127.0.0.1"})
                attacks = client.get("/api/attacks", environ_base={"REMOTE_ADDR": "127.0.0.1"})
                profile = client.get("/api/attackers", environ_base={"REMOTE_ADDR": "127.0.0.1"})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"FAKE_PASSWORD", response.data)
            self.assertNotIn(b"real", response.data.lower())
            event = json.loads(events_file.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(event["source_ip"], "127.0.0.1")
            self.assertEqual(attacks.json["events"][0]["endpoint"], "/credentials.txt")
            # The profile endpoint itself is also an observed HTTP event.
            self.assertGreaterEqual(profile.json["attackers"][0]["total_events"], 1)

    def test_agent_analysis_validates_ip_and_discloses_deterministic_method(self):
        with tempfile.TemporaryDirectory() as directory:
            events_file = Path(directory) / "events.jsonl"
            database = HoneybotDatabase(Path(directory) / "events.sqlite")
            with patch.object(honeypot, "EVENTS_FILE", events_file), patch.dict(honeypot.app.config, {"DATABASE": database}), \
                    patch.dict(os.environ, {"LLM_ENABLED": "false"}):
                client = honeypot.app.test_client()
                invalid = client.post("/api/agent/analyze", json={"source_ip": []})
                empty = client.post("/api/agent/analyze", json={"source_ip": "127.0.0.1"})
            self.assertEqual(invalid.status_code, 400)
            self.assertIn(empty.json["model"], {"RandomForestClassifier", "transparent-rule-memory"})
            self.assertFalse(empty.json["llm_used"])


if __name__ == "__main__":
    unittest.main()
