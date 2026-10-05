import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as honeypot
from database import HoneybotDatabase
from deception import mode_for_risk, synthetic_endpoint
from risk_response import RiskResponseManager


class HoneypotSurfacesTests(unittest.TestCase):
    def test_ssh_style_decoy_returns_fixed_data_and_never_executes_command(self):
        with tempfile.TemporaryDirectory() as directory:
            database = HoneybotDatabase(Path(directory) / "state.sqlite")
            events = Path(directory) / "events.jsonl"
            with patch.object(honeypot, "EVENTS_FILE", events), patch.dict(honeypot.app.config,
                    {"DATABASE": database, "RISK_RESPONSE_MANAGER": RiskResponseManager()}):
                client = honeypot.app.test_client()
                login = client.post("/ssh/login", json={"username": "demo", "password": "fake"})
                command = client.post("/ssh/session", json={"command": "whoami"})
                unknown = client.post("/ssh/session", json={"command": "powershell Start-Process calc"})
            self.assertEqual(login.status_code, 401)
            self.assertEqual(command.json["output"], "analyst")
            self.assertFalse(command.json["executed"])
            if unknown.is_json:
                self.assertIn("unavailable", unknown.json["output"])
                self.assertFalse(unknown.json["executed"])
            else:
                self.assertEqual(unknown.status_code, 403)
            profile = database.get_attacker("127.0.0.1")
            self.assertEqual(profile["failed_logins"], 1)
            self.assertEqual(profile["commands"][:1], ["whoami"])

    def test_deception_tiers_change_at_risk_thresholds(self):
        self.assertEqual([mode_for_risk(score) for score in (0, 30, 60, 80)],
                         ["basic", "expanded", "deep_admin", "high_interaction"])
        self.assertIsNotNone(synthetic_endpoint("/backup", "expanded"))
        self.assertIsNone(synthetic_endpoint("/backup", "basic"))


if __name__ == "__main__":
    unittest.main()
