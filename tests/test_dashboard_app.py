import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from demo_geo import synthetic_demo_geo


class DashboardAppTests(unittest.TestCase):
    def test_enter_security_center_selects_existing_dashboard_view(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "events.jsonl"
            with patch.dict(os.environ, {"HONEYPOT_EVENTS_FILE": str(log), "HONEYPOT_API_URL": "http://127.0.0.1:1"}):
                app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "dashboard.py"), default_timeout=20).run()
                enter_button = next(button for button in app.button if button.label == "ENTER SECURITY CENTER")
                app = enter_button.click().run()

            self.assertEqual([error.message for error in app.exception], [])
            self.assertEqual(app.radio[0].value, "Threats")
            self.assertTrue(any("Operational overview" in item.value for item in app.markdown))
            self.assertTrue(any(button.label == "▶  RUN DEMO" for button in app.button))
            self.assertTrue(any(button.label == "◉  LIVE DEMO" for button in app.button))

    def test_overview_renders_backend_demo_markers_and_status_without_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "events.jsonl"
            event = {"timestamp": datetime.now(timezone.utc).isoformat(), "source_ip": "127.0.0.42",
                     "method": "GET", "endpoint": "/.env", "event_type": "simulation",
                     "risk": {"score": 73, "level": "HIGH", "indicators": ["Synthetic decoy access"]},
                     "source_geo": synthetic_demo_geo("127.0.0.42"),
                     "ml": {"label": "credential_attack", "confidence": .9},
                     "action": "MONITORED", "details": {}, "features": {}}
            log.write_text(json.dumps(event) + "\n", encoding="utf-8")
            with patch.dict(os.environ, {"HONEYPOT_EVENTS_FILE": str(log), "HONEYPOT_API_URL": "http://127.0.0.1:1",
                                         "DEMO_MODE": "true"}):
                app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "dashboard.py"), default_timeout=20).run()
            self.assertEqual([error.message for error in app.exception], [])
            self.assertTrue(app.selectbox)
            self.assertTrue(any("DEMO-ATTACKER-01" in option for option in app.selectbox[0].options))
            rendered = "\n".join(element.value for element in app.markdown)
            self.assertIn("ADAPTIVE AI", rendered)
            self.assertIn("Observe. Learn. Deceive. Contain.", rendered)
            self.assertIn("Live threat activity", rendered)
            self.assertEqual({button.label for button in app.button} & {"ENTER SECURITY CENTER", "▶  RUN DEMO"},
                             {"ENTER SECURITY CENTER", "▶  RUN DEMO"})

    def test_live_demo_uses_three_attempt_containment_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "events.jsonl"
            with patch.dict(os.environ, {"HONEYPOT_EVENTS_FILE": str(log), "HONEYPOT_API_URL": "http://127.0.0.1:1"}):
                app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "dashboard.py"), default_timeout=20).run()
                live_button = next(button for button in app.button if button.label == "◉  LIVE DEMO")
                app = live_button.click().run()
                self.assertEqual([error.message for error in app.exception], [])
                runtime = app.session_state["live_demo_runtime"]
                self.assertEqual(len(runtime["events"]), 1)
                self.assertFalse(runtime["events"][-1]["block"])

                for expected_count in (2, 3):
                    runtime["last_attempt_monotonic"] = 0
                    app.run()
                    runtime = app.session_state["live_demo_runtime"]
                    self.assertEqual(len(runtime["events"]), expected_count)
                    if expected_count < 3:
                        self.assertFalse(runtime["events"][-1]["block"])

                self.assertTrue(runtime["events"][-1]["block"])
                self.assertEqual(runtime["events"][-1]["source_ip"], "203.0.113.10")
                self.assertEqual(runtime["events"][-1]["risk_level"], "HIGH")
                self.assertEqual([error.message for error in app.exception], [])
                rendered = "\n".join(element.value for element in app.markdown)
                self.assertIn("Threat detected — source temporarily blocked due to repeated suspicious activity.", rendered)
                self.assertFalse(log.exists())

    def test_new_intelligence_views_render_without_changing_backend_contracts(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "events.jsonl"
            event = {"timestamp": datetime.now(timezone.utc).isoformat(), "source_ip": "127.0.0.42",
                     "method": "GET", "endpoint": "/.env", "event_type": "simulation",
                     "risk": {"score": 73, "level": "HIGH", "indicators": ["Synthetic decoy access"]},
                     "source_geo": synthetic_demo_geo("127.0.0.42"),
                     "ml": {"label": "credential_attack", "confidence": .9}, "action": "MONITORED",
                     "deception_change": {"previous_mode": "basic", "new_mode": "expanded", "reason": "risk increased"},
                     "block": {}, "details": {}, "features": {}}
            log.write_text(json.dumps(event) + "\n", encoding="utf-8")
            with patch.dict(os.environ, {"HONEYPOT_EVENTS_FILE": str(log), "HONEYPOT_API_URL": "http://127.0.0.1:1"}):
                app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "dashboard.py"), default_timeout=20).run()
                for page, expected in (("Deception", "Adaptive deception"), ("Containment", "Temporary containment"),
                                       ("AI Analysis", "Evidence-led behavior assessment"), ("Attackers", "Observed sources")):
                    app.radio[0].set_value(page).run()
                    self.assertEqual([error.message for error in app.exception], [], page)
                    rendered = "\n".join(element.value for element in app.markdown)
                    self.assertIn(expected, rendered)


if __name__ == "__main__":
    unittest.main()
