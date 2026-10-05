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
