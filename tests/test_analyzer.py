import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import app as honeypot
from database import HoneybotDatabase
from analyzer import RuleBasedAnalyzer, analyze_request, extract_behavior_features


class AnalyzerTests(unittest.TestCase):
    def test_ordinary_homepage_is_low(self):
        result = analyze_request("GET", "/", "Mozilla/5.0")
        self.assertEqual(result["level"], "LOW")
        self.assertEqual(result["score"], 0)

    def test_sensitive_endpoint_is_low_with_visible_indicator(self):
        result = analyze_request("GET", "/admin", "Mozilla/5.0")
        self.assertEqual(result["level"], "LOW")  # One weak signal remains below threshold.
        self.assertIn("Sensitive decoy endpoint visited", result["indicators"])

    def test_traversal_and_scanner_are_high(self):
        result = analyze_request("GET", "/../etc/passwd", "sqlmap")
        self.assertEqual(result["level"], "HIGH")
        self.assertEqual(result["score"], 60)
        self.assertEqual(len(result["indicators"]), 2)

    def test_repeated_activity_increases_score(self):
        base = analyze_request("GET", "/", "Mozilla/5.0")
        repeated = analyze_request("GET", "/", "Mozilla/5.0", prior_requests_from_ip=6)
        self.assertGreater(repeated["score"], base["score"])
        self.assertEqual(repeated["level"], "LOW")

    def test_score_is_capped(self):
        result = analyze_request("DELETE", "/admin", "nikto", {"query": {"q": "../<script>"}}, 20)
        self.assertLessEqual(result["score"], 100)
        self.assertEqual(result["level"], "CRITICAL")

    def test_feature_extractor_returns_behavior_without_a_risk_label(self):
        features = extract_behavior_features(
            "get", "/login", "Mozilla/5.0", {"query": {"next": "/admin"}, "body": {"username": "student"}}, 4
        )
        self.assertEqual(features["method"], "GET")
        self.assertEqual(features["endpoint_category"], "login")
        self.assertTrue(features["has_query_parameters"])
        self.assertEqual(features["query_parameter_count"], 1)
        self.assertEqual(features["body_field_count"], 1)
        self.assertEqual(features["request_number_from_ip"], 5)
        self.assertNotIn("risk", features)

    def test_rule_analyzer_consumes_extracted_features(self):
        features = extract_behavior_features("GET", "/../demo", "sqlmap")
        result = RuleBasedAnalyzer().analyze(features)
        self.assertEqual(result["level"], "HIGH")
        self.assertEqual(result["score"], 60)


class EventFeatureLoggingTests(unittest.TestCase):
    def test_features_are_written_and_optional_detector_is_pluggable(self):
        class ExampleDetector:
            def score(self, features):
                self.received_features = features
                return 0.75

        detector = ExampleDetector()
        with tempfile.TemporaryDirectory() as directory:
            events_file = Path(directory) / "events.jsonl"
            database = HoneybotDatabase(Path(directory) / "events.sqlite")
            with patch.object(honeypot, "EVENTS_FILE", events_file), patch.dict(
                honeypot.app.config, {"ANOMALY_DETECTOR": detector, "DATABASE": database}
            ):
                response = honeypot.app.test_client().get("/?source=demo", headers={"User-Agent": "GuideDemo/1.0"})

            self.assertEqual(response.status_code, 200)
            event = json.loads(events_file.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(event["source_ip"], "127.0.0.1")
            self.assertEqual(event["source_geo"]["approximate_location"], "Local/Private network")
            self.assertEqual(event["features"]["query_parameter_count"], 1)
            self.assertEqual(event["features"]["endpoint_category"], "root")
            self.assertEqual(event["risk"]["level"], "LOW")
            self.assertEqual(event["anomaly"], {"score": 0.75, "detector": "ExampleDetector"})
            self.assertEqual(detector.received_features, event["features"])


if __name__ == "__main__":
    unittest.main()
