import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from behaviour import engineer_features
from database import HoneybotDatabase, SQLiteRiskStore
from ml_engine import BehaviorModel
from risk_response import RiskResponseManager
import ml_engine


class PersistenceAndMLTests(unittest.TestCase):
    def test_events_profiles_and_risk_state_survive_database_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.sqlite"
            database = HoneybotDatabase(path)
            manager = RiskResponseManager(store=SQLiteRiskStore(database), block_after_high_risk=3)
            for _ in range(3):
                result = manager.evaluate("127.0.0.1", "/login", "POST",
                    {"score": 15, "indicators": ["Sensitive decoy endpoint visited"]},
                    {"endpoint_category": "login"}, authentication_failed=True,
                    now=datetime(2026, 1, 1, tzinfo=timezone.utc))
            self.assertEqual(result["source_risk"]["authentication_attempts"], 3)
            database.save_event({"timestamp": "2026-01-01T00:00:00+00:00", "source_ip": "127.0.0.1",
                "endpoint": "/login", "method": "POST", "features": {"authentication_failed": True},
                "risk": {"score": 60, "level": "HIGH", "indicators": ["Repeated authentication attempts"]},
                "action": "BLOCKED"})
            profile = database.get_attacker("127.0.0.1")
            self.assertEqual(profile["failed_logins"], 1)
            reopened = HoneybotDatabase(path)
            self.assertEqual(reopened.list_events()[0]["endpoint"], "/login")
            self.assertEqual(reopened.get_attacker("127.0.0.1")["total_events"], 1)
            persisted = RiskResponseManager(store=SQLiteRiskStore(reopened))
            state = persisted.source_states()[0]
            self.assertEqual(state["authentication_attempts"], 3)

    def test_feature_engineering_uses_event_history(self):
        events = [
            {"timestamp": "2026-01-01T00:00:00+00:00", "endpoint": "/login", "method": "POST",
             "service": "http", "features": {"authentication_failed": True}, "risk": {"score": 30, "indicators": ["login"]}},
            {"timestamp": "2026-01-01T00:00:30+00:00", "endpoint": "/credentials.txt", "method": "GET",
             "service": "http", "features": {"decoy_resource_access": True}, "risk": {"score": 50, "indicators": ["decoy"]}},
        ]
        features = engineer_features(events)
        self.assertEqual(features["failed_login_count"], 1)
        self.assertEqual(features["unique_endpoints"], 2)
        self.assertEqual(features["historical_risk"], 50)
        self.assertEqual(features["decoy_resource_access"], 1)

    def test_random_forest_predicts_and_kmeans_clusters_observed_profiles(self):
        model = BehaviorModel()
        result = model.classify({"historical_risk": 80, "suspicious_event_count": 8,
                                 "unique_endpoints": 10, "events_per_minute": 6})
        self.assertIn(result["label"], {"normal", "reconnaissance", "brute_force", "credential_attack",
                                         "suspicious_access", "command_execution", "exploitation_attempt"})
        self.assertGreaterEqual(result["confidence"], 0)
        self.assertEqual(result["model"], "RandomForestClassifier")
        a = {"source_ip": "1.1.1.1", "events": [{"timestamp": "2026-01-01T00:00:00Z", "endpoint": "/a",
             "risk": {"score": 0}}]}
        b = {"source_ip": "2.2.2.2", "events": [{"timestamp": "2026-01-01T00:00:00Z", "endpoint": "/b",
             "risk": {"score": 1}}]}
        clusters = model.cluster_profiles([a, b])
        self.assertTrue(clusters)
        self.assertTrue(all(item["ground_truth"] is False for item in clusters))

    def test_model_dependency_failure_uses_safe_rule_fallback(self):
        original = ml_engine._DEFAULT_MODEL
        try:
            with patch.object(ml_engine, "ML_AVAILABLE", False):
                ml_engine._DEFAULT_MODEL = None
                model = ml_engine.get_model()
                prediction = model.classify({"failed_login_count": 4})
                self.assertEqual(prediction["label"], "brute_force")
                self.assertEqual(prediction["model"], "transparent-rule-fallback")
        finally:
            ml_engine._DEFAULT_MODEL = original


if __name__ == "__main__":
    unittest.main()
