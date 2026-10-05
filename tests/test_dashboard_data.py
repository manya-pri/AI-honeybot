import unittest
from datetime import datetime, timezone

from dashboard_data import prepare_dashboard_data
from demo_geo import synthetic_demo_geo


class DashboardDataTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 1, 11, 11, tzinfo=timezone.utc)
        self.events = [
            {
                "timestamp": "2026-10-01T11:00:00+00:00",
                "source_ip": "127.0.0.1",
                "method": "GET",
                "endpoint": "/",
                "risk": {"score": 0, "level": "LOW", "indicators": []},
                "action": "ALLOWED",
                "source_geo": {"status": "local_private", "approximate_location": "Local/Private network"},
                "source_risk": {"first_seen": "first", "last_seen": "last", "request_count": 2,
                                "suspicious_request_count": 0, "cumulative_risk_score": 0},
                "details": {},
                "features": {},
            },
            {
                "timestamp": "2026-10-01T11:05:00+00:00",
                "source_ip": "8.8.8.8",
                "method": "GET",
                "endpoint": "/admin",
                "risk": {"score": 80, "level": "HIGH", "indicators": ["Probe"]},
                "action": "BLOCKED",
                "block_expiry": "2026-10-01T12:05:00+00:00",
                "block": {"source_ip": "8.8.8.8", "risk_score": 80, "reason": "Repeated probes",
                          "first_seen": "2026-10-01T11:05:00+00:00", "last_seen": "2026-10-01T11:05:00+00:00",
                          "expires_at": "2026-10-01T12:05:00+00:00"},
                "source_geo": {"status": "enriched", "approximate_location": "Approximate: Sample City, Exampleland",
                               "city": "Sample City", "country": "Exampleland", "asn": "AS64500",
                               "network": "8.8.8.0/24", "latitude": 12.5, "longitude": 77.6},
                "source_risk": {"first_seen": "2026-10-01T11:00:00+00:00", "last_seen": "2026-10-01T11:05:00+00:00",
                                "request_count": 3, "suspicious_request_count": 3, "cumulative_risk_score": 100},
                "details": {},
                "features": {},
            },
            {
                "timestamp": "2026-10-01T11:10:00+00:00",
                "source_ip": "9.9.9.9",
                "method": "POST",
                "endpoint": "/login",
                "risk": {"score": 35, "level": "MEDIUM", "indicators": ["Repeated login"]},
                "action": "MONITORED",
                "source_geo": {"status": "not_configured"},
            },
        ]

    def test_summary_and_latest_source_state(self):
        data = prepare_dashboard_data(self.events, now=self.now)
        self.assertEqual(data["summary"], {
            "total_interactions": 3,
            "high_risk": 1,
            "high_risk_attackers": 1,
            "total_sources": 3,
            "active_sources": 3,
            "active_suspicious": 2,
            "currently_blocked": 1,
        })
        source = data["latest_by_source"].set_index("source_ip").loc["8.8.8.8"]
        self.assertEqual(source["cumulative_risk_score"], 100)
        self.assertEqual(source["current_status"], "TEMPORARILY BLOCKED")
        self.assertEqual(source["block_reason"], "Repeated probes")

    def test_expired_block_is_not_reported_as_current(self):
        later = datetime(2026, 10, 1, 13, tzinfo=timezone.utc)
        data = prepare_dashboard_data(self.events, now=later)
        self.assertEqual(data["summary"]["currently_blocked"], 0)
        source = data["latest_by_source"].set_index("source_ip").loc["8.8.8.8"]
        self.assertEqual(source["current_status"], "REQUEST REJECTED")

    def test_active_source_counts_use_recent_activity_window(self):
        later = datetime(2026, 10, 1, 11, 30, tzinfo=timezone.utc)
        data = prepare_dashboard_data(self.events, now=later)
        self.assertEqual(data["summary"]["total_sources"], 3)
        self.assertEqual(data["summary"]["active_sources"], 0)
        self.assertEqual(data["summary"]["active_suspicious"], 0)

    def test_private_and_unavailable_locations_are_never_invented(self):
        data = prepare_dashboard_data(self.events, now=self.now)
        sources = data["latest_by_source"].set_index("source_ip")
        self.assertEqual(sources.loc["127.0.0.1", "approximate_location"], "Local/Private network")
        self.assertEqual(sources.loc["9.9.9.9", "approximate_location"], "Location unavailable")

    def test_legacy_event_without_action_is_marked_as_recorded(self):
        data = prepare_dashboard_data([{"timestamp": "2026-10-01T11:00:00Z", "source_ip": "127.0.0.1",
                                        "risk": {"score": 5, "level": "LOW"}}], now=self.now)
        source = data["latest_by_source"].iloc[0]
        self.assertEqual(source["current_status"], "RECORDED")
        self.assertEqual(source["approximate_location"], "Location unavailable")

    def test_simulated_map_points_are_clear_synthetic_and_have_marker_details(self):
        events = [{"timestamp": self.now.isoformat(), "source_ip": f"127.0.0.{octet}",
                   "method": "GET", "endpoint": "/.env", "event_type": "simulation",
                   "risk": {"score": 73, "level": "HIGH", "indicators": ["Decoy access"]},
                   "ml": {"label": "credential_attack"}, "source_geo": synthetic_demo_geo(f"127.0.0.{octet}")}
                  for octet in (42, 43, 44)]
        data = prepare_dashboard_data(events, now=self.now)
        self.assertTrue(data["demo_mode"])
        self.assertEqual(len(data["demo_map"]), 3)
        first = data["demo_map"][0]
        self.assertEqual(first["attacker_id"], "DEMO-ATTACKER-01")
        self.assertEqual(first["attack_type"], "credential_attack")
        self.assertEqual(first["risk_score"], 73)
        self.assertEqual(first["event_count"], 1)
        self.assertEqual(first["threat_level"], "HIGH")
        self.assertIn("SYNTHETIC", first["location"])


if __name__ == "__main__":
    unittest.main()
