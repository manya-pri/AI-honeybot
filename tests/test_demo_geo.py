import unittest

from demo_geo import synthetic_demo_geo


class DemoGeoTests(unittest.TestCase):
    def test_loopback_simulator_points_are_marked_synthetic_and_stable(self):
        values = [synthetic_demo_geo(f"127.0.0.{octet}") for octet in (42, 43, 44)]
        self.assertEqual([value["demo_attacker_id"] for value in values], [
            "DEMO-ATTACKER-01", "DEMO-ATTACKER-02", "DEMO-ATTACKER-03"])
        self.assertEqual({value["country"] for value in values}, {"India", "Germany", "USA"})
        self.assertTrue(all(value["synthetic"] and "DEMO DATA" in value["demo_label"] for value in values))
        self.assertTrue(all(-90 <= value["latitude"] <= 90 and -180 <= value["longitude"] <= 180 for value in values))

    def test_synthetic_coordinates_are_never_assigned_to_public_ip(self):
        with self.assertRaises(ValueError):
            synthetic_demo_geo("203.0.113.7")


if __name__ == "__main__":
    unittest.main()
