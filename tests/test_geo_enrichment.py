import unittest

from geo_enrichment import enrich_source_ip


class FakeGeoIPEnricher:
    def __init__(self):
        self.lookups = []

    def lookup(self, public_ip):
        self.lookups.append(public_ip)
        return {
            "country": "Exampleland",
            "region": "North",
            "city": "Sample City",
            "asn": 64500,
            "organization": "Example Network",
            "network": "8.8.8.0/24",
            "latitude": 12.5,
            "longitude": 77.6,
        }


class GeoEnrichmentTests(unittest.TestCase):
    def test_local_private_and_loopback_ips_skip_lookup(self):
        enricher = FakeGeoIPEnricher()
        for address in ("127.0.0.1", "::1", "10.0.0.2", "192.168.1.5", "169.254.1.2"):
            with self.subTest(address=address):
                result = enrich_source_ip(address, enricher)
                self.assertEqual(result["approximate_location"], "Local/Private network")
                self.assertEqual(result["status"], "local_private")
        self.assertEqual(enricher.lookups, [])

    def test_public_ip_gets_approximate_location_and_asn(self):
        enricher = FakeGeoIPEnricher()
        result = enrich_source_ip("8.8.8.8", enricher)
        self.assertEqual(enricher.lookups, ["8.8.8.8"])
        self.assertEqual(result["approximate_location"], "Approximate: Sample City, North, Exampleland")
        self.assertEqual(result["asn"], "AS64500")
        self.assertEqual(result["network"], "8.8.8.0/24")
        self.assertEqual((result["latitude"], result["longitude"]), (12.5, 77.6))

    def test_public_ip_without_provider_is_not_looked_up(self):
        result = enrich_source_ip("8.8.8.8")
        self.assertEqual(result["status"], "not_configured")
        self.assertEqual(result["city"], None)

    def test_invalid_or_non_public_address_is_not_looked_up(self):
        enricher = FakeGeoIPEnricher()
        self.assertEqual(enrich_source_ip("not-an-ip", enricher)["status"], "invalid_ip")
        self.assertEqual(enrich_source_ip("192.0.2.1", enricher)["status"], "non_public")
        self.assertEqual(enricher.lookups, [])

    def test_lookup_failure_does_not_raise(self):
        class FailingEnricher:
            def lookup(self, _public_ip):
                raise OSError("database unavailable")

        result = enrich_source_ip("8.8.8.8", FailingEnricher())
        self.assertEqual(result["status"], "lookup_error")
        self.assertEqual(result["latitude"], None)


if __name__ == "__main__":
    unittest.main()
