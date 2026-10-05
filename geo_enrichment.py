"""Optional, local-database IP enrichment with conservative address handling.

No network lookup is performed. Public-IP enrichment is opt-in and uses local
MaxMind-format databases through the optional ``maxminddb`` package.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Protocol


_LOCAL_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


class GeoIPEnricher(Protocol):
    """Provider contract for local GeoIP databases or test doubles."""

    def lookup(self, public_ip: str) -> dict[str, Any]:
        """Return approximate geographic and network fields for a public IP."""


def _empty_result(label: str, status: str) -> dict[str, Any]:
    return {
        "approximate_location": label,
        "country": None,
        "region": None,
        "city": None,
        "asn": None,
        "organization": None,
        "network": None,
        "latitude": None,
        "longitude": None,
        "status": status,
    }


def enrich_source_ip(source_ip: str, enricher: GeoIPEnricher | None = None) -> dict[str, Any]:
    """Classify local addresses without lookup; optionally enrich public IPs.

    Geographic results are approximate network-registration/database estimates,
    never a claim about a person's physical location.
    """
    try:
        parsed_ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return _empty_result("Unknown source address", "invalid_ip")

    if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped:
        parsed_ip = parsed_ip.ipv4_mapped
    normalized_ip = str(parsed_ip)

    is_rfc1918_or_ula = any(parsed_ip.version == network.version and parsed_ip in network for network in _LOCAL_PRIVATE_NETWORKS)
    if parsed_ip.is_loopback or parsed_ip.is_link_local or is_rfc1918_or_ula:
        return _empty_result("Local/Private network", "local_private")
    if not parsed_ip.is_global:
        return _empty_result("Non-public/reserved address", "non_public")
    if enricher is None:
        return _empty_result("Approximate location unavailable (not configured)", "not_configured")

    try:
        result = enricher.lookup(normalized_ip)
    except Exception:
        # GeoIP must remain optional: enrichment failure cannot break logging.
        return _empty_result("Approximate location unavailable", "lookup_error")

    country = result.get("country")
    region = result.get("region")
    city = result.get("city")
    place = ", ".join(str(part) for part in (city, region, country) if part)
    latitude = result.get("latitude")
    longitude = result.get("longitude")
    if not isinstance(latitude, (int, float)) or not -90 <= latitude <= 90:
        latitude = None
    if not isinstance(longitude, (int, float)) or not -180 <= longitude <= 180:
        longitude = None

    asn_number = result.get("asn")
    asn = f"AS{asn_number}" if isinstance(asn_number, int) else asn_number
    return {
        "approximate_location": f"Approximate: {place}" if place else "Approximate location unavailable",
        "country": country,
        "region": region,
        "city": city,
        "asn": asn,
        "organization": result.get("organization"),
        "network": result.get("network"),
        "latitude": latitude,
        "longitude": longitude,
        "status": "enriched" if result else "no_match",
    }


class MaxMindGeoIPEnricher:
    """Look up public IPs in locally installed MaxMind City and/or ASN MMDBs."""

    def __init__(self, city_database: str | None = None, asn_database: str | None = None):
        if not city_database and not asn_database:
            raise ValueError("Configure at least one local GeoIP database.")
        try:
            import maxminddb
        except ImportError as exc:
            raise RuntimeError("Install the optional 'maxminddb' package to enable GeoIP databases.") from exc

        self._city_reader = maxminddb.open_database(city_database) if city_database else None
        self._asn_reader = maxminddb.open_database(asn_database) if asn_database else None

    @staticmethod
    def _read(reader: Any, address: str) -> tuple[dict[str, Any], str | None]:
        if reader is None:
            return {}, None
        record, prefix_length = reader.get_with_prefix_len(address)
        if not isinstance(record, dict):
            return {}, None
        network = None
        if isinstance(prefix_length, int):
            network = str(ipaddress.ip_network(f"{address}/{prefix_length}", strict=False))
        return record, network

    def lookup(self, public_ip: str) -> dict[str, Any]:
        city_record, city_network = self._read(self._city_reader, public_ip)
        asn_record, asn_network = self._read(self._asn_reader, public_ip)
        country = city_record.get("country", {}).get("names", {}).get("en")
        subdivisions = city_record.get("subdivisions", [])
        region = subdivisions[-1].get("names", {}).get("en") if subdivisions else None
        city = city_record.get("city", {}).get("names", {}).get("en")
        location = city_record.get("location", {})
        return {
            "country": country,
            "region": region,
            "city": city,
            "asn": asn_record.get("autonomous_system_number"),
            "organization": asn_record.get("autonomous_system_organization"),
            "network": asn_network or city_network,
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude"),
        }

    def close(self) -> None:
        for reader in (self._city_reader, self._asn_reader):
            if reader is not None:
                reader.close()
