"""Fictional map locations for loopback-only simulator events."""
from __future__ import annotations

from ipaddress import ip_address
from typing import Any


_LOCATIONS = (
    {"country": "India", "city": "Synthetic Demo Zone A", "latitude": 28.6139, "longitude": 77.2090},
    {"country": "Germany", "city": "Synthetic Demo Zone B", "latitude": 52.5200, "longitude": 13.4050},
    {"country": "USA", "city": "Synthetic Demo Zone C", "latitude": 38.9072, "longitude": -77.0369},
)


def synthetic_demo_geo(source_ip: str) -> dict[str, Any]:
    """Return conspicuously fictional coordinates; never use for observed traffic."""
    parsed = ip_address(source_ip)
    if not parsed.is_loopback:
        raise ValueError("synthetic demo locations are restricted to loopback simulator sources")
    index = parsed.packed[-1] % len(_LOCATIONS)
    location = _LOCATIONS[index]
    return {
        "status": "synthetic_demo",
        "synthetic": True,
        "demo_label": "DEMO DATA — SIMULATED ATTACK",
        "demo_attacker_id": f"DEMO-ATTACKER-{index + 1:02d}",
        "country": location["country"],
        "city": location["city"],
        "approximate_location": f"SYNTHETIC DEMO — {location['city']}, {location['country']}",
        "latitude": location["latitude"],
        "longitude": location["longitude"],
    }
