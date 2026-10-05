"""End-to-end local demo using only loopback services and synthetic inputs."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
API_BASE = os.environ.get("HONEYPOT_API_URL", "http://127.0.0.1:8000").rstrip("/")
DEMO_SOURCE = "127.0.0.42"


def port_open(port: int) -> bool:
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


def post(path: str, payload: dict) -> dict:
    request = Request(API_BASE + path, data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=4) as response:
            return json.loads(response.read())
    except HTTPError as error:
        return json.loads(error.read())
    except URLError as error:
        raise SystemExit("FastAPI is not available. This runner starts it when possible.") from error


def verify_api() -> None:
    try:
        with urlopen(API_BASE + "/api/health", timeout=3) as response:
            health = json.loads(response.read())
    except URLError as error:
        raise SystemExit("Loopback port 8000 does not provide the HoneyBot API.") from error
    if health.get("service") != "adaptive-ai-honeybot":
        raise SystemExit("Port 8000 belongs to another service; demo stopped without sending events.")


def main() -> None:
    process = None
    api_port = urlsplit(API_BASE).port or 80
    if not port_open(api_port):
        os.environ["DEMO_MODE"] = "true"
        process = subprocess.Popen([sys.executable, "-m", "uvicorn", "api_server:app", "--host", "127.0.0.1", "--port", str(api_port)],
                                   cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        for _ in range(100):
            if port_open(8000):
                break
            if process.poll() is not None:
                raise SystemExit("Could not start local FastAPI. Check that requirements are installed.")
            time.sleep(.1)
    verify_api()
    print("Starting local synthetic attacker sequence...")
    sequence = [
        {"endpoint": "/", "method": "GET"},
        {"endpoint": "/login", "method": "POST", "authentication_failed": True},
        {"endpoint": "/login", "method": "POST", "authentication_failed": True},
        {"endpoint": "/wp-admin", "method": "GET", "user_agent": "nmap/7.95"},
        {"endpoint": "/.env", "method": "GET"},
        {"endpoint": "/api/v1/users", "method": "GET", "user_agent": "sqlmap"},
        {"endpoint": "/ssh/session", "method": "POST", "user_agent": "HoneyBotDemo/1.0"},
        {"endpoint": "/login", "method": "POST", "authentication_failed": True},
    ]
    for item in sequence:
        event = post("/api/simulation/event", {"source_ip": DEMO_SOURCE, **item})
        risk = event.get("risk", {})
        shift = event.get("deception_change")
        print(f"{item['method']} {item['endpoint']}: risk {risk.get('score')} {risk.get('level')} | {event.get('ml', {}).get('label')}")
        if shift:
            print(f"  deception {shift.get('previous_mode')} -> {shift.get('new_mode')}")
    for source_ip in ("127.0.0.43", "127.0.0.44"):
        for endpoint, agent in (("/.env", "HoneyBotDemo/1.0"), ("/admin", "nmap/7.95")):
            point = post("/api/simulation/event", {"source_ip": source_ip, "endpoint": endpoint, "user_agent": agent})
            print(f"{point['source_geo']['demo_attacker_id']} appeared: {point['source_geo']['demo_label']}")
    assessment = post("/api/agent/analyze", {"source_ip": DEMO_SOURCE})
    print("Agent assessment:", json.dumps(assessment, indent=2))
    containment = post("/api/response/contain", {"source_ip": DEMO_SOURCE,
        "reason": "Demo policy after accumulated synthetic observations"})
    print("Containment:", json.dumps(containment, indent=2))
    profile_request = Request(API_BASE + f"/api/attackers/{DEMO_SOURCE}")
    try:
        with urlopen(profile_request, timeout=4) as response:
            profile = json.loads(response.read())
    except HTTPError as error:
        profile = json.loads(error.read())
    print(f"Profile history stored: {profile.get('total_events', 0)} events")
    report_request = Request(API_BASE + f"/api/threats/report/{DEMO_SOURCE}", method="POST")
    with urlopen(report_request, timeout=4) as response:
        report = json.loads(response.read())
    print(f"Threat report generated: {report['report_id']}")
    all_attacks = Request(API_BASE + "/api/attacks?limit=1000")
    with urlopen(all_attacks, timeout=4) as response:
        events = json.loads(response.read()).get("events", [])
    map_points = {event.get("source_geo", {}).get("demo_attacker_id") for event in events
                  if event.get("source_geo", {}).get("synthetic")}
    print(f"Synthetic threat map points: {len(map_points)} ({', '.join(sorted(map_points))})")
    print(f"FastAPI docs: {API_BASE}/docs")
    print("Dashboard: run streamlit run dashboard.py --server.address 127.0.0.1")
    if process:
        print(f"Demo API remains running on loopback at {API_BASE}")


if __name__ == "__main__":
    main()
