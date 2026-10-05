"""Shared helpers for localhost-only demonstration traffic."""
from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE_URL = "http://127.0.0.1:5000"
_VERIFIED = False


def verify_local_honeypot() -> None:
    global _VERIFIED
    if _VERIFIED:
        return
    try:
        with urlopen(BASE_URL + "/api/health", timeout=3) as response:
            health = json.loads(response.read(2000))
    except (HTTPError, URLError, TimeoutError) as error:
        raise SystemExit("Local Flask honeypot is not available at 127.0.0.1:5000; start `python app.py`.") from error
    if health.get("service") != "adaptive-ai-honeybot":
        raise SystemExit("Port 5000 is not serving Adaptive AI HoneyBot; simulator stopped without sending events.")
    _VERIFIED = True


def send(path: str, *, method: str = "GET", data: dict | None = None, user_agent: str = "HoneyBotDemo/1.0") -> tuple[int, str]:
    verify_local_honeypot()
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("simulator paths must be local absolute paths")
    body = None
    headers = {"User-Agent": user_agent}
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    request = Request(BASE_URL + path, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, response.read(2000).decode(errors="replace")
    except HTTPError as error:
        return error.code, error.read(1000).decode(errors="replace")
    except URLError as error:
        raise SystemExit("Local honeypot is not running. Start it with: python app.py") from error
