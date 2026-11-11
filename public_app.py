"""Public WSGI entry point for the decoy-only hosted demonstration.

This gate intentionally keeps the Flask/FastAPI analyst APIs private. It also
uses Render's Cloudflare client-IP header (never X-Forwarded-For) for request
attribution and applies in-memory request ceilings before entering the app.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from ipaddress import ip_address
from typing import Callable, Iterable

from app import app as honeypot_app

_WINDOW_SECONDS = 60.0
_PER_IP_LIMIT = 60
_GLOBAL_LIMIT = 300
_MAX_TRACKED_IPS = 4096
_lock = threading.Lock()
_recent_by_ip: dict[str, deque[float]] = {}
_recent_global: deque[float] = deque()
_last_cleanup = 0.0

_PRIVATE_ROOTS = {"api", "docs", "redoc", "openapi.json", "dashboard", "metrics"}
_ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "TRACE", "OPTIONS"}
_SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
]


def _send(start_response: Callable, status: str, body: str) -> list[bytes]:
    encoded = body.encode("utf-8")
    start_response(status, [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(encoded))),
        ("Cache-Control", "no-store"),
        *_SECURITY_HEADERS,
    ])
    return [encoded]


def _client_ip(environ: dict) -> str:
    # Render's edge sets CF-Connecting-IP. Do not use X-Forwarded-For: client
    # supplied values can be preserved by some proxy chains.
    candidate = (environ.get("HTTP_CF_CONNECTING_IP") or environ.get("REMOTE_ADDR") or "unknown").strip()
    try:
        return str(ip_address(candidate))
    except ValueError:
        return "unknown"


def _limited(client: str, now: float) -> bool:
    global _last_cleanup
    cutoff = now - _WINDOW_SECONDS
    with _lock:
        while _recent_global and _recent_global[0] <= cutoff:
            _recent_global.popleft()

        if now - _last_cleanup >= _WINDOW_SECONDS:
            for source, history in list(_recent_by_ip.items()):
                while history and history[0] <= cutoff:
                    history.popleft()
                if not history:
                    del _recent_by_ip[source]
            _last_cleanup = now

        history = _recent_by_ip.get(client)
        if history is None:
            if len(_recent_by_ip) >= _MAX_TRACKED_IPS:
                return True
            history = _recent_by_ip[client] = deque()
        while history and history[0] <= cutoff:
            history.popleft()

        if len(history) >= _PER_IP_LIMIT or len(_recent_global) >= _GLOBAL_LIMIT:
            return True
        history.append(now)
        _recent_global.append(now)
        return False


def _with_security_headers(start_response: Callable) -> Callable:
    def secured(status: str, headers: list[tuple[str, str]], exc_info=None):
        existing = {name.lower() for name, _value in headers}
        headers.extend((name, value) for name, value in _SECURITY_HEADERS if name.lower() not in existing)
        return start_response(status, headers, exc_info)

    return secured


def application(environ: dict, start_response: Callable) -> Iterable[bytes]:
    path = environ.get("PATH_INFO", "/") or "/"
    segments = [segment.casefold() for segment in path.split("/") if segment and segment not in {".", ".."}]
    first_segment = segments[0] if segments else ""

    if path == "/healthz" and environ.get("REQUEST_METHOD", "GET").upper() == "GET":
        return _send(start_response, "200 OK", "ok\n")
    if first_segment in _PRIVATE_ROOTS:
        return _send(start_response, "404 Not Found", "Not found\n")
    if environ.get("REQUEST_METHOD", "GET").upper() not in _ALLOWED_METHODS:
        return _send(start_response, "405 Method Not Allowed", "Method not allowed\n")
    if _limited(_client_ip(environ), time.monotonic()):
        return _send(start_response, "429 Too Many Requests", "Rate limit exceeded\n")

    # The source address is replaced with the validated edge address so the
    # existing event logger and temporary containment policy see the requester.
    public_environ = dict(environ)
    public_environ["REMOTE_ADDR"] = _client_ip(environ)
    return honeypot_app(public_environ, _with_security_headers(start_response))


app = application
