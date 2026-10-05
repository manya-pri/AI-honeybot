"""Run a clean, temporary API + dashboard demonstration and discard its state."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for(url: str, process: subprocess.Popen, label: str) -> None:
    last_error: Exception | None = None
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited during startup with code {process.returncode}")
        try:
            with urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception as error:
            last_error = error
        time.sleep(0.2)
    raise RuntimeError(f"{label} health check timed out: {last_error}")


def main() -> None:
    api_port, ui_port = free_port(), free_port()
    with TemporaryDirectory(prefix="honeybot-demo-") as temp:
        env = os.environ.copy()
        env.update({
            "HONEYPOT_DATABASE": str(Path(temp) / "demo.sqlite"),
            "HONEYPOT_EVENTS_FILE": str(Path(temp) / "events.jsonl"),
            "HONEYPOT_API_URL": f"http://127.0.0.1:{api_port}",
            "DEMO_MODE": "true", "LLM_ENABLED": "false",
        })
        # The in-process scenario runner must target the same temporary API
        # and storage paths inherited by the two child services.
        os.environ.update(env)
        api = ui = None
        try:
            api = subprocess.Popen([sys.executable, "-m", "uvicorn", "api_server:app", "--host", "127.0.0.1",
                                    "--port", str(api_port)], cwd=ROOT, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            wait_for(f"{env['HONEYPOT_API_URL']}/api/health", api, "FastAPI")
            ui = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "dashboard.py", "--server.address",
                                   "127.0.0.1", "--server.port", str(ui_port), "--server.headless", "true"],
                                  cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            wait_for(f"http://127.0.0.1:{ui_port}/_stcore/health", ui, "Streamlit dashboard")

            from scripts.demo_mode import main as play_sequence
            play_sequence()

            from dashboard_data import prepare_dashboard_data
            import json
            events_path = Path(env["HONEYPOT_EVENTS_FILE"])
            events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
            dashboard = prepare_dashboard_data(events)
            if len(dashboard["demo_map"]) != 3 or not dashboard["demo_mode"]:
                raise RuntimeError(f"dashboard map data incomplete: {len(dashboard['demo_map'])} points")
            if dashboard["summary"]["currently_blocked"] < 1:
                raise RuntimeError("expected the suspicious primary source to be temporarily contained")
            print(f"Verified clean demo database: {len(events)} events, {len(dashboard['demo_map'])} synthetic map markers.")
            print(f"Dashboard health: http://127.0.0.1:{ui_port}/_stcore/health (HTTP 200)")
        finally:
            for process in (ui, api):
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == "__main__":
    main()
