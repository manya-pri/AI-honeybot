# Local demonstration

Install the project requirements and run:

```powershell
python scripts/run_demo_isolated.py
```

This starts FastAPI and the Streamlit dashboard on temporary loopback ports with a clean temporary SQLite database and JSONL event log. The repeatable sequence records login attempts, reconnaissance, a synthetic decoy credential access, ML classification, AI-agent analysis, adaptive deception, the three-suspicious-event threshold, temporary containment, profile and timeline updates, three map markers, and a stored threat report. Both services and temporary state are removed at the end.

The markers use fictional, fixed sample coordinates for demo attackers `127.0.0.42`, `.43`, and `.44`. The map and profile records label these as `DEMO DATA — SIMULATED ATTACK`; the locations are not real threat intelligence. Selecting or clicking a marker shows its demo attacker ID, synthetic location, attack type, risk, event count, and threat level.

For an interactive long-running demo, start the three local services in separate terminals using the commands in the README, then run `python scripts/demo_mode.py`. Individual HTTP-only simulators are in `scripts/`.
