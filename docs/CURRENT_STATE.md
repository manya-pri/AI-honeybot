# Current state

## Existing functionality (preserved)

- Flask decoy binds to loopback, caps request bodies, redacts credential-like submitted fields, and writes JSON Lines events.
- `analyzer.py` extracts per-request features and explainable rule indicators. `risk_response.py` supports persistent SQLite state and a temporary in-memory fallback, with reversible temporary blocks.
- `geo_enrichment.py` skips local/reserved addresses and optionally reads local MaxMind databases.
- `dashboard.py` and `dashboard_data.py` provide the existing Streamlit SOC-style overview, sources, containment and timeline views.
- The existing unit tests cover rules, risk policy, enrichment and dashboard transformations.

## Gaps found

Attacker/risk memory is lost on restart; there is no trained classifier, clustering, SSH listener, FastAPI, relational database, Docker setup, demo orchestrator, or model evaluation. The dashboard is a file-backed Streamlit app rather than an API-backed SPA. Existing block policy rejects individually HIGH requests and applies a temporary source block after its configured streak; the login threshold has a separate local demo exception.

## Preserve and extend

Keep Flask routes, JSONL event compatibility, redaction, local-only bind, transparent rule baseline, GeoIP safeguards, dashboard, and tests. Add synthetic decoys and read-only profile/summary/timeline/analysis endpoints without exposing host data or introducing shell access.

## Refactoring/additions

Add documentation of actual guarantees and limitations, expand endpoint feature detection, and expose derived attacker history from recorded events. Persistent database storage, real ML, SSH emulation and compose deployment remain later phases; they must not be represented as implemented.

## Implemented in the continuation

The application now also dual-writes normalized events to SQLite; persists attacker aggregates, risk states, agent assessments and expiring containment; computes history-based behavior features; runs a Random Forest trained on seeded synthetic behavior cases and K-Means over observed profiles; provides a separate FastAPI API; records deception mode transitions; has fixed-response HTTP SSH-style routes; includes localhost-only simulators and an isolated clean-database demo runner; and has a loopback-bound Compose configuration. The optional LLM provider returns schema-validated recommendations only and falls back to the local agent. Simulator-only loopback events receive visibly synthetic map coordinates. The SSH-style interface is not a real SSH listener. Docker configuration has static checks, but container execution could not be validated on the current host because the Docker CLI is not installed.
