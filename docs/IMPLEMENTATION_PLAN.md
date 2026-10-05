# Implementation plan

1. **Inspect and document:** inventory current Flask, Streamlit, event JSONL, risk state, GeoIP, dependencies and tests; record preservation constraints in `CURRENT_STATE.md`.
2. **Safe integrated prototype:** retain the current architecture and add synthetic-only decoy resources, common event-level detection, and read-only health, attack, attacker, timeline and summary endpoints.
3. **Behavior assessment:** derive transparent agent assessments from recorded history; do not claim an LLM or trained classifier.
4. **Verification and docs:** run existing and added tests, document API, safety boundary, local run/demo process and reference concepts.
5. **Future expansion:** introduce SQLite repositories and evaluated scikit-learn model only with data provenance/labels; add separately isolated SSH simulation; consider FastAPI/Docker only after the current app is covered by integration tests.

The continuation implements persistent SQLite event/profile/risk memory, behavior features, synthetic-scenario Random Forest classification, profile clustering, FastAPI, safe simulation endpoints, fixed-output SSH-style HTTP interactions, risk-based deception, temporary containment/release, SOC agent view, local simulator scripts, a demo runner and a Docker Compose configuration. External LLM, actual SSH protocol service, independently evaluated production ML, PostgreSQL, and container runtime validation remain future work. The Docker CLI was unavailable on the implementation host.
