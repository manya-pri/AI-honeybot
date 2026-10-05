# Local JSON API

The existing Flask app binds to `127.0.0.1:5000` and retains its JSON-compatible routes. A FastAPI service backed by the same SQLite file is available on `127.0.0.1:8000` and provides generated OpenAPI documentation at `/docs`.

| Method and path | Behavior |
|---|---|
| `GET /api/health` | Local service mode/status |
| `GET /api/attacks?limit=100` | Recent persisted JSONL events; limit 1–500 |
| `GET /api/attackers` | History-derived per-IP aggregate |
| `GET /api/attackers/<ip>/timeline` | Recorded timeline for the path IP |
| `GET /api/dashboard/summary` | Event, source, high-risk and active-block counts |
| `GET /api/threats` | Recent HIGH/CRITICAL recorded events |
| `GET /api/metrics` | Counts by risk level and action |
| `GET /api/agent/status` | Deterministic analysis status |
| `GET /api/agent/decisions` | Explainable risk/action records with evidence |
| `POST /api/agent/analyze` | Evidence-based summary; JSON `{"source_ip":"127.0.0.1"}` |

FastAPI additionally provides `GET /api/attacks/{event_id}`, `POST /api/simulation/event`, `POST /api/response/contain`, `DELETE /api/response/contain/{source_ip}`, `POST /api/threats/report/{source_ip}`, and `GET /api/threats/reports`. Simulation source IPs must be loopback addresses. Containment requires at least three suspicious observations and risk >= 60, is temporary, and can be released explicitly.

Flask retains compatibility JSON routes; FastAPI adds typed validation and generated OpenAPI at `/docs`. Agent responses identify the classifier and set `llm_used: false`. Missing/corrupt JSONL history degrades to empty results in the Flask compatibility API. Do not bind this prototype to a public interface.
