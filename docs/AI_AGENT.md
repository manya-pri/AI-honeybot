# AI security agent

`POST /api/agent/analyze` accepts a validated source IP and builds a compact context from its persisted profile, latest events (without request bodies or secrets), risk score, behavioral features, ML label, behavioral cluster, deception state, and previous response.

## Agent modes

- **Local** is the default and remains available when the provider is disabled, incomplete, malformed, or unreachable. It uses the existing Random Forest and transparent evidence/risk rules.
- **LLM** is opt-in through `LLM_ENABLED=true`, `LLM_API_KEY`, `LLM_MODEL`, and optional `LLM_BASE_URL` (default `https://api.openai.com/v1`). OpenAI Chat Completions-compatible providers must return the strict JSON assessment schema. HTTPS is required except for a provider deliberately hosted on loopback.

Both modes return `agent_mode` (`llm` or `local`) and `llm_used`. If an enabled provider is missing configuration or fails, the request returns a local result with a concise `fallback_reason`; the service stays available. `/api/agent/status` shows configured mode and the latest persisted assessment. Assessment results are kept in SQLite agent memory.

The structured assessment fields are `threat_type`, `confidence`, `behaviours`, `risk_assessment`, `recommended_action`, and `evidence_summary`. The agent is asked for concise evidence only; no chain-of-thought is requested or shown. Raw request bodies, login credentials, and authorization data are excluded from provider context.

An LLM has no tools, shell access, or response-policy authority. A recommendation does not itself block anything. The API's containment endpoint remains governed by the local risk manager, including the minimum three suspicious observations, and only creates a temporary block inside this honeypot.

For a local setup, copy `.env.example` to `.env` and configure the provider. Keep `.env` untracked; never put a real key in source code, logs, or screenshots. Without those settings, the local agent is used.
