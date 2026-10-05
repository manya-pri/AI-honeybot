# Security boundaries

- Bind the demo only to loopback. Do not reverse-proxy or expose it to an untrusted network.
- Decoy resources contain static synthetic strings and sample records only. No host files, keys, credentials or real customer data are read.
- Login submission values are redacted before logging; arbitrary raw bodies are not retained.
- Classifier inference is deterministic over persisted features. The Random Forest uses synthetic training scenarios; there is no model-generated action, shell tool or arbitrary command execution.
- Optional LLM triage is disabled by default. When enabled, only compact attacker profile fields and recent method/path/risk/classification evidence are sent to the configured HTTPS provider; raw request bodies, credentials, and authorization headers are excluded. Keep `LLM_API_KEY` in an untracked local environment file or secret manager.
- LLM output must validate against a strict schema and its action is a recommendation only. Invalid output, missing credentials, or provider/network errors fall back to the local agent. The backend's existing risk manager enforces the three-suspicious-event minimum before temporary containment.
- Docker exposes only the reverse proxy on `127.0.0.1:8080`; application ports stay on the Compose network. The bridge permits outbound traffic so an explicitly configured LLM provider can be reached.
- Risk policy can issue only a temporary source block within this Flask process. It cannot change firewall rules, affect external systems or retaliate. Local login-threshold blocks exist for demonstrating reversible behavior.
- GeoIP is optional, local-database-only, and never looks up local/private/reserved IPs.
- Simulator-only loopback events can receive fictional map coordinates and IDs. These records carry `synthetic: true` and a visible `DEMO DATA — SIMULATED ATTACK` label. They are not attached to live Flask traffic or presented as real geolocation.
- JSONL has no rotation/encryption or multiprocess coordination. Event retention and production hardening are future work.
