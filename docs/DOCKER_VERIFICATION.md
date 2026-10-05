# Docker verification

## Result

**Static configuration validation passed. Docker image build and container runtime checks are unverified on this host:** the Docker CLI/Engine is not installed (`docker` is not recognized). Consequently, `docker compose build` and `docker compose up` could not be run here. Unit tests parse the Compose YAML and check service wiring, health checks, shared storage, non-root execution, and loopback-only port publication.

## Services and ports

| Service | Container port / role | Health check | Host published |
| --- | --- | --- | --- |
| `database` | One-shot SQLite schema initialization on the shared volume | Successful process exit gates the app services | None |
| `honeypot` | Flask decoy on 5000 | `GET /api/health` | None; reachable through `/honeypot/` on the proxy |
| `backend` | FastAPI on 8000 | `GET /api/health` | None; API and `/docs` pass through the proxy |
| `frontend` | Streamlit on 8501 | `GET /_stcore/health` | None; served at proxy root |
| `reverse-proxy` | Nginx on 8080 | Depends on all three app health checks | `127.0.0.1:8080:8080` only |

SQLite and JSONL use the `honeybot_data` volume; Streamlit mounts it read-only and consumes event records written by the backend services. FastAPI, Flask, and Streamlit remain on the Compose bridge network. The bridge permits outbound connections for an explicitly configured LLM provider; no application container port is directly published to the host. `LLM_ENABLED` defaults to false and `LLM_API_KEY` is passed through from the local environment without being stored in the image.

## Remaining verification

On a machine with Docker Engine and the Compose plugin, run:

```powershell
docker compose config
docker compose build
docker compose up -d
Invoke-RestMethod http://127.0.0.1:8080/api/health
Invoke-WebRequest http://127.0.0.1:8080/_stcore/health
docker compose ps
docker compose down
```

Then inspect `/docs`, the dashboard, and the synthetic simulator while the stack is up. A real image build, service-to-service runtime test, and health-check transition have not been claimed until those commands pass.
