# Deployment

# Deployment

## Public Render demo

`render.yaml` defines a free Render web service. The public root (`/`) serves a standalone synthetic dashboard; its attack sequence runs in the browser and sends no API requests. `/login` and the other decoy paths use the Flask honeypot. Create a Render Blueprint from the repository's `main` branch (which contains this configuration); the service itself is pinned to `master`. Render provides a public HTTPS URL and forwards traffic to the configured `$PORT`. Use the health check at `/healthz`.

The service runs `public_app:app`, not the regular local entry point. The WSGI gate blocks `/api`, `/docs`, `/redoc`, `/openapi.json`, `/dashboard`, and `/metrics`; it also caps traffic at 60 requests per source IP per minute and 300 total requests per minute. The synthetic dashboard is served before the honeypot's risk policy, so normal visits remain available even if a source is temporarily contained on a decoy route. The gate uses the `CF-Connecting-IP` value for source attribution and ignores `X-Forwarded-For`. The service has one Gunicorn worker so those in-memory ceilings apply consistently. Render's public edge terminates HTTPS.

The public decoy can still be probed and its endpoints can receive arbitrary input up to the Flask 16 KB request limit. Password-like fields are redacted, and the public landing/login pages warn visitors not to submit real credentials. The dashboard numbers and map markers are fictional examples; they do not represent live traffic or real locations. Do not enable LLM calls or add real account/data integrations to this service.

The free plan uses ephemeral storage at `/tmp/honeybot`; SQLite history and JSONL logs can be lost on restart, deploy, or instance recycling. Free instances can sleep after inactivity and take time to wake. The public deployment is for a resume/demo, not production monitoring. To retain events, choose a paid storage plan and define retention, access control, and deletion policy first.

## Local development

Install dependencies, start Flask with `python app.py`, FastAPI with `python -m uvicorn api_server:app --host 127.0.0.1 --port 8000`, and the optional Streamlit view. Run `python scripts/demo_mode.py` for synthetic activity. `docker compose up --build` provides a loopback-only container stack at port 8080. Docker was unavailable during implementation, so the Compose image build/runtime remains unverified. SQLite persists locally to `data/honeybot.sqlite`; JSONL remains at `data/events.jsonl`. Keep `.env` secrets out of source control. Optional GeoIP uses local MaxMind files configured by `HONEYPOT_GEOIP_CITY_DB` / `HONEYPOT_GEOIP_ASN_DB`.
