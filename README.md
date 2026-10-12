# SentinelAI SOC — web application starter

A dark, browser-based SOC dashboard built with FastAPI, SQLite, and vanilla JavaScript. It supports demo events, event filtering and status workflow, an audit trail, a protected Wazuh webhook receiver, a Suricata EVE JSON ingest endpoint, and optional server-side LLM-assisted event triage.

## Implemented vs. not implemented

**Implemented in this repository**
- Browser dashboard and event table.
- SQLite event store, summary metrics, status changes, and basic audit trail.
- Synthetic demo-event generator.
- `POST /api/integrations/wazuh` webhook receiver with `X-Webhook-Token` authentication and basic Wazuh alert field mapping.
- `POST /api/integrations/suricata` endpoint accepting one EVE JSON object per request with `X-API-Key` authentication and basic field mapping.
- Optional OpenAI-compatible Chat Completions request for investigation. When no AI key is configured, a clearly labelled template-based fallback is returned instead.
- Dockerfile and Compose configuration bound to `127.0.0.1` on the host.

**Not implemented / not verified**
- No live Wazuh manager or Suricata sensor is included or connected by default.
- No continuous Suricata `eve.json` file tailer or automatic agent installation.
- No endpoint agent, antivirus engine, packet capture, threat-intelligence enrichment, automated containment, multi-user RBAC, SSO, MFA, or production-grade audit integrity.
- No live attacker attribution. IP geolocation, if added later, would be approximate and cannot prove a person's location.
- AI results are advisory and may be wrong. A real AI provider may receive event data when investigation is requested.

This is a development starter, not a production SIEM/EDR or a substitute for Wazuh, Suricata, endpoint protection, incident-response processes, or a security review.

## Run locally

Requires Python 3.11+ (3.12 recommended).

```bash
cd sentinelai-soc
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and replace `SENTINEL_API_KEY` and `WAZUH_WEBHOOK_TOKEN` with different, long random secrets. Example secret generation on Linux/macOS:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Load `.env` into the process. FastAPI does not automatically load `.env` in this starter. On Linux/macOS you can run:

```bash
set -a; source .env; set +a
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In PowerShell, set environment variables from `.env` manually, or use a local dotenv loader of your choice; do not commit `.env`. Then open http://127.0.0.1:8000. The browser prompts for `SENTINEL_API_KEY` when the first protected API request is made and keeps it in session storage for that browser tab/session.

## Run with Docker Compose

```bash
cp .env.example .env
# Edit .env and set strong secrets first
docker compose up --build -d
```

Open http://127.0.0.1:8000. The Compose port is deliberately bound to loopback. For remote access, put the app behind a properly configured TLS reverse proxy and implement a stronger identity/access-control model first.

## API quick test

Use the same value as `SENTINEL_API_KEY` for `API_KEY` below.

```bash
export API_KEY='your-configured-sentinel-api-key'
curl -H "X-API-Key: $API_KEY" http://127.0.0.1:8000/api/summary
curl -X POST -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  -d '{}' http://127.0.0.1:8000/api/demo/seed
curl -H "X-API-Key: $API_KEY" http://127.0.0.1:8000/api/events
```

### Wazuh webhook receiver

Send an example alert payload using `WAZUH_WEBHOOK_TOKEN`:

```bash
curl -X POST http://127.0.0.1:8000/api/integrations/wazuh \
  -H 'Content-Type: application/json' \
  -H 'X-Webhook-Token: your-configured-wazuh-webhook-token' \
  -d '{"timestamp":"2026-10-11T10:00:00Z","rule":{"id":"5710","level":10,"description":"SSH authentication failure","groups":["authentication"]},"agent":{"id":"001","name":"linux-web-01"},"data":{"srcip":"198.51.100.23","srcuser":"admin"}}'
```

This endpoint is a generic receiver. Configure an actual Wazuh integration/forwarder to send this format, then test and adapt mappings to your Wazuh version and payload shape. Do not assume that Wazuh sends to this endpoint automatically.

### Suricata EVE JSON receiver

The endpoint accepts a single EVE record per HTTP request:

```bash
curl -X POST http://127.0.0.1:8000/api/integrations/suricata \
  -H 'Content-Type: application/json' -H "X-API-Key: $API_KEY" \
  -d '{"timestamp":"2026-10-11T10:00:00.000000+0000","event_type":"alert","src_ip":"192.0.2.5","dest_ip":"10.0.0.5","alert":{"signature":"ET SCAN Example scan","severity":2,"signature_id":12345}}'
```

A production deployment needs a reliable forwarder that reads Suricata's EVE output, handles retries and back-pressure, protects credentials, and monitors delivery failures. That forwarder is not bundled here.

### Optional AI investigation

Set `AI_API_KEY`, `AI_BASE_URL`, and `AI_MODEL` in the backend environment. The implementation calls `{AI_BASE_URL}/chat/completions` and expects an OpenAI-compatible response schema. Use only a provider approved for the sensitivity of your logs. Redact secrets and personal data before sending telemetry to an external service.

## Security notes before production

- Change all default secrets and keep them out of Git.
- Run behind TLS; do not expose this development server directly to the internet.
- Add user accounts, RBAC, MFA/SSO, rate limiting, CSRF strategy where relevant, secret rotation, backup/restore, retention policies, and tamper-resistant audit logging.
- Validate all integration payloads against your deployed versions and add integration tests.
- Restrict access to event payloads; raw telemetry can contain credentials, tokens, personal data, or sensitive infrastructure details.
- Test on systems you own or are explicitly authorized to monitor.
