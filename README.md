# Linux telemetry collector

This API is designed to run on a Linux host you control. It tails/parses logs from sensors already installed and configured there. It does not install Zeek, Suricata, Cowrie, or configure packet capture automatically.

## 1. Install sensors (choose the ones you need)

Install Zeek and/or Suricata using their official installation instructions for your Linux distribution. Configure Zeek JSON logs and Suricata EVE JSON output. For SSH deception, run Cowrie on a **separate isolated VM/container** with restricted outbound traffic. Do not run a public honeypot on a sensitive production server.

## 2. Install the collector

```bash
cd collector
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c 'import secrets; print(secrets.token_urlsafe(48))'
# Put the generated value in COLLECTOR_TOKEN in .env.
```

Edit log paths in `.env` to match your machine. Use a secret manager or locked-down environment file in production.

## 3. Start it for a local test

```bash
set -a; source .env; set +a
uvicorn app:app --host 127.0.0.1 --port 8787
```

This binds to localhost intentionally. For a hosted dashboard, put it behind a properly configured HTTPS reverse proxy/VPN or deploy into a private network with a controlled access gateway. Do not simply bind to `0.0.0.0` on a public server.

## API

- `GET /health`
- `GET /api/events?limit=100`
- `GET /api/detections?limit=100`

All endpoints require `Authorization: Bearer <COLLECTOR_TOKEN>` except health returns limited status. CORS should be restricted to your exact dashboard origin.

## Threat intelligence

Set `ABUSEIPDB_API_KEY` in the collector environment. The collector only looks up public IPv4 addresses and returns provider provenance, confidence, and check timestamp. Respect provider quotas and terms. API errors are reported as unknown, never as safe.

## ML model

The Isolation Forest model runs locally in the collector process on connection records with duration, bytes, packets and ports. It waits for at least 30 usable observations and retrains on a recent sample. Anomaly scores are review signals, not confirmed attacks. This starter implementation uses in-memory records; add a durable database and model lifecycle management for production.

## CORS and TLS

Set `CORS_ORIGINS` to the exact Vercel origin. Place the collector behind HTTPS. Use a firewall/VPN, rotate tokens, redact personal data and configure retention.
