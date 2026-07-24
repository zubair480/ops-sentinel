# OpsSentinel

OpsSentinel is a real-time autonomous incident-response and supply-chain
sentinel built for the You.com Agentic Hackathon at AWS Builder Loft SF.

It retrieves and synthesizes live evidence through You.com Search and Research,
hands the grounded finding to local Threat Analyst and Remediation Planner
agents, and dispatches a guarded rollback payload to Opsera Forge. No paid LLM
provider is required, and every integration has a deterministic fallback.

## What judges can see

- Two one-click scenarios: an open-source zero-day and a semiconductor supply
  disruption.
- A free-form investigation mode for operator-supplied threat signals.
- A live server-sent event stream that shows each agent handoff.
- Severity, affected-component, and confidence scoring.
- A predicted dependency blast-radius map with impact metrics.
- A human approval/hold gate before production execution.
- Downloadable evidence packages and device-local response history.
- Clickable evidence cards for every material claim.
- An auditable `PIPELINE_ROLLBACK` action with a stable incident hash.
- A verified Opsera simulation when no production webhook is configured.
- Responsive, accessible dark-mode UI with reduced-motion support.

## Architecture

```text
Browser
  └─ React dashboard
       └─ FastAPI / Cloudflare Worker event stream
            ├─ You.com Research → agentic analysis + normalized citations
            ├─ Threat Analyst → typed, evidence-grounded finding
            ├─ Remediation Planner → guarded rollback payload
            └─ Opsera webhook → live dispatch or verified simulation
```

## Project structure

```text
ops-sentinel/
├── backend/
│   ├── main.py
│   ├── services/
│   │   ├── youcom_service.py
│   │   └── opsera_service.py
│   ├── agents/
│   │   ├── threat_analyst.py
│   │   └── remediator.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.jsx
│   │   │   ├── IncidentTrigger.jsx
│   │   │   ├── AgentLogStream.jsx
│   │   │   ├── CitationCard.jsx
│   │   │   └── OpseraPipelineCard.jsx
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── app/                      # Cloudflare/Sites production wrapper
├── .env.example
└── README.md
```

## Run locally

Prerequisites: Python 3.11+, Node.js 20+, and npm.

### 1. Backend

From the project root:

```bash
python -m venv .venv
```

Activate the virtual environment:

```bash
# macOS/Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install and start the API:

```bash
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Open `http://localhost:8000/docs` for the interactive API.

### 2. Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

The dashboard will automatically use the backend on localhost. If the API is
not running, it completes the same flow with deterministic demo data.

## Environment variables

Copy `.env.example` to `.env`, or use the safe blank `.env` included in the
prototype:

| Variable | Purpose | Required? |
|---|---|---|
| `YOUCOM_API_KEY` | Live You.com Search and agentic Research | No; evidence rules and demo citations are used |
| `OPSERA_WEBHOOK_URL` | Live Opsera/Forge trigger endpoint | No; verified simulation is used |
| `OPSERA_API_TOKEN` | Optional bearer token for the webhook | No |
| `FRONTEND_ORIGINS` | Comma-separated FastAPI CORS allowlist | No |

Do not commit real credentials.

## API

### `GET /health`

Liveness check.

### `GET /api/status`

Reports whether You.com Research, local reasoning, and Opsera are live or in
safe fallback mode.

### `POST /api/incidents/simulate`

```json
{
  "incident_type": "zero_day"
}
```

Accepted types are `zero_day` and `supply_chain`.

### `GET /api/incidents/stream?incident_type=zero_day`

Returns `stage` and `complete` server-sent events for the execution timeline.

Use `incident_type=custom&query=...` for a free-form investigation.

### `POST /api/mitigations/decision`

Records an `approved` or `held` operator decision against an incident hash and
returns signed audit metadata.

## Credits needed

No paid LLM credits are needed. The live intelligence path uses the
complimentary You.com API credits already included with a new platform account.
Without a key, the same judge flow runs with labeled evidence rules and verified
demo citations. An Opsera sandbox webhook remains optional; without it, the
dashboard returns a verified simulation.

AWS credits are not required to run the local prototype.

## Safety

- Missing credentials never cause a destructive action.
- Live Opsera calls use an idempotency key derived from the incident.
- Production actions retain a human-approval guardrail in the payload.
- Research failures degrade to live Search plus labeled evidence rules.
- URLs are validated before being exposed as clickable citations.
