# OpsSentinel

OpsSentinel is a real-time autonomous incident-response and supply-chain
sentinel built for the You.com Agentic Hackathon at AWS Builder Loft SF.

It retrieves live evidence through You.com, assigns an Agno Threat Analyst to
synthesize the finding with Parasail inference, hands the result to a
Remediation Planner, and dispatches a guarded rollback payload to Opsera Forge.
Every integration has a deterministic demo fallback, so the complete judge flow
works without credentials.

## What judges can see

- Two one-click scenarios: an open-source zero-day and a semiconductor supply
  disruption.
- A live server-sent event stream that shows each agent handoff.
- Severity, affected-component, and confidence scoring.
- Clickable evidence cards for every material claim.
- An auditable `PIPELINE_ROLLBACK` action with a stable incident hash.
- A verified Opsera simulation when no production webhook is configured.
- Responsive, accessible dark-mode UI with reduced-motion support.

## Architecture

```text
Browser
  └─ React dashboard
       └─ FastAPI event stream
            ├─ You.com Search API → normalized citations
            ├─ Agno Threat Analyst → Parasail/OpenAI-compatible inference
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
| `YOUCOM_API_KEY` | Live You.com Search API retrieval | No; demo citations are used |
| `PARASAIL_API_KEY` | Live OpenAI-compatible inference via Agno | No; deterministic analysis is used |
| `PARASAIL_MODEL` | Parasail model identifier | No; defaults to `parasail-deepseek-r1` |
| `PARASAIL_BASE_URL` | Parasail inference base URL | No |
| `OPSERA_WEBHOOK_URL` | Live Opsera/Forge trigger endpoint | No; verified simulation is used |
| `OPSERA_API_TOKEN` | Optional bearer token for the webhook | No |
| `FRONTEND_ORIGINS` | Comma-separated FastAPI CORS allowlist | No |

Do not commit real credentials.

## API

### `GET /health`

Liveness check.

### `GET /api/status`

Reports whether You.com, Parasail, and Opsera are live or in demo mode.

### `POST /api/incidents/simulate`

```json
{
  "incident_type": "zero_day"
}
```

Accepted types are `zero_day` and `supply_chain`.

### `GET /api/incidents/stream?incident_type=zero_day`

Returns `stage` and `complete` server-sent events for the execution timeline.

## Credits needed

None are needed for the polished demo flow. For a fully live hackathon run,
provision:

1. A You.com API key with enough Search API requests for the judging session.
2. A Parasail API key with modest serverless inference credit, or an OpenAI key
   if you adapt the compatible model configuration.
3. An Opsera sandbox webhook/agent endpoint. Use a non-production pipeline for
   judging.

AWS credits are not required to run the local prototype.

## Safety

- Missing credentials never cause a destructive action.
- Live Opsera calls use an idempotency key derived from the incident.
- Production actions retain a human-approval guardrail in the payload.
- Search and inference failures degrade to labeled demo mode.
- URLs are validated before being exposed as clickable citations.
