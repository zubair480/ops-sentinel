"""FastAPI entrypoint for OpsSentinel's autonomous response workflow."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Query  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import StreamingResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from backend.agents.remediator import RemediationPlanner  # noqa: E402
from backend.agents.threat_analyst import ThreatAnalyst  # noqa: E402
from backend.services.opsera_service import OpseraService  # noqa: E402
from backend.services.youcom_service import YouComService  # noqa: E402


IncidentType = Literal["zero_day", "supply_chain", "custom"]

SEARCH_QUERIES: dict[IncidentType, str] = {
    "zero_day": (
        "latest critical zero-day open source library supply chain vulnerability "
        "CISA NVD affected versions mitigation"
    ),
    "supply_chain": (
        "latest semiconductor export restrictions advanced chip manufacturing "
        "supply chain disruption lead times"
    ),
    "custom": (
        "latest critical cybersecurity and software supply chain advisories "
        "CISA NVD active exploitation mitigation"
    ),
}

STAGES = {
    "search": {
        "kind": "search",
        "message": "Ingesting live web index and extracting factual citations…",
        "detail": "You.com Search API · recency and source validation enabled",
    },
    "analysis": {
        "kind": "analysis",
        "message": "You.com Research is cross-referencing advisories and affected assets…",
        "detail": "You.com agentic research · citation-grounded Threat Analyst",
    },
    "plan": {
        "kind": "plan",
        "message": "Building a least-blast-radius mitigation and rollback plan…",
        "detail": "Local Remediation Agent · policy OPS-P1",
    },
    "action": {
        "kind": "action",
        "message": "Preparing a guarded rollback and remediation PR payload…",
        "detail": "Opsera Forge · execution mode verified after dispatch",
    },
}

app = FastAPI(
    title="OpsSentinel API",
    description="Autonomous incident response and supply-chain intelligence.",
    version="1.1.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS", "http://localhost:5173,http://localhost:3000"
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

youcom = YouComService()
analyst = ThreatAnalyst()
remediator = RemediationPlanner()
opsera = OpseraService()
audit_events: deque[dict] = deque(maxlen=100)


class IncidentRequest(BaseModel):
    incident_type: IncidentType = "zero_day"
    custom_query: str | None = None


class MitigationDecision(BaseModel):
    incident_hash: str
    decision: Literal["approved", "held"]
    incident_id: str | None = None
    run_id: str | None = None


def _event(name: str, data: dict) -> str:
    return f"event: {name}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


def _record_audit(
    event_type: str,
    *,
    incident_id: str | None,
    run_id: str | None,
    detail: str,
) -> dict:
    record = {
        "audit_id": f"AUD-{uuid.uuid4().hex[:8].upper()}",
        "event_type": event_type,
        "incident_id": incident_id,
        "run_id": run_id,
        "detail": detail,
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    audit_events.appendleft(record)
    return record


def _provenance(search_result: dict) -> dict:
    domains: list[str] = []
    for citation in search_result["citations"]:
        domain = urlparse(citation["url"]).netloc.removeprefix("www.")
        if domain and domain not in domains:
            domains.append(domain)
    return {
        "citation_count": len(search_result["citations"]),
        "source_domains": domains[:8],
        "source_mode": search_result["source_mode"],
        "reasoning_mode": search_result.get("reasoning_mode", "evidence_rules"),
        "fallback_active": search_result["source_mode"] != "live",
        "retrieved_at": datetime.now(UTC).isoformat(),
    }


def _incident_result(
    *,
    incident_id: str,
    run_id: str,
    incident_type: IncidentType,
    search_result: dict,
    threat_summary: dict,
    action_payload: dict,
    opsera_response: dict,
    started: datetime,
) -> dict:
    return {
        "incident_id": incident_id,
        "run_id": run_id,
        "incident_type": incident_type,
        "source_mode": search_result["source_mode"],
        "query": search_result["query"],
        "citations": search_result["citations"],
        "provenance": _provenance(search_result),
        "threat_summary": threat_summary,
        "opsera": {
            "request": action_payload,
            "response": opsera_response,
        },
        "telemetry": {
            "elapsed_ms": int((datetime.now(UTC) - started).total_seconds() * 1000),
            "completed_at": datetime.now(UTC).isoformat(),
        },
    }


async def execute_incident(
    incident_type: IncidentType, custom_query: str | None = None
) -> dict:
    started = datetime.now(UTC)
    incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
    run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
    query = (
        custom_query.strip()
        if incident_type == "custom" and custom_query and custom_query.strip()
        else SEARCH_QUERIES[incident_type]
    )
    _record_audit(
        "INCIDENT_STARTED",
        incident_id=incident_id,
        run_id=run_id,
        detail=f"{incident_type} evidence sweep started",
    )
    search_result = await asyncio.to_thread(
        youcom.research,
        query,
        scenario=incident_type,
    )
    threat_summary = await asyncio.to_thread(
        analyst.analyze, incident_type, search_result
    )
    action_payload = remediator.plan(incident_type, threat_summary)
    opsera_response = await asyncio.to_thread(opsera.dispatch, action_payload)
    result = _incident_result(
        incident_id=incident_id,
        run_id=run_id,
        incident_type=incident_type,
        search_result=search_result,
        threat_summary=threat_summary,
        action_payload=action_payload,
        opsera_response=opsera_response,
        started=started,
    )
    _record_audit(
        "INCIDENT_ANALYZED",
        incident_id=incident_id,
        run_id=run_id,
        detail=(
            f"{threat_summary['severity_label']} finding with "
            f"{len(search_result['citations'])} cited sources"
        ),
    )
    return result


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "ops-sentinel",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/api/status")
def integration_status() -> dict:
    return {
        "youcom": "live" if bool(os.getenv("YOUCOM_API_KEY")) else "demo",
        "reasoning": (
            "youcom_research" if bool(os.getenv("YOUCOM_API_KEY")) else "evidence_rules"
        ),
        "opsera": "live" if bool(os.getenv("OPSERA_WEBHOOK_URL")) else "demo",
        "api_version": app.version,
        "capabilities": [
            "live_research",
            "indicator_extraction",
            "policy_guardrails",
            "audit_receipts",
        ],
    }


@app.post("/api/incidents/simulate")
async def simulate_incident(request: IncidentRequest) -> dict:
    return await execute_incident(request.incident_type, request.custom_query)


@app.post("/api/mitigations/decision")
async def mitigation_decision(request: MitigationDecision) -> dict:
    status = (
        "APPROVED_FOR_PRODUCTION"
        if request.decision == "approved"
        else "HELD_FOR_REVIEW"
    )
    receipt = _record_audit(
        "MITIGATION_DECISION",
        incident_id=request.incident_id,
        run_id=request.run_id,
        detail=f"{status} for incident hash {request.incident_hash}",
    )
    return {
        "incident_hash": request.incident_hash,
        "decision": request.decision,
        "status": status,
        **receipt,
    }


@app.get("/api/audit")
def audit_trail(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    return {
        "events": list(audit_events)[:limit],
        "session_scope": True,
        "retention_note": "In-memory demo audit; connect durable storage for production.",
    }


@app.get("/api/incidents/stream")
async def stream_incident(
    incident_type: IncidentType = Query(default="zero_day"),
    query: str = Query(default="", max_length=280),
) -> StreamingResponse:
    async def events():
        incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        _record_audit(
            "INCIDENT_STARTED",
            incident_id=incident_id,
            run_id=run_id,
            detail=f"{incident_type} streaming evidence sweep started",
        )
        yield _event(
            "stage",
            {**STAGES["search"], "run_id": run_id, "sequence": 1},
        )
        await asyncio.sleep(0.45)

        started = datetime.now(UTC)
        search_query = (
            query.strip()
            if incident_type == "custom" and query.strip()
            else SEARCH_QUERIES[incident_type]
        )
        search_result = await asyncio.to_thread(
            youcom.research,
            search_query,
            scenario=incident_type,
        )

        yield _event(
            "stage",
            {**STAGES["analysis"], "run_id": run_id, "sequence": 2},
        )
        await asyncio.sleep(0.45)
        threat_summary = await asyncio.to_thread(
            analyst.analyze, incident_type, search_result
        )

        yield _event(
            "stage",
            {**STAGES["plan"], "run_id": run_id, "sequence": 3},
        )
        await asyncio.sleep(0.45)
        action_payload = remediator.plan(incident_type, threat_summary)

        yield _event(
            "stage",
            {**STAGES["action"], "run_id": run_id, "sequence": 4},
        )
        await asyncio.sleep(0.45)
        opsera_response = await asyncio.to_thread(opsera.dispatch, action_payload)

        result = _incident_result(
            incident_id=incident_id,
            run_id=run_id,
            incident_type=incident_type,
            search_result=search_result,
            threat_summary=threat_summary,
            action_payload=action_payload,
            opsera_response=opsera_response,
            started=started,
        )
        _record_audit(
            "INCIDENT_ANALYZED",
            incident_id=incident_id,
            run_id=run_id,
            detail=(
                f"{threat_summary['severity_label']} finding with "
                f"{len(search_result['citations'])} cited sources"
            ),
        )
        yield _event("complete", result)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# Render builds the Vite dashboard into frontend/dist. Mounting it last keeps
# every API route above reachable while serving the SPA and its static assets
# from the same HTTPS origin.
frontend_dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if frontend_dist.is_dir():
    app.mount(
        "/",
        StaticFiles(directory=frontend_dist, html=True),
        name="frontend",
    )
