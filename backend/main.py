"""FastAPI entrypoint for OpsSentinel's autonomous response workflow."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import UTC, datetime
from typing import Literal

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Query  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import StreamingResponse  # noqa: E402
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
        "message": "Cross-referencing advisories against the production dependency graph…",
        "detail": "Parasail inference · Agno Threat Analyst",
    },
    "plan": {
        "kind": "plan",
        "message": "Building a least-blast-radius mitigation and rollback plan…",
        "detail": "Agno Remediation Planner · policy OPS-P1",
    },
    "action": {
        "kind": "action",
        "message": "Pipeline rollback triggered and remediation PR staged.",
        "detail": "Opsera Forge · human approval gate preserved",
    },
}

app = FastAPI(
    title="OpsSentinel API",
    description="Autonomous incident response and supply-chain intelligence.",
    version="1.0.0",
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


class IncidentRequest(BaseModel):
    incident_type: IncidentType = "zero_day"
    custom_query: str | None = None


class MitigationDecision(BaseModel):
    incident_hash: str
    decision: Literal["approved", "held"]


def _event(name: str, data: dict) -> str:
    return f"event: {name}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


async def execute_incident(
    incident_type: IncidentType, custom_query: str | None = None
) -> dict:
    started = datetime.now(UTC)
    query = (
        custom_query.strip()
        if incident_type == "custom" and custom_query and custom_query.strip()
        else SEARCH_QUERIES[incident_type]
    )
    search_result = await asyncio.to_thread(
        youcom.search,
        query,
        scenario=incident_type,
    )
    threat_summary = await asyncio.to_thread(
        analyst.analyze, incident_type, search_result
    )
    action_payload = remediator.plan(incident_type, threat_summary)
    opsera_response = await asyncio.to_thread(opsera.dispatch, action_payload)
    elapsed_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)

    return {
        "incident_id": f"INC-{uuid.uuid4().hex[:6].upper()}",
        "incident_type": incident_type,
        "source_mode": search_result["source_mode"],
        "query": search_result["query"],
        "citations": search_result["citations"],
        "threat_summary": threat_summary,
        "opsera": {
            "request": action_payload,
            "response": opsera_response,
        },
        "telemetry": {
            "elapsed_ms": elapsed_ms,
            "completed_at": datetime.now(UTC).isoformat(),
        },
    }


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
        "parasail": "live" if bool(os.getenv("PARASAIL_API_KEY")) else "demo",
        "opsera": "live" if bool(os.getenv("OPSERA_WEBHOOK_URL")) else "demo",
    }


@app.post("/api/incidents/simulate")
async def simulate_incident(request: IncidentRequest) -> dict:
    return await execute_incident(request.incident_type, request.custom_query)


@app.post("/api/mitigations/decision")
async def mitigation_decision(request: MitigationDecision) -> dict:
    return {
        "incident_hash": request.incident_hash,
        "decision": request.decision,
        "status": (
            "APPROVED_FOR_PRODUCTION"
            if request.decision == "approved"
            else "HELD_FOR_REVIEW"
        ),
        "audit_id": f"AUD-{uuid.uuid4().hex[:8].upper()}",
        "recorded_at": datetime.now(UTC).isoformat(),
    }


@app.get("/api/incidents/stream")
async def stream_incident(
    incident_type: IncidentType = Query(default="zero_day"),
    query: str = Query(default="", max_length=280),
) -> StreamingResponse:
    async def events():
        yield _event("stage", STAGES["search"])
        await asyncio.sleep(0.45)

        started = datetime.now(UTC)
        search_query = (
            query.strip()
            if incident_type == "custom" and query.strip()
            else SEARCH_QUERIES[incident_type]
        )
        search_result = await asyncio.to_thread(
            youcom.search,
            search_query,
            scenario=incident_type,
        )

        yield _event("stage", STAGES["analysis"])
        await asyncio.sleep(0.45)
        threat_summary = await asyncio.to_thread(
            analyst.analyze, incident_type, search_result
        )

        yield _event("stage", STAGES["plan"])
        await asyncio.sleep(0.45)
        action_payload = remediator.plan(incident_type, threat_summary)

        yield _event("stage", STAGES["action"])
        await asyncio.sleep(0.45)
        opsera_response = await asyncio.to_thread(opsera.dispatch, action_payload)

        result = {
            "incident_id": f"INC-{uuid.uuid4().hex[:6].upper()}",
            "incident_type": incident_type,
            "source_mode": search_result["source_mode"],
            "query": search_result["query"],
            "citations": search_result["citations"],
            "threat_summary": threat_summary,
            "opsera": {
                "request": action_payload,
                "response": opsera_response,
            },
            "telemetry": {
                "elapsed_ms": int(
                    (datetime.now(UTC) - started).total_seconds() * 1000
                ),
                "completed_at": datetime.now(UTC).isoformat(),
            },
        }
        yield _event("complete", result)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
