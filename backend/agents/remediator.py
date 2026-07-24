"""Remediation Planner agent and Opsera action payload builder."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any


class RemediationPlanner:
    """Translate a threat finding into a constrained, auditable pipeline action."""

    PIPELINE_BY_INCIDENT = {
        "zero_day": "prod-auth-service",
        "supply_chain": "edge-controller-release",
        "custom": "security-investigation",
    }

    def plan(
        self, incident_type: str, threat_summary: dict[str, Any]
    ) -> dict[str, Any]:
        pipeline = self.PIPELINE_BY_INCIDENT.get(
            incident_type, "prod-auth-service"
        )
        fingerprint_input = json.dumps(
            {
                "type": incident_type,
                "title": threat_summary["title"],
                "components": threat_summary["affected_components"],
                "pipeline": pipeline,
            },
            sort_keys=True,
        )
        incident_hash = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:12]

        return {
            "action": "PIPELINE_ROLLBACK",
            "target_pipeline": pipeline,
            "status": "TRIGGERED",
            "incident_hash": incident_hash,
            "guardrails": {
                "require_human_approval_for_production": True,
                "preserve_audit_log": True,
                "max_rollback_depth": 1,
            },
            "remediation_steps": self._steps(incident_type),
            "created_at": datetime.now(UTC).isoformat(),
        }

    @staticmethod
    def _steps(incident_type: str) -> list[str]:
        if incident_type == "supply_chain":
            return [
                "Pause affected hardware release train",
                "Route demand to approved alternate suppliers",
                "Stage procurement manifest update for approval",
            ]
        return [
            "Rollback to last known-good dependency lockfile",
            "Rebuild and rescan the production image",
            "Stage a remediation pull request for approval",
        ]
