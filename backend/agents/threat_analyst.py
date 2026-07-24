"""Threat Analyst agent: evidence synthesis with optional Parasail inference."""

from __future__ import annotations

import json
import os
import re
from typing import Any


class ThreatAnalyst:
    """Convert normalized citations into a source-grounded threat assessment."""

    def __init__(self) -> None:
        self.api_key = os.getenv("PARASAIL_API_KEY", "")
        self.model_id = os.getenv("PARASAIL_MODEL", "parasail-deepseek-r1")
        self.base_url = os.getenv("PARASAIL_BASE_URL", "https://api.parasail.io/v1")

    def analyze(
        self, incident_type: str, search_result: dict[str, Any]
    ) -> dict[str, Any]:
        baseline = self._baseline(incident_type, search_result["citations"])
        if not self.api_key:
            baseline["inference_mode"] = "deterministic_demo"
            return baseline

        try:
            from agno.agent import Agent
            from agno.models.openai.like import OpenAILike

            model = OpenAILike(
                id=self.model_id,
                api_key=self.api_key,
                base_url=self.base_url,
            )
            agent = Agent(
                name="OpsSentinel Threat Analyst",
                role="Cybersecurity and supply-chain threat intelligence analyst",
                model=model,
                instructions=[
                    "Use only the supplied citation evidence.",
                    "Never invent URLs, CVEs, affected versions, or vendors.",
                    "Return compact valid JSON and no markdown.",
                ],
            )
            response = agent.run(self._prompt(incident_type, search_result))
            content = getattr(response, "content", response)
            parsed = self._parse_json(str(content))
            merged = self._merge_validated(parsed, baseline)
            merged["inference_mode"] = "parasail_agno"
            return merged
        except Exception as exc:  # Provider failure must not derail a live demo.
            baseline["inference_mode"] = "deterministic_fallback"
            baseline["inference_fallback"] = type(exc).__name__
            return baseline

    @staticmethod
    def _baseline(
        incident_type: str, citations: list[dict[str, str]]
    ) -> dict[str, Any]:
        evidence = [
            {
                "claim": citation["snippet"],
                "citation_ref": f"[{index + 1}]",
                "url": citation["url"],
            }
            for index, citation in enumerate(citations)
        ]

        if incident_type == "supply_chain":
            return {
                "title": "Advanced-chip export controls threaten lead times",
                "severity_score": 8.7,
                "severity_label": "HIGH",
                "summary": (
                    "A semiconductor export-control signal maps to two approved "
                    "suppliers in the impacted region. Procurement lead-time risk "
                    "is elevated and a controlled release pause is recommended."
                ),
                "affected_components": [
                    "edge-controller-v4",
                    "APAC supplier tier 2",
                    "Q4 launch",
                ],
                "confidence": 0.91,
                "evidence": evidence,
            }

        return {
            "title": "XZ Utils supply-chain backdoor detected",
            "severity_score": 10.0,
            "severity_label": "CRITICAL",
            "summary": (
                "Malicious code in liblzma versions 5.6.0 and 5.6.1 can "
                "interfere with SSH authentication on affected Linux systems. "
                "The simulated production auth image matches the exposed range."
            ),
            "affected_components": [
                "liblzma 5.6.1",
                "prod-auth-service",
                "linux/amd64",
            ],
            "confidence": 0.98,
            "evidence": evidence,
        }

    @staticmethod
    def _prompt(incident_type: str, search_result: dict[str, Any]) -> str:
        schema = {
            "title": "short incident title",
            "severity_score": "number from 0 to 10",
            "severity_label": "LOW | MEDIUM | HIGH | CRITICAL",
            "summary": "two evidence-grounded sentences",
            "affected_components": ["component names"],
            "confidence": "number from 0 to 1",
        }
        return (
            f"Incident type: {incident_type}\n"
            f"Evidence: {json.dumps(search_result['citations'])}\n"
            f"Return this JSON shape: {json.dumps(schema)}"
        )

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any]:
        fenced = re.search(r"\{.*\}", content, flags=re.DOTALL)
        if not fenced:
            raise ValueError("Agent response did not contain JSON")
        parsed = json.loads(fenced.group(0))
        if not isinstance(parsed, dict):
            raise ValueError("Agent response was not an object")
        return parsed

    @staticmethod
    def _merge_validated(
        parsed: dict[str, Any], baseline: dict[str, Any]
    ) -> dict[str, Any]:
        output = dict(baseline)
        for key in ("title", "summary"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                output[key] = value.strip()[:1500]

        components = parsed.get("affected_components")
        if isinstance(components, list):
            clean = [str(value).strip()[:100] for value in components if str(value).strip()]
            if clean:
                output["affected_components"] = clean[:8]

        try:
            score = float(parsed.get("severity_score"))
            output["severity_score"] = round(max(0.0, min(score, 10.0)), 1)
        except (TypeError, ValueError):
            pass

        try:
            confidence = float(parsed.get("confidence"))
            output["confidence"] = round(max(0.0, min(confidence, 1.0)), 2)
        except (TypeError, ValueError):
            pass

        label = str(parsed.get("severity_label", "")).upper()
        if label in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            output["severity_label"] = label
        return output
