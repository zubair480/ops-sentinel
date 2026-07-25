"""Threat Analyst agent: You.com Research synthesis with free local fallback."""

from __future__ import annotations

import re
from typing import Any


class ThreatAnalyst:
    """Convert normalized citations into a source-grounded threat assessment."""

    def analyze(
        self, incident_type: str, search_result: dict[str, Any]
    ) -> dict[str, Any]:
        baseline = self._baseline(incident_type, search_result["citations"])
        analysis = search_result.get("analysis")
        if isinstance(analysis, dict):
            merged = self._merge_validated(analysis, baseline)
            merged["inference_mode"] = "youcom_research"
            merged["indicators"] = self._extract_indicators(
                search_result["citations"], merged
            )
            return merged

        baseline["inference_mode"] = "evidence_rules"
        baseline["indicators"] = self._extract_indicators(
            search_result["citations"], baseline
        )
        return baseline

    @staticmethod
    def _extract_indicators(
        citations: list[dict[str, str]], analysis: dict[str, Any]
    ) -> list[dict[str, str]]:
        """Extract defensible observables from evidence without inventing IOCs."""

        text = " ".join(
            [
                str(analysis.get("title", "")),
                str(analysis.get("summary", "")),
                *[
                    f"{citation.get('title', '')} {citation.get('snippet', '')}"
                    for citation in citations
                ],
            ]
        )
        cves = sorted(
            {value.upper() for value in re.findall(r"\bCVE-\d{4}-\d{4,8}\b", text, re.I)}
        )
        return [{"type": "CVE", "value": value} for value in cves[:8]]

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
                "risk_tags": [
                    "vendor concentration",
                    "export control",
                    "lead-time exposure",
                ],
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
            "risk_tags": [
                "software supply chain",
                "dependency compromise",
                "remote access",
            ],
            "evidence": evidence,
        }

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
