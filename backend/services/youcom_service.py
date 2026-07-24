"""Resilient You.com Search API client with citation normalization."""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


SEARCH_URL = "https://api.ydc-index.io/search"


DEMO_CITATIONS: dict[str, list[dict[str, str]]] = {
    "zero_day": [
        {
            "title": "NVD: CVE-2024-3094 detail",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
            "snippet": (
                "NIST records malicious code in the upstream XZ Utils tarballs "
                "for versions 5.6.0 and 5.6.1."
            ),
        },
        {
            "title": "CISA alert: XZ Utils supply-chain compromise",
            "url": (
                "https://www.cisa.gov/news-events/alerts/2024/03/29/"
                "reported-supply-chain-compromise-affecting-xz-utils-data-"
                "compression-library-cve-2024-3094"
            ),
            "snippet": (
                "CISA recommends downgrading XZ Utils and hunting for affected "
                "versions after the reported compromise."
            ),
        },
        {
            "title": "Red Hat urgent security alert",
            "url": (
                "https://www.redhat.com/en/blog/"
                "urgent-security-alert-fedora-41-and-rawhide-users"
            ),
            "snippet": (
                "Red Hat identifies affected Fedora builds and advises users to "
                "stop affected systems until remediated."
            ),
        },
    ],
    "supply_chain": [
        {
            "title": "BIS semiconductor export controls",
            "url": (
                "https://www.bis.gov/press-release/commerce-strengthens-export-"
                "controls-restrict-chinas-capability-produce-advanced-"
                "semiconductors-military"
            ),
            "snippet": (
                "The U.S. Commerce Department details strengthened controls on "
                "advanced semiconductor manufacturing equipment."
            ),
        },
        {
            "title": "Federal Register: semiconductor manufacturing items",
            "url": (
                "https://www.federalregister.gov/documents/2024/12/05/"
                "2024-28267/foreign-produced-direct-product-rule-additions-and-"
                "refinements-to-controls-for-advanced-computing-and"
            ),
            "snippet": (
                "The rule describes additions and refinements to controls for "
                "advanced computing and semiconductor manufacturing equipment."
            ),
        },
        {
            "title": "Semiconductor Industry Association market data",
            "url": (
                "https://www.semiconductors.org/global-semiconductor-sales-"
                "increase-19-1-in-2024-double-digit-growth-projected-in-2025/"
            ),
            "snippet": (
                "Industry data provides demand context for assessing substitution "
                "risk and procurement pressure."
            ),
        },
    ],
}


class YouComService:
    """Search You.com's live index and return only verifiable web citations."""

    def __init__(
        self,
        api_key: str | None = None,
        endpoint: str = SEARCH_URL,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.api_key = api_key or os.getenv("YOUCOM_API_KEY", "")
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def search(
        self,
        query: str,
        *,
        count: int = 6,
        freshness: str | None = "day",
        scenario: str = "zero_day",
    ) -> dict[str, Any]:
        """Return ``query`` and normalized ``title/url/snippet`` citations.

        A deterministic citation set is returned when no API key is present or
        the live request is temporarily unavailable. This keeps judge demos
        functional while exposing ``source_mode`` and ``fallback_reason``.
        """

        if not self.api_key:
            return self._demo_result(query, scenario, "YOUCOM_API_KEY is unset")

        params: dict[str, Any] = {
            "query": query,
            "num_web_results": max(1, min(count, 20)),
        }
        if freshness:
            params["freshness"] = freshness

        try:
            response = self.session.get(
                self.endpoint,
                headers={
                    "X-API-Key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "OpsSentinel/1.0",
                },
                params=params,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            citations = self._extract_citations(response.json())[:count]
            if not citations:
                return self._demo_result(
                    query, scenario, "Live response contained no usable web URLs"
                )
            return {
                "query": query,
                "citations": citations,
                "source_mode": "live",
            }
        except (requests.RequestException, ValueError, TypeError) as exc:
            return self._demo_result(
                query, scenario, f"Live search unavailable: {type(exc).__name__}"
            )

    def research(
        self, query: str, *, scenario: str = "zero_day", count: int = 8
    ) -> dict[str, Any]:
        """Research-oriented retrieval using a broader live Search API result set."""

        return self.search(
            query,
            count=count,
            freshness=None,
            scenario=scenario,
        )

    def _demo_result(
        self, query: str, scenario: str, reason: str
    ) -> dict[str, Any]:
        return {
            "query": query,
            "citations": DEMO_CITATIONS.get(scenario, DEMO_CITATIONS["zero_day"]),
            "source_mode": "demo",
            "fallback_reason": reason,
        }

    @classmethod
    def _extract_citations(cls, payload: Any) -> list[dict[str, str]]:
        candidates = list(cls._candidate_records(payload))
        citations: list[dict[str, str]] = []
        seen_urls: set[str] = set()

        for item in candidates:
            if not isinstance(item, dict):
                continue
            title = cls._first_text(item, "title", "name", "headline")
            url = cls._first_text(item, "url", "link", "source_url")
            snippet = cls._first_text(
                item,
                "snippet",
                "description",
                "summary",
                "content",
                "text",
            )
            if not title or not cls._is_web_url(url) or url in seen_urls:
                continue
            seen_urls.add(url)
            citations.append(
                {
                    "title": title.strip()[:240],
                    "url": url.strip(),
                    "snippet": (snippet or "Open the source to verify this finding.")
                    .strip()
                    .replace("\x00", "")[:700],
                }
            )
        return citations

    @classmethod
    def _candidate_records(cls, payload: Any) -> Iterable[dict[str, Any]]:
        """Walk common Search API response envelopes without binding to one version."""

        if isinstance(payload, list):
            for value in payload:
                if isinstance(value, dict):
                    yield value
                yield from cls._candidate_records(value)
            return

        if not isinstance(payload, dict):
            return

        # Prefer known result containers, then recursively inspect nested envelopes.
        for key in ("hits", "results", "web", "news", "documents", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
                    yield from cls._candidate_records(item)
            elif isinstance(value, dict):
                yield from cls._candidate_records(value)

        if any(key in payload for key in ("url", "link", "source_url")):
            yield payload

    @staticmethod
    def _first_text(item: dict[str, Any], *keys: str) -> str:
        for key in keys:
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value
            if isinstance(value, dict):
                nested = value.get("text") or value.get("value")
                if isinstance(nested, str) and nested.strip():
                    return nested
        return ""

    @staticmethod
    def _is_web_url(url: str) -> bool:
        if not url:
            return False
        parsed = urlparse(url.strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
