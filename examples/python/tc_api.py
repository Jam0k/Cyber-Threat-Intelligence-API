"""Minimal ThreatCluster API client. Stdlib + requests only.

    from tc_api import ThreatCluster
    tc = ThreatCluster()                      # reads TC_KEY from the environment
    for t in tc.threats(time_filter="24h", limit=10):
        print(t["threat_score"], t["ai_title"])

Handles: auth header, 429 back-off (honours Retry-After), 403 lookback/scope
errors surfaced as PermissionError, and offset pagination. Free keys get a
7-day window and trimmed rows — check `tier` / `lookback_days` on responses.
"""
from __future__ import annotations

import os
import time
from typing import Any, Iterator

import requests

BASE = "https://threatcluster.io/api/public/v1"


class ThreatCluster:
    def __init__(self, key: str | None = None, base: str = BASE, timeout: int = 30):
        self.key = key or os.environ.get("TC_KEY")
        if not self.key:
            raise SystemExit("set TC_KEY (mint one at https://threatcluster.io/settings#api)")
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers["X-API-Key"] = self.key
        self.s.headers["User-Agent"] = "threatcluster-api-examples/1.0"

    def get(self, path: str, retries: int = 3, **params: Any) -> Any:
        """GET a path (relative to the base). Returns parsed JSON, or text for txt/csv."""
        for attempt in range(retries + 1):
            r = self.s.get(f"{self.base}/{path.lstrip('/')}", params=params, timeout=self.timeout)
            if r.status_code == 429 and attempt < retries:
                time.sleep(int(r.headers.get("Retry-After", "5")))
                continue
            if r.status_code == 403:
                # insufficient_scope tells you which scope the key lacks
                raise PermissionError(r.json().get("detail", r.text))
            r.raise_for_status()
            ctype = r.headers.get("content-type", "")
            return r.json() if "json" in ctype else r.text
        raise RuntimeError("rate limited; retries exhausted")

    def post(self, path: str, body: dict, retries: int = 3) -> Any:
        """POST JSON to a path. Same retry/403 handling as get()."""
        for attempt in range(retries + 1):
            r = self.s.post(f"{self.base}/{path.lstrip('/')}", json=body, timeout=max(self.timeout, 90))
            if r.status_code == 429 and attempt < retries:
                time.sleep(int(r.headers.get("Retry-After", "5")))
                continue
            if r.status_code == 403:
                raise PermissionError(r.json().get("detail", r.text))
            r.raise_for_status()
            return r.json()
        raise RuntimeError("rate limited; retries exhausted")

    # -- convenience wrappers ------------------------------------------------
    def ask(self, ident: str, action: str = "custom", question: str | None = None) -> dict:
        """Ask AI about one cluster (Researcher+, 25 credits). action is one of
        executive_summary, extract_iocs, threat_actor, related_campaigns,
        vulnerability, recommended_actions, or custom with a question."""
        body = {"action": action}
        if question:
            body["question"] = question
        return self.post(f"threats/{ident}/ask", body)

    def ask_corpus(self, query: str, history: list[dict] | None = None) -> dict:
        """Ask AI across the whole corpus (Researcher+, 50 credits)."""
        body: dict = {"query": query}
        if history:
            body["history"] = history
        return self.post("ask", body)

    def search(self, q: str, limit: int = 10, include_articles: bool = False) -> dict:
        """One term across clusters, entities and the dark web."""
        return self.get("/search", q=q, limit=limit, include_articles=include_articles)

    def threats(self, **params: Any) -> list[dict]:
        return self.get("threats", **params)["threats"]

    def threat(self, ident: str) -> dict:
        return self.get(f"threats/{ident}")

    def threat_iocs(self, ident: str) -> list[dict]:
        return self.get(f"threats/{ident}/iocs")["iocs"]

    def threat_stix(self, ident: str) -> dict:
        return self.get(f"threats/{ident}/stix")

    def ioc_feed(self, **params: Any) -> Any:
        return self.get("iocs/feed", **params)

    def vulnerabilities(self, **params: Any) -> Any:
        return self.get("vulnerabilities", **params)

    def entity_search(self, q: str, **params: Any) -> Any:
        return self.get("entities/search", q=q, **params)

    def entity(self, etype: str, value: str) -> dict:
        return self.get(f"entities/{etype}/{value}")

    def related(self, etype: str, value: str) -> Any:
        return self.get(f"entities/{etype}/{value}/related")

    def iter_threats(self, page_size: int = 100, max_items: int | None = None, **params: Any) -> Iterator[dict]:
        """Walk /threats with offset pagination until a short page."""
        seen = 0
        offset = 0
        while True:
            page = self.threats(limit=page_size, offset=offset, **params)
            for t in page:
                yield t
                seen += 1
                if max_items and seen >= max_items:
                    return
            if len(page) < page_size:
                return
            offset += page_size
