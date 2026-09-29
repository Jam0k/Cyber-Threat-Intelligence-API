#!/usr/bin/env python3
"""agent-tool: a tool-calling function `threatcluster_lookup(query)` for LLM agents.

What it does
  Wraps the unified search endpoint as a plain Python function that returns a compact,
  JSON-serialisable answer: a one-line summary, the matching clusters with scores, the
  matching entities and dark-web groups, and a `citations` list of ThreatCluster URLs the
  model can quote. No LLM client is needed to run it; see TOOL_SCHEMA for registration.

Endpoints
  GET /search?q=<query>&limit=<n>   (5 credits)

Cost: 5 credits per call. Works on the free tier (7-day window).

Usage
  python3 agent-tool.py "lockbit"            # prints the JSON the model would receive

Registering it as a tool (three lines, either vendor):
  OpenAI:  tools=[{"type": "function", "function": TOOL_SCHEMA}]; on a tool call run threatcluster_lookup(**args)
  Claude:  tools=[{"name": TOOL_SCHEMA["name"], "description": TOOL_SCHEMA["description"], "input_schema": TOOL_SCHEMA["parameters"]}]
  Either:  return json.dumps(threatcluster_lookup(**args)) as the tool result; the model cites the `citations` URLs.
"""
import json
import os
import sys
import time

import requests

API_BASE = os.environ.get("THREATCLUSTER_API_BASE", "https://threatcluster.io/api/public/v1").rstrip("/")
API_KEY = os.environ.get("THREATCLUSTER_API_KEY", "")
SITE = os.environ.get("THREATCLUSTER_SITE", "https://threatcluster.io")  # where the linked pages live
PACE_SECONDS = 2.1  # free keys get 30 requests/min; ~28/min keeps loops clear of 429s
_credits = {"used": 0, "remaining": None}


def _auth_headers():
    # A tc_... key is sent as X-API-Key; anything else is a short-lived bearer (e.g. from `tc login`).
    if not API_KEY:
        sys.exit("THREATCLUSTER_API_KEY is not set. Free keys: https://threatcluster.io/about/api")
    if API_KEY.startswith("tc_"):
        return {"X-API-Key": API_KEY}
    return {"Authorization": "Bearer " + API_KEY}


def api_get(path, _allow=(), **params):
    """GET one endpoint. Exits non-zero with the API's own error body, unless the
    status is listed in _allow (per-item lookups where a 404 is itself an answer)."""
    r = requests.get(API_BASE + path, headers=_auth_headers(), params=params, timeout=60)
    if "X-Request-Cost" in r.headers:
        _credits["used"] += int(r.headers["X-Request-Cost"])
    if "X-RateLimit-Remaining" in r.headers:
        _credits["remaining"] = r.headers["X-RateLimit-Remaining"]
    if r.status_code >= 400 and r.status_code not in _allow:
        try:
            body = json.dumps(r.json())
        except ValueError:
            body = r.text[:500]
        sys.exit("HTTP %d from %s: %s" % (r.status_code, path, body))
    return r


def cluster_url(cluster):
    # The free payload carries `slug` (canonical page) and `cluster_id`; the last 8 hex
    # chars of the id also resolve, via a 301 to the slug, when slug is missing.
    ident = cluster.get("slug") or cluster.get("short_id") or cluster.get("cluster_id", "").replace("-", "")[-8:]
    return "%s/cluster/%s" % (SITE, ident)


def report_credits():
    # Stderr, so it never pollutes piped output (brief.md, blocklists, JSON).
    # Keys without a daily cap send no remaining-credits header.
    left = ", remaining today: %s" % _credits["remaining"] if _credits["remaining"] is not None else ""
    sys.stderr.write("[threatcluster] credits used this run: %d%s\n" % (_credits["used"], left))

TOOL_SCHEMA = {
    "name": "threatcluster_lookup",
    "description": ("Look up a threat actor, malware family, CVE, vendor, product or campaign in ThreatCluster's "
                    "incident corpus (last 7 days on a free key). Returns matching incident clusters with threat "
                    "scores, related entities, dark-web groups, and citation URLs."),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What to look up, e.g. 'LockBit', 'CVE-2026-83549', 'Ivanti'"},
            "limit": {"type": "integer", "description": "Max clusters to return (1-10)", "default": 5},
        },
        "required": ["query"],
    },
}


def threatcluster_lookup(query, limit=5):
    data = api_get("/search", q=query, limit=max(1, min(int(limit), 10))).json()
    clusters = []
    for c in data.get("clusters", []):
        clusters.append({
            "title": c.get("ai_title") or c.get("title"),
            "threat_score": c.get("threat_score"),
            "urgency": c.get("urgency_level"),
            "latest_activity": (c.get("date_range_latest") or c.get("updated_at") or "")[:10],
            "summary": c.get("ai_summary"),
            "url": cluster_url(c),
        })
    entities = [{"type": e.get("entity_type"), "value": e.get("entity_value"),
                 "clusters": e.get("cluster_count"),
                 "url": "%s/entities/%s/%s" % (SITE, (e.get("entity_type") or "").replace("_", "-"), e.get("entity_value"))}
                for e in data.get("entities", [])]
    darkweb = [{"type": d.get("type"), "name": d.get("name"), "active": d.get("active"),
                "victim_count": d.get("victim_count")} for d in data.get("darkweb", [])]

    if clusters:
        top = clusters[0]
        answer = ("%d incident cluster(s) in the last %s days match %r; highest-scoring: %r (score %s, %s)."
                  % (len(clusters), data.get("days") or data.get("lookback_days") or 7, query,
                     top["title"], top["threat_score"], top["latest_activity"]))
    else:
        answer = "No incident clusters in the last %s days match %r." % (data.get("days") or 7, query)
    return {
        "query": query,
        "window_days": data.get("days") or data.get("lookback_days"),
        "answer": answer,
        "clusters": clusters,
        "entities": entities,
        "darkweb": darkweb,
        "citations": [c["url"] for c in clusters] + [e["url"] for e in entities[:3]],
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: agent-tool.py <query>")
    print(json.dumps(threatcluster_lookup(" ".join(sys.argv[1:])), indent=2))
    report_credits()
