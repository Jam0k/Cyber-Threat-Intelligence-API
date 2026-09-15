#!/usr/bin/env python3
"""siem-ioc-enrichment: what does ThreatCluster know about this indicator?

What it does
  For each IOC (domain, IPv4 or MD5/SHA1/SHA256 hash) it finds the matching entity, then
  prints the incident context: the clusters it appears in (title, score, link), the actors
  / malware / tools seen alongside it, and the other indicators from the top cluster, so an
  analyst can pivot straight from a SIEM alert.

Endpoints
  GET /entities/search?q=<ioc>              (1 credit)  resolve the indicator to an entity
  GET /entities/{type}/{value}              (1 credit)  clusters + co-occurring entities
  GET /threats/{slug}                       (1 credit)  full entity set of the top cluster

Cost: up to 3 credits per IOC. Works on the free tier (7-day window).

Usage
  python3 siem-ioc-enrichment.py evil-domain.example 203.0.113.7 <sha256>
"""
import argparse
import re
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
    remaining = _credits["remaining"] if _credits["remaining"] is not None else "n/a"
    sys.stderr.write("[threatcluster] credits used this run: %d, remaining today: %s\n" % (_credits["used"], remaining))

INDICATOR_TYPES = ("domain", "ipv4", "ipv6", "url", "md5", "sha1", "sha256", "email")
CONTEXT_TYPES = ("apt_group", "ransomware_group", "malware", "tool", "campaign", "cve", "attack_type", "platform")


def guess_type(ioc):
    # Only used to narrow the search; the API's own entity_type is what we trust.
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ioc):
        return "ipv4"
    if re.fullmatch(r"[0-9a-fA-F]{64}", ioc):
        return "sha256"
    if re.fullmatch(r"[0-9a-fA-F]{40}", ioc):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{32}", ioc):
        return "md5"
    return "domain"


def enrich(ioc):
    hits = api_get("/entities/search", q=ioc, entity_type=guess_type(ioc), limit=5).json().get("entities", [])
    match = next((e for e in hits if (e.get("entity_value") or "").lower() == ioc.lower()), None)
    print("== %s" % ioc)
    if not match:
        print("   no ThreatCluster context in the last 7 days\n")
        return
    etype, value = match["entity_type"], match["entity_value"]
    print("   type %s; %s cluster(s), %s article(s); page %s/entities/%s/%s"
          % (etype, match.get("cluster_count", "?"), match.get("article_count", "?"), SITE, etype.replace("_", "-"), value))

    time.sleep(PACE_SECONDS)
    detail = api_get("/entities/%s/%s" % (etype, value)).json()
    clusters = detail.get("clusters", [])
    print("   Clusters:")
    for c in clusters:
        print("     %5.1f  %-7s  %s\n            %s" % (c.get("threat_score") or 0, c.get("urgency_level") or "-",
                                                      c.get("ai_title") or c.get("title"), cluster_url(c)))
    co = detail.get("co_entities") or {}
    for t in CONTEXT_TYPES:
        vals = co.get(t)
        if vals:
            print("   %-17s %s" % (t + ":", ", ".join(str(v.get("value", v)) if isinstance(v, dict) else str(v) for v in vals[:8])))

    if not clusters:
        print()
        return
    time.sleep(PACE_SECONDS)
    top = api_get("/threats/" + (clusters[0].get("slug") or clusters[0].get("cluster_id"))).json()
    ents = top.get("entities") or {}
    print("   Related indicators (from the top cluster):")
    shown = 0
    for t in INDICATOR_TYPES:
        for v in ents.get(t, []) or []:
            if str(v).lower() != ioc.lower():
                print("     %-8s %s" % (t, v))
                shown += 1
    if not shown:
        print("     (none beyond the queried indicator)")
    print()


def main():
    ap = argparse.ArgumentParser(description="Enrich IOCs with ThreatCluster incident context")
    ap.add_argument("iocs", nargs="+", help="domains, IPv4s or file hashes")
    args = ap.parse_args()
    for i, ioc in enumerate(args.iocs):
        if i:
            time.sleep(PACE_SECONDS)
        enrich(ioc.strip())
    report_credits()


if __name__ == "__main__":
    main()
