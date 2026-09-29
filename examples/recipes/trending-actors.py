#!/usr/bin/env python3
"""trending-actors: which threat actors, ransomware crews and malware families are rising this week?

What it does
  Prints the trending APT groups, ransomware groups and malware families of the last
  7 days: how many clusters mention them, the change versus the previous window, whether
  they are new to the corpus, and the ThreatCluster entity page for each.

Endpoints
  GET /entities/trending?time_filter=7d&limit=10   (1 credit)

Cost: 1 credit per run. Works on the free tier.

Usage
  python3 trending-actors.py
  python3 trending-actors.py --types apt_group malware cve
"""
import argparse
from urllib.parse import quote
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

DEFAULT_TYPES = ["apt_group", "ransomware_group", "malware"]


def main():
    ap = argparse.ArgumentParser(description="Trending actors/malware this week")
    ap.add_argument("--types", nargs="+", default=DEFAULT_TYPES, help="entity types to show")
    ap.add_argument("--limit", type=int, default=10, help="rows per type (free tier caps at 10)")
    args = ap.parse_args()

    data = api_get("/entities/trending", time_filter="7d", limit=args.limit).json()
    trending = data.get("trending", {})
    for etype in args.types:
        rows = trending.get(etype) or []
        print("== %s (last %s) ==" % (etype, data.get("time_filter", "7d")))
        if not rows:
            print("   nothing trending\n")
            continue
        print("   %-28s %8s %8s  %s" % ("entity", "mentions", "change", "page"))
        for r in rows:
            change = "NEW" if r.get("is_new") else ("%+.0f%%" % r["change"] if r.get("change") is not None else "-")
            # quote(safe='') because entity values can contain '/', '#' or spaces.
            print("   %-28s %8s %8s  %s/entities/%s/%s" % ((r.get("value") or "")[:28], r.get("frequency", "?"), change,
                                                          SITE, etype.replace("_", "-"), quote(str(r.get("value") or ""), safe="")))
        print()
    report_credits()


if __name__ == "__main__":
    main()
