#!/usr/bin/env python3
"""vendor-in-the-news: which of my vendors/products are in incident reporting this week?

What it does
  For each vendor or product name you give it, pulls the highest-scoring threat clusters
  of the last 7 days whose title, summary or keywords mention that name, keeps those at
  or above a threat-score threshold, and prints one line per hit with a link to the
  ThreatCluster cluster page.

Endpoints
  GET /threats?keyword=<name>&time_filter=7d&sort_by=threat_score   (1 credit per vendor)

Cost: 1 credit per vendor name. Works on the free tier (7-day window, 25 rows per query).

Usage
  python3 vendor-in-the-news.py Microsoft Cisco Fortinet Ivanti Citrix
  python3 vendor-in-the-news.py --min-score 70 "Palo Alto" SonicWall
"""
import argparse
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

DEFAULT_VENDORS = ["Microsoft", "Cisco", "Fortinet", "Ivanti", "Citrix"]


def main():
    ap = argparse.ArgumentParser(description="Incident clusters mentioning your vendors this week")
    ap.add_argument("vendors", nargs="*", default=DEFAULT_VENDORS, help="vendor/product names")
    ap.add_argument("--min-score", type=float, default=60.0, help="threat-score threshold (0-100)")
    args = ap.parse_args()

    total_hits = 0
    seen = set()  # the same cluster can match two vendors; print it once, under the first
    for i, vendor in enumerate(args.vendors):
        if i:
            time.sleep(PACE_SECONDS)
        data = api_get("/threats", keyword=vendor, time_filter="7d", sort_by="threat_score", limit=25).json()
        hits = [t for t in data.get("threats", [])
                if (t.get("threat_score") or 0) >= args.min_score and t.get("cluster_id") not in seen]
        print("%s: %d cluster(s) >= %g in the last 7 days" % (vendor, len(hits), args.min_score))
        for t in hits:
            seen.add(t.get("cluster_id"))
            total_hits += 1
            title = t.get("ai_title") or t.get("title") or "(untitled)"
            print("  %5.1f  %-7s  %s\n         %s" % (t.get("threat_score") or 0, t.get("urgency_level") or "-",
                                                   title, cluster_url(t)))
    print("\n%d cluster(s) across %d vendor name(s)." % (total_hits, len(args.vendors)))
    report_credits()


if __name__ == "__main__":
    main()
