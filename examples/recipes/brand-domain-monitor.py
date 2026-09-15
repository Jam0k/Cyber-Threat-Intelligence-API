#!/usr/bin/env python3
"""brand-domain-monitor: are my brands or domains showing up on the dark web?

What it does
  Matches a list of keywords (brand names, domains, subsidiaries) against ransomware
  leak-site victims and ransomware groups in one call,
  and prints the hits per bucket with dates and links.

Endpoints
  GET /darkweb/keyword-hits?keywords=a,b,c   (3 credits, however many keywords)

Cost: 3 credits per run. Works on the free tier (7-day window, up to 5 hits per bucket).

Usage
  python3 brand-domain-monitor.py acme acme-corp.example "Acme Holdings"
  (The default keywords are generic sector words, so the demo has something to show.)
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

DEFAULT_KEYWORDS = ["bank", "hospital", "school"]


def matched(keywords, *fields):
    blob = " ".join(str(f or "") for f in fields).lower()
    return ", ".join(k for k in keywords if k.lower() in blob) or "(matched on other fields)"


def main():
    ap = argparse.ArgumentParser(description="Dark-web keyword hits for brands/domains")
    ap.add_argument("keywords", nargs="*", default=DEFAULT_KEYWORDS, help="brand names, domains, subsidiaries")
    ap.add_argument("--per-bucket", type=int, default=25, help="max hits per bucket (free tier caps at 5)")
    args = ap.parse_args()

    data = api_get("/darkweb/keyword-hits", keywords=",".join(args.keywords), per_bucket_limit=args.per_bucket).json()
    hits = data.get("hits", {})
    print("Keywords: %s" % ", ".join(data.get("keywords", args.keywords)))
    print("Total hits: %s (window: last %s days)\n" % (data.get("total", 0), data.get("lookback_days", "?")))

    for v in hits.get("victims", []):
        print("VICTIM   %s  %-14s %-32s %s  %s"
              % ((v.get("discovered") or "")[:10], v.get("group_name") or "?", (v.get("victim_name") or "?")[:32],
                 v.get("country") or "--", v.get("sector") or ""))
        print("         matched: %s  %s/dark-web/victim/%s" % (matched(args.keywords, v.get("victim_name")), SITE, v.get("id", "")))
    for g in hits.get("groups", []):
        print("GROUP    %s  %s/dark-web/group/%s" % (g.get("name") or g.get("group_name") or "?", SITE, g.get("name") or ""))
    empty = [k for k in ("victims", "groups") if not hits.get(k)]
    if empty:
        print("\nNo hits in: %s" % ", ".join(empty))
    report_credits()


if __name__ == "__main__":
    main()
