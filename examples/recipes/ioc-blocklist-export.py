#!/usr/bin/env python3
"""ioc-blocklist-export: validated malicious domains and IPs as plain blocklists.

What it does
  Pulls the confirmed indicators extracted from the last N hours of reporting and writes
  two plain files, one indicator per line and nothing else, ready for a firewall object
  group or a Pi-hole adlist: blocklist-domains.txt and blocklist-ips.txt. Counts and the
  number of indicators still pending validation are printed.

Endpoints
  GET /iocs/export?types=domain,ip&format=json   (3 credits)

Cost: 3 credits per run. Works on the free tier (window capped at 168 hours).

Usage
  python3 ioc-blocklist-export.py                      # last 7 days into ./
  python3 ioc-blocklist-export.py --hours 24 --out-dir /etc/pihole/lists
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


def main():
    ap = argparse.ArgumentParser(description="Export confirmed domains/IPs as blocklists")
    ap.add_argument("--hours", type=int, default=168, help="lookback in hours (free tier caps at 168)")
    ap.add_argument("--confidence", default="confirmed", help="confirmed (default) or all")
    ap.add_argument("--out-dir", default=".", help="directory for the two list files")
    args = ap.parse_args()

    data = api_get("/iocs/export", types="domain,ip", format="json", hours=args.hours, confidence=args.confidence).json()
    domains, ips = set(), set()
    by_conf = {}
    for ioc in data.get("iocs", []):
        by_conf[ioc.get("confidence")] = by_conf.get(ioc.get("confidence"), 0) + 1
        t, v = ioc.get("type"), (ioc.get("value") or "").strip().lower()
        if not v:
            continue
        if t == "domain":
            domains.add(v)
        elif t in ("ipv4", "ipv6", "ip"):
            ips.add(v)

    os.makedirs(args.out_dir, exist_ok=True)
    paths = {}
    for name, values in (("blocklist-domains.txt", domains), ("blocklist-ips.txt", ips)):
        path = os.path.join(args.out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(values)) + ("\n" if values else ""))
        paths[name] = path

    print("Window: last %s hours, confidence filter: %s" % (data.get("hours", args.hours), data.get("confidence_filter", args.confidence)))
    print("Indicators returned: %d (%s)" % (data.get("count", len(domains) + len(ips)),
                                           ", ".join("%s=%d" % kv for kv in sorted(by_conf.items(), key=lambda kv: str(kv[0])))))
    print("Still pending validation (not exported): %s" % data.get("pending_count", 0))
    print("%-22s %5d  ->  %s" % ("domains", len(domains), paths["blocklist-domains.txt"]))
    print("%-22s %5d  ->  %s" % ("ips", len(ips), paths["blocklist-ips.txt"]))
    if domains:
        print("first domains: " + ", ".join(sorted(domains)[:5]))
    if ips:
        print("first ips:     " + ", ".join(sorted(ips)[:5]))
    report_credits()


if __name__ == "__main__":
    main()
