#!/usr/bin/env python3
"""sector-ransomware-watch: new dark-web ransomware victims for a sector/country, as a Slack message.

What it does
  Lists leak-site victims posted in the last N days (free tier: up to 7), optionally
  filtered to one sector and/or country, and formats them as a Slack mrkdwn message
  with the week's most active groups underneath. If SLACK_WEBHOOK_URL is set the
  message is posted; otherwise it is printed so you can see exactly what would go out.

Endpoints
  GET /darkweb/ransomware/victims/facets   (1 credit)  sector/country/group counts
  GET /darkweb/ransomware/victims          (1 credit)  the victim rows

Cost: 2 credits per run. Works on the free tier (7-day window, 25 rows per list).

Usage
  python3 sector-ransomware-watch.py --sector Healthcare
  python3 sector-ransomware-watch.py --sector "Financial Services" --country US --days 3
  Sector names are the values returned by the facets endpoint (printed on a bad name).
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
    # Keys without a daily cap send no remaining-credits header.
    left = ", remaining today: %s" % _credits["remaining"] if _credits["remaining"] is not None else ""
    sys.stderr.write("[threatcluster] credits used this run: %d%s\n" % (_credits["used"], left))


def main():
    ap = argparse.ArgumentParser(description="New ransomware victims for a sector/country -> Slack message")
    ap.add_argument("--sector", help="sector name exactly as the facets endpoint returns it")
    ap.add_argument("--country", help="ISO-2 country code, e.g. US, GB, DE")
    ap.add_argument("--days", type=int, default=7, help="lookback in days (free tier caps at 7)")
    ap.add_argument("--limit", type=int, default=25, help="max victims to list (free tier caps at 25)")
    args = ap.parse_args()

    facets = api_get("/darkweb/ransomware/victims/facets", days=args.days).json()
    sectors = {s["value"]: s["count"] for s in facets.get("sectors", [])}
    if args.sector and args.sector not in sectors:
        sys.exit("Unknown sector %r. Sectors seen in the window: %s" % (args.sector, ", ".join(sorted(sectors))))

    time.sleep(PACE_SECONDS)
    filters = {}
    if args.sector:
        filters["sector"] = args.sector
    if args.country:
        filters["country"] = args.country.upper()
    data = api_get("/darkweb/ransomware/victims", days=args.days, limit=args.limit, **filters).json()
    victims = data.get("victims", [])

    scope = " / ".join(x for x in [args.sector, args.country and args.country.upper()] if x) or "all sectors"
    lines = ["*ThreatCluster ransomware watch: %s, last %d days*" % (scope, data.get("lookback_days") or args.days)]
    if not victims:
        lines.append("No new leak-site victims matched.")
    else:
        shown = "%d new leak-site victims" % len(victims)
        if len(victims) >= args.limit:
            shown += " (showing the first %d)" % args.limit
        lines.append(shown)
        for v in victims:
            posted = (v.get("discovered") or "")[:10]
            name = v.get("name") or v.get("victim") or "?"
            where = v.get("country") or "--"
            sector = "" if args.sector else "  [%s]" % (v.get("sector") or "unknown sector")
            lines.append("• %s  %s  →  <%s/dark-web/victim/%s|%s>  (%s)%s"
                         % (posted, v.get("group", "?"), SITE, v.get("id", ""), name, where, sector))

    top_groups = ", ".join("%s %d" % (g["value"], g["count"]) for g in facets.get("groups", [])[:5])
    top_sectors = ", ".join("%s %d" % (s["value"], s["count"]) for s in facets.get("sectors", [])[:5])
    lines.append("_Most active groups this window: %s_" % top_groups)
    lines.append("_Most hit sectors this window: %s_" % top_sectors)
    lines.append("Source: %s/dark-web/victims" % SITE)
    message = "\n".join(lines)

    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if webhook:
        resp = requests.post(webhook, json={"text": message}, timeout=30)
        if resp.status_code >= 400:
            sys.exit("Slack webhook returned HTTP %d: %s" % (resp.status_code, resp.text[:200]))
        print("Posted %d victims to Slack." % len(victims))
    else:
        print(message)
    report_credits()


if __name__ == "__main__":
    main()
