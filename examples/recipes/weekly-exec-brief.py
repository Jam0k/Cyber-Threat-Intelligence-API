#!/usr/bin/env python3
"""weekly-exec-brief: the week's top 10 threat clusters as a Markdown brief.

What it does
  Pulls the ten highest-scoring threat clusters of the last 7 days and renders a Markdown
  brief: rank, title, score and urgency, a one-sentence summary, entity chips (actors,
  malware, CVEs, platforms...) and a link to each cluster. Saved to brief.md and printed.

Endpoints
  GET /threats?time_filter=7d&sort_by=threat_score&limit=10   (1 credit)

Cost: 1 credit per run. Works on the free tier.

Usage
  python3 weekly-exec-brief.py                # writes ./brief.md
  python3 weekly-exec-brief.py --out /tmp/brief.md
"""
import argparse
from datetime import datetime, timezone
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

CHIP_TYPES = ("apt_group", "ransomware_group", "malware", "campaign", "cve", "platform", "company", "country")


def first_sentence(text):
    text = (text or "").strip().replace("\n", " ")
    for stop in (". ", "! ", "? "):
        if stop in text:
            return text.split(stop, 1)[0] + stop.strip()
    return text


def chips(entities, max_chips=6):
    # One chip per type first (breadth), then fill the remaining slots.
    out = []
    ents = entities if isinstance(entities, dict) else {}
    for t in CHIP_TYPES:
        if ents.get(t):
            out.append("`%s: %s`" % (t, ents[t][0]))
    for t in CHIP_TYPES:
        for v in (ents.get(t) or [])[1:]:
            if len(out) >= max_chips:
                break
            out.append("`%s: %s`" % (t, v))
    return " ".join(out[:max_chips])


def main():
    ap = argparse.ArgumentParser(description="Top-10 weekly brief in Markdown")
    ap.add_argument("--out", default="brief.md", help="where to write the brief")
    args = ap.parse_args()

    data = api_get("/threats", time_filter="7d", sort_by="threat_score", limit=10).json()
    threats = data.get("threats", [])
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    md = ["# ThreatCluster weekly executive brief: week ending %s" % today, "",
          "Top %d threat clusters of the last 7 days, ranked by ThreatCluster threat score." % len(threats), ""]
    for i, t in enumerate(threats, 1):
        title = t.get("ai_title") or t.get("title") or "(untitled)"
        md.append("## %d. %s" % (i, title))
        md.append("**Score %.0f** · %s urgency · %s article(s) · latest activity %s"
                  % (t.get("threat_score") or 0, t.get("urgency_level") or "unknown",
                     t.get("article_count") or 0, (t.get("date_range_latest") or "")[:10]))
        md.append("")
        md.append(first_sentence(t.get("ai_summary")))
        md.append("")
        chip_line = chips(t.get("entities"))
        if chip_line:
            md.append(chip_line)
        md.append("[Read the cluster](%s)" % cluster_url(t))
        md.append("")
    md.append("---")
    md.append("Generated with the ThreatCluster public API (free tier, 7-day window).")
    text = "\n".join(md) + "\n"

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text, end="")
    sys.stderr.write("[weekly-exec-brief] wrote %s\n" % args.out)
    report_credits()


if __name__ == "__main__":
    main()
