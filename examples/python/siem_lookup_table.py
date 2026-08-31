#!/usr/bin/env python3
"""Write a CSV lookup table of confirmed IOCs for Splunk / Sentinel / Elastic.

    export TC_KEY=tc_live_…
    python3 siem_lookup_table.py --hours 168 --out tc_iocs.csv

Schedule it hourly; the API returns first_seen/last_seen so you can age rows out.
Free key: one request per run, 100/day budget; --hours is clamped to 168 (7 days).
"""
import argparse
import csv
import sys

from tc_api import ThreatCluster

ap = argparse.ArgumentParser()
ap.add_argument("--hours", type=int, default=168, help="free keys are clamped to 168")
ap.add_argument("--types", default="all", help="all | domain,ip,hash,url …")
ap.add_argument("--out", default="tc_iocs.csv")
args = ap.parse_args()

tc = ThreatCluster()
feed = tc.ioc_feed(hours=args.hours, types=args.types, confidence="confirmed",
                   format="json", threat_score=True)
rows = feed.get("iocs", feed) if isinstance(feed, dict) else feed
if not rows:
    print("no indicators in window", file=sys.stderr)
    sys.exit(0)

fields = ["value", "type", "confidence", "first_seen", "last_seen", "threat_score", "cluster_ids"]
with open(args.out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        r = dict(r)
        if isinstance(r.get("cluster_ids"), list):
            r["cluster_ids"] = "|".join(r["cluster_ids"])
        w.writerow(r)
print(f"{len(rows)} indicators -> {args.out}")
