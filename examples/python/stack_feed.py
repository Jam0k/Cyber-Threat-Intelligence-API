#!/usr/bin/env python3
"""Run your monitoring through the API: a feed built from your stack, a webhook,
an alert rule on the vendors in it, a CVE rule on the products, then poll for
what is new. Researcher plan or above (feeds:write, alerts:write).

    export TC_KEY=tc_live_…
    python3 stack_feed.py https://hooks.example.com/threatcluster
    python3 stack_feed.py https://hooks.example.com/threatcluster --since 2026-09-06T00:00:00Z

Everything it creates is printed with its id so you can keep or delete it
(DELETE /feeds/{id}, /webhooks/{id}, /alert-rules/{uuid}, /cve-alerts/{uuid}).
"""
import argparse
from datetime import datetime, timedelta, timezone

from tc_api import ThreatCluster

STACK = [  # what you run, typed so it hits the entity graph rather than free text
    {"keyword": "FortiOS", "entity_type": "platform"},
    {"keyword": "Okta", "entity_type": "company"},
    {"keyword": "Ivanti", "entity_type": "company"},
    {"keyword": "Snowflake", "entity_type": "company"},
]

ap = argparse.ArgumentParser()
ap.add_argument("webhook_url", help="HTTPS endpoint that should receive alerts (SOAR, Slack app, your own)")
ap.add_argument("--since", help="ISO-8601; default = last 24h", default=None)
a = ap.parse_args()
since = a.since or (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
tc = ThreatCluster()

feed = tc.create_feed("Our stack", entities=STACK, description="created by stack_feed.py")
fid = feed["feed_id"]
print(f"feed      {fid}  ({feed['keywords_added']} entities)")

hook = tc.create_webhook(a.webhook_url, name="stack_feed.py", webhook_type="json")["webhook"]
print(f"webhook   {hook['id']}  {hook['webhook_url']}")

rule = tc.create_alert_rule(
    "Stack vendors named in an incident",
    conditions=[{"entity_type": e["entity_type"], "entity_value": e["keyword"]} for e in STACK],
    logic="OR", webhook_id=hook["id"])["rule"]
print(f"rule      {rule['uuid']}  {len(rule['conditions'])} conditions")

cve = tc.create_cve_rule("Exploited CVEs in our products", webhook_id=hook["id"],
                         vendors=["Fortinet", "Okta", "Ivanti"], severity=["CRITICAL", "HIGH"], require_kev=True)["rule"]
print(f"cve rule  {cve['uuid']}")

dry = tc.post(f"alert-rules/{rule['uuid']}/test", {})
print(f"\ndry run: {dry['total_matches']} clusters in the last 7 days would have fired")
for m in dry["matching_clusters"][:5]:
    print(f"  {m['created_at'][:10]}  {m['threat_score']:>5}  {m['title']}")

items = tc.feed(fid, since=since, sort_by="latest", limit=10).get("items", [])
print(f"\nfeed items since {since}: {len(items)}")
for it in items:
    print(f"  {str(it.get('date_range_latest') or it.get('pub_date') or '')[:10]}  {it.get('ai_title') or it.get('title')}")

fired = tc.alerts(since=since, limit=10)
print(f"\nalerts fired since {since}: {fired.get('count', len(fired.get('alerts') or []))}")
