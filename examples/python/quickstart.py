#!/usr/bin/env python3
"""Morning board: top clusters and confirmed IOCs from the last 24 hours.

    export TC_KEY=tc_live_…
    python3 quickstart.py
"""
from tc_api import ThreatCluster

tc = ThreatCluster()

print("== search?q=lockbit: clusters / entities / dark web ==")
hits = tc.search("lockbit", limit=5)
for c in hits["clusters"]:
    print(f"cluster  {c.get('threat_score', 0):5.1f}  {c.get('ai_title')}  [{c.get('short_id')}]")
for e in hits["entities"]:
    print(f"entity   {e['entity_type']}: {e['entity_value']}  ({e.get('cluster_count', 0)} clusters)")
for d in hits["darkweb"]:
    print(f"darkweb  {d['type']}: {d.get('name')}  {d.get('date') or ''}")

print("\n== Trending, last 24h ==")
for t in tc.threats(time_filter="24h", limit=10):
    short = t["cluster_id"].replace("-", "")[-8:]
    print(f"{t.get('threat_score', 0):5.1f}  {t.get('ai_title') or t.get('title')}")
    print(f"       {', '.join(t.get('keywords') or [])[:100]}")
    print(f"       https://threatcluster.io/api/public/v1/threats/{short}")

print("\n== Confirmed IOCs, last 24h ==")
feed = tc.ioc_feed(hours=24, confidence="confirmed", format="json")
rows = feed.get("iocs", feed) if isinstance(feed, dict) else feed
by_type: dict[str, int] = {}
for r in rows:
    by_type[r.get("type", "?")] = by_type.get(r.get("type", "?"), 0) + 1
for k, v in sorted(by_type.items(), key=lambda kv: -kv[1]):
    print(f"{v:6d}  {k}")
