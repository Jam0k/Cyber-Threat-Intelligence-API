#!/usr/bin/env python3
"""KEV-listed CVEs with a public exploit, filtered to the vendors you run.

    export TC_KEY=tc_live_…
    python3 kev_watch.py fortinet cisco "palo alto" ivanti
"""
import sys

from tc_api import ThreatCluster

vendors = sys.argv[1:] or ["fortinet", "cisco", "ivanti", "citrix", "microsoft"]
tc = ThreatCluster()

for vendor in vendors:
    res = tc.vulnerabilities(days=30, kev_only=True, has_exploit=True, vendor=vendor, limit=20)
    cves = res.get("cves", []) if isinstance(res, dict) else res
    if not cves:
        continue
    print(f"\n== {vendor} ({res.get('total', len(cves))} total) ==")
    for c in cves:
        print(f"{c['cve_id']:<18} CVSS {str(c.get('cvss_v3_score') or '-'):<5} "
              f"EPSS {str(c.get('epss_score') or '-'):<6} "
              f"{(c.get('description') or '')[:80]}")
