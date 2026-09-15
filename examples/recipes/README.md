# Recipes

Small, runnable examples for the ThreatCluster public API. Every script works on the free key,
uses only `requests` and the standard library, and was executed against the live API before
being published; the captured output is shown on https://threatcluster.io/build/<slug>.

```bash
export THREATCLUSTER_API_KEY=tc_live_...   # free key: https://threatcluster.io/api
python3 examples/recipes/<slug>.py
```

| Recipe | What it does | Credits / run |
|---|---|---|
| [A lookup tool for LLM agents](agent-tool.py) | a tool-calling function `threatcluster_lookup(query)` for LLM agents. | 5 |
| [Brand and domain dark-web monitor](brand-domain-monitor.py) | are my brands or domains showing up on the dark web?. | 3 |
| [CVE triage: KEV and EPSS filter](cve-triage.py) | from a list of CVE ids, keep only the ones that matter right now. | 10 |
| [Exploited this week](exploited-this-week.py) | CVEs from the last 7 days that are in KEV or have a public exploit. | 2 |
| [IOC blocklist export](ioc-blocklist-export.py) | validated malicious domains and IPs as plain blocklists. | 3 |
| [Sector ransomware watch for Slack](sector-ransomware-watch.py) | new dark-web ransomware victims for a sector/country, as a Slack message. | 2 |
| [SIEM indicator enrichment](siem-ioc-enrichment.py) | what does ThreatCluster know about this indicator?. | 6 |
| [Trending threat actors](trending-actors.py) | which threat actors, ransomware crews and malware families are rising this week?. | 1 |
| [Vendor in the news](vendor-in-the-news.py) | which of my vendors/products are in incident reporting this week?. | 5 |
| [Weekly executive brief](weekly-exec-brief.py) | the week's top 10 threat clusters as a Markdown brief. | 1 |

Bearer tokens from `tc login` also work: if the key does not start with `tc_` the scripts send it as `Authorization: Bearer`.

Every recipe here was run against the live API before publishing; the captured
output for each is shown on its page at https://threatcluster.io/build.
