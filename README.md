# Cyber Threat Intelligence (CTI) API

Threat intelligence as a REST API: clustered threat reporting with AI summaries and scores,
validated IOCs, entity intelligence (actors, malware, tools, companies, CVEs), vulnerability
data with EPSS/KEV, ransomware leak-site tracking, and cited Ask-AI answers — 42 endpoints under one base URL.

**Free tier included.** Every account can mint a read-only key: 100 credits a day over the last 7 days, headline rows. No card, no trial clock. Paid plans buy history, depth and budget — not access.

| | |
|---|---|
| Base URL | `https://threatcluster.io/api/public/v1` |
| Auth | `X-API-Key: tc_live_…` header |
| Docs | [Swagger UI](https://threatcluster.io/api/public/v1/docs) · [ReDoc](https://threatcluster.io/api/public/v1/redoc) · [openapi.json](https://threatcluster.io/api/public/v1/openapi.json) |
| Quick start | https://threatcluster.io/api |
| Free key | 100 credits/day · 30 req/min · last 7 days · `threats:read` `iocs:read` `entities:read` `vulns:read` `darkweb:read` |

This repo holds a daily-refreshed **OpenAPI snapshot** ([`openapi/openapi.json`](openapi/openapi.json)),
a dependency-light **Python client**, **runnable examples** in curl, Python and Node, and a
walkthrough of **real request/response pairs** for every major endpoint — [EXAMPLES.md](EXAMPLES.md).
It's also the issue tracker for the API — bugs, field questions, endpoint requests: open an issue.

---

## Quickstart

1. **Sign up** (free) at https://threatcluster.io
2. **Mint a key**: Settings → API & Feeds → Generate API key. It starts `tc_live_`, is shown once, and carries the scopes of your plan.
   Every cluster, entity, CVE and leak-site page on the site has an **API** button that shows the exact request for that record.
3. **Call it**:

```bash
export TC_KEY=tc_live_…
curl -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/threats?time_filter=24h&limit=5"
```

```json
{
  "threats": [
    {
      "cluster_id": "9c2f…-a1b2c3d4",
      "ai_title": "Qilin claims UK NHS supplier, 400 GB listed on leak site",
      "ai_summary": "…",
      "threat_score": 78.4,
      "severity_score": 82, "actionability_score": 64, "credibility_score": 91,
      "urgency_level": "high",
      "article_count": 14,
      "keywords": ["qilin", "healthcare", "united kingdom", "data leak"],
      "sources": ["https://…", "https://…"],
      "timeline": [{"date": "2026-08-29", "event": "Victim listed on leak site"}]
    }
  ],
  "count": 5, "limit": 5, "offset": 0, "time_filter": "24h", "sort_by": "trending"
}
```

The last 8 characters of `cluster_id` are the short id; `https://threatcluster.io/cluster/<slug>-<short_id>`
is the human page, and `.md` / `.json` variants of that URL exist for LLM context.

---

## Endpoints

Grouped by the scope a key needs. **free** = reachable with a free key.

### Account — any key (free, costs 0)
| Method + path | What you get |
|---|---|
| `GET /me` | Your tier, per-minute rate, credits used and left today, when the allowance resets, prepaid pack balance, the key's scopes, and the per-request cost table. Costs nothing, so check it before a batch instead of parsing headers off every call |

### Threats — `threats:read` (free)
| Method + path | What you get |
|---|---|
| `GET /search` | One term across clusters, entities and the dark web, most recent first. `q` (min 2 chars), `limit` ≤ 20 per bucket, `days` window, `include_articles` |
| `GET /threats` | Trending or newest clusters. `time_filter` = `1h` `24h` `7d` `30d`, `keyword`, `sort_by` = `trending` `new`, `limit` ≤ 100, `offset` |
| `GET /threats/{id}` | One cluster (UUID or 8-char short id): title, summary, timeline, scores, keywords, sources |
| `GET /threats/{id}/iocs` | Validated indicators from the cluster's reporting, with type, confidence, reason |
| `GET /threats/{id}/stix` | The cluster as a STIX 2.1 bundle (report, indicators, inferred relationships) |
| `GET /stats/overview` | Corpus counts with 24h deltas |
| `GET /stats/entities/timeline` | Daily mention counts for an entity |

### IOCs — `iocs:read` (free)
| Method + path | What you get |
|---|---|
| `GET /iocs/feed` | SIEM-polling feed. `hours` (default 720), `types`, `confidence` (`confirmed` default), `format` = `txt` `csv` `json`, `enrich`, `threat_score`, `related_entities` |
| `GET /iocs/export` | Bulk export with type / confidence / time-window filters |

### Entities — `entities:read` (free)
| Method + path | What you get |
|---|---|
| `GET /entities/search?q=` | Search actors, malware, tools, companies, countries, industries, CVEs; `entity_type` filter |
| `GET /entities/{type}/{value}` | Entity record: profile, frequency, recent clusters |
| `GET /entities/{type}/{value}/related` | Co-occurring entities, weighted |
| `GET /entities/{type}/{value}/cooccurring-cves` | CVEs reported alongside the entity |
| `GET /entities/trending` | Rising entities by type |

Entity type slugs: `cve` `apt-group` `ransomware-group` `malware` `tool` `campaign` `mitre-attack`
`cwe` `attack-type` `country` `industry` `company` `platform`.

### Vulnerabilities — `vulns:read` (free)
| Method + path | What you get |
|---|---|
| `GET /vulnerabilities` | CVEs with CVSS, EPSS, KEV, exploit availability. `days`, `severity`, `vendor`, `product`, `kev_only`, `has_exploit`, `published_after/before`, `page`, `limit` |
| `GET /vulnerabilities/{cve_id}` | One CVE with related clusters and exploit links |
| `GET /vulnerabilities/stats` | Counts + severity breakdown |

### Ask AI — `ai:read` (Researcher+)
| Method + path | What you get |
|---|---|
| `POST /threats/{id}/ask` | A cited answer about one incident. `action` = `executive_summary` `extract_iocs` `threat_actor` `related_campaigns` `vulnerability` `recommended_actions`, or `custom` with a `question` (≤1,000 chars). Grounded in the cluster's own reporting; inline `[A1]` tags map to `sources`. **25 credits**; identical canned asks are cached for an hour |
| `POST /ask` | One question across every incident, indicator, entity and leak-site record, with citations. `query` (≤500 chars), optional `history` for follow-ups. **50 credits** |

A model timeout or failure refunds the credits. Both are also in the client: `tc.ask(id, "recommended_actions")`, `tc.ask_corpus("…")`.

### Your feeds & alerts — `feeds:*`, `alerts:*` (Researcher+)
`GET /feed`, `GET /feeds`, `GET /feeds/{id}/entities`, `/alert-rules`, `/cve-alerts`, `GET /alerts`,
`POST /alerts/{source}/{trigger_id}/disposition`.

### Dark web — `darkweb:read` (free)
`/darkweb/ransomware/victims` (+ `/facets`), `/darkweb/ransomware/groups`, `/darkweb/ransomware/group/{name}`,
`/darkweb/ransomware/victim/{id}`, `/darkweb/breaches`, `/darkweb/market/{name}`, `/darkweb/keyword-hits`,
`/darkweb/trends`, `/darkweb/stats`.

### Inventory, MSSP, compliance — `inventory:*`, `mssp:*`, `compliance:read` (Business / MSSP)
`POST /inventory`, `GET /inventory/threats`, `GET /inventory/summary`, `/mssp/customers…`,
`GET /mssp/customers/{id}/risk`, `GET /compliance/evidence`.

Full parameter and response schemas: [`openapi/openapi.json`](openapi/openapi.json) or the live
[Swagger UI](https://threatcluster.io/api/public/v1/docs).

---

## Plans, scopes, rate limits

| Plan | Credits | Rate | Scopes on a new key |
|---|---|---|---|
| **Free** | **100 / day** | 30 / min | `threats:read` `iocs:read` `entities:read` `vulns:read` `darkweb:read` |
| Researcher ($19.99) | 1,000 / day | 120 / min | + `feeds:read` `feeds:write` `alerts:read` `alerts:write` `ai:read` |
| Analyst | 1,000 / day | 240 / min | same as Researcher |
| Business / MSSP ($399) | no daily budget | 600 / min, per-key overrides | all scopes (+ `inventory:*`, `mssp:*`, `compliance:read`) |

**What a request costs.** Most calls are 1 credit. `/search` is 5; STIX bundles, the IOC feed and
export, dark-web keyword hits and trends are 3; a fully enriched leak-site victim record is 10;
Ask AI is 25 per incident and 50 across the corpus.
A request that finds nothing costs nothing: empty searches and 404 lookups refund their credits.
Every response carries `X-Request-Cost`, and keys with a daily budget also get `X-RateLimit-Limit`,
`X-RateLimit-Remaining` and `X-RateLimit-Reset`. `GET /me` returns the same numbers as JSON, plus the
prepaid pack balance, at no cost. Past the daily budget, one-off credit packs cover
the overage on any plan ($10 for 2,000, $50 for 12,000, never expire) — see
https://threatcluster.io/pricing#packs.

**What "free" means on the wire.** A free key sees the last **7 days**: `time_filter` is clamped to
`7d`, `hours` to 168, `days` to 7, `weeks` to 1, and fetching an older cluster or victim by id
returns `403 lookback_exceeded`. Rows are the headline, not the dossier — short `ai_summary`,
`threat_score` + `urgency_level`, keywords, source URLs, a 3-event timeline; no `enhanced_summary`,
sub-scores, severity reasoning, article bodies or `recent_events`. Secondary lists (related entities,
co-occurring CVEs, keyword hits, breaches) cap at 10. Every free response carries `"tier": "free"`
and `"lookback_days": 7`. Researcher and above get full records and full history.

* Budgets are per key and reset at 00:00 UTC. Over budget → `429 daily_budget_exceeded` with a `Retry-After` header; per-minute bursts → `429` too. Back off and retry.
* Scopes are fixed when a key is minted. Upgrade, then re-mint to widen.
* Errors are JSON: `401` bad/expired key, `403 insufficient_scope` (tells you the scope you need),
  `403 scope_not_in_tier` when minting above your plan, `404`, `429`.

---

## Examples

| | |
|---|---|
| [`examples/bash/quickstart.sh`](examples/bash/quickstart.sh) | curl walkthrough: threats → cluster → IOCs → STIX → CVEs → entities |
| [`examples/python/tc_api.py`](examples/python/tc_api.py) | ~60-line client: auth header, retries on 429, pagination helper |
| [`examples/python/quickstart.py`](examples/python/quickstart.py) | Morning board: top clusters + confirmed IOCs from the last 24h |
| [`examples/python/siem_lookup_table.py`](examples/python/siem_lookup_table.py) | Write a CSV lookup table of confirmed IOCs for Splunk / Sentinel / Elastic (7-day window on a free key) |
| [`examples/python/kev_watch.py`](examples/python/kev_watch.py) | KEV-listed CVEs with public exploits against your vendor list |
| [`examples/node/quickstart.mjs`](examples/node/quickstart.mjs) | Node 18+ `fetch`, no dependencies |

All examples read the key from `TC_KEY`.

```bash
export TC_KEY=tc_live_…
python3 examples/python/quickstart.py
node examples/node/quickstart.mjs
bash examples/bash/quickstart.sh
```

### Other ways in
* **`tc` CLI** — `pipx install threatcluster-cli`. Same API, keyring auth, JSON output, doubles as an agent tool. https://threatcluster.io/cli
* **Postman / Insomnia** — import `openapi/openapi.json` directly.
* **OpenAPI generators** — `openapi-generator-cli generate -i openapi/openapi.json -g <lang>` gives you a typed client.
* **Integration guides** — Splunk, Sentinel, Elastic, Claude, OpenAI, Cursor, Bash, curl, VS Code, Windows Terminal: https://threatcluster.io/integrations
* **No key at all** — [public feeds](https://threatcluster.io/feeds): RSS, MISP manifest, IOC blocklist (TLP:CLEAR).
  Snapshots live in [Jam0k/Public-Feeds-IOCs](https://github.com/Jam0k/Public-Feeds-IOCs); leak-site listings in
  [Jam0k/Ransomware-Intel](https://github.com/Jam0k/Ransomware-Intel). The site's own JSON endpoints are shaped like a
  free key for anonymous callers, so the API is the way to get full records and history.

---

## OpenAPI snapshot

[`openapi/openapi.json`](openapi/openapi.json) is refreshed daily by
[`.github/workflows/snapshot-openapi.yml`](.github/workflows/snapshot-openapi.yml) from the live schema,
so `git log -p openapi/` is a changelog of the API surface. Breaking changes ship as `/v2`, never on top
of `/v1`; anything being retired is announced ahead of time and keeps working through the notice period.

## Terms
Free and paid plans cover your own tooling and internal use. Embedding in a product you sell, or
redistributing API responses, needs a Business or MSSP agreement — hello@threatcluster.io.
The public feeds are TLP:CLEAR. Code in this repository is GPL-3.0 licensed (see [LICENSE](LICENSE));
that licence covers the code and documentation here only — data returned by the ThreatCluster API is
governed by the plan terms at https://threatcluster.io/pricing.

## Contributing
Examples in another language, a fix to a snippet, a field that's documented wrong — PRs welcome.
See [CONTRIBUTING.md](CONTRIBUTING.md). For API bugs, open an issue with the request (key redacted),
the response and a timestamp.
