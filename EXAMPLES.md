# Request & response examples

Every response below was captured live from the API. Unless marked otherwise, the caller is a **free key** (scopes `threats:read` `iocs:read` `entities:read` `vulns:read` `darkweb:read`, last 7 days, 100 requests/day). Where a long array has been shortened for the page, a note under the block says what was cut — the JSON shown is otherwise verbatim.

Set your key once:

```bash
export TC_KEY=tc_live_…   # Settings → API & Feeds → Generate API key
```

Endpoint reference: [Swagger UI](https://threatcluster.io/api/public/v1/docs) · [`openapi/openapi.json`](openapi/openapi.json)

## Trending threat clusters

`GET /threats` — the feed. `time_filter` = `1h` `24h` `7d` …, `sort_by` = `trending` or `new`, `keyword`, `limit`, `offset`.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/threats?time_filter=24h&limit=2"
```

```json
{
  "threats": [
    {
      "cluster_id": "70c6fdc1-40ff-45f4-81a5-f71898a55c29",
      "title": "Sygnia Reveals New Activity by China",
      "ai_title": "Fire Ant Threat Actor Targets Trusted Infrastructure in 2026",
      "ai_summary": "The China-nexus threat actor known as Fire Ant has evolved its tactics in 2026, transitioning from targeting VMware hypervisors to compromising trusted infrastructure, including Cisco routers, TACACS authentication servers, and Linux management hosts. This shift allows Fire Ant to collect credentials, traffic, and…",
      "timeline": [
        {
          "date": "2025-01-01",
          "event": "Fire Ant first reported",
          "detail": "Initial reports indicated Fire Ant's targeting of VMware hypervisors and virtualization infrastructure.",
          "source": "Sygnia",
          "source_url": "https://www.sygnia.co/blog/fire-ant-evolves-from-hypervisors-to-trusted-infrastructure/"
        }
      ],
      "article_count": 5,
      "threat_score": 77.75,
      "urgency_level": "medium",
      "keywords": [
        "reveals",
        "activity",
        "sygnia",
        "china",
        "incident",
        "response",
        "leader"
      ],
      "sources": [
        "Morningstar",
        "Sg.Finance.Yahoo"
      ],
      "date_range_earliest": "2026-08-30T17:05:25+00:00",
      "date_range_latest": "2026-08-30T18:03:55+00:00",
      "created_at": "2026-08-30T18:48:47.799134+00:00",
      "updated_at": "2026-08-31T16:33:04.191980+00:00",
      "recent_article_count_12h": 3,
      "recent_article_count_6h": 3,
      "articles": [
        {
          "title": "Sygnia Reveals New Activity by China",
          "source": "Sg.Finance.Yahoo",
          "pub_date": "2026-08-30T17:05:25+00:00",
          "url": "https://sg.finance.yahoo.com/news/sygnia-reveals-activity-china-nexus-170000050.html",
          "is_primary": false
        },
        {
          "title": "Sygnia Reveals New Activity by China",
          "source": "Morningstar",
          "pub_date": "2026-08-30T18:03:55+00:00",
          "url": "https://www.morningstar.com/news/business-wire/20260830433829/sygnia-reveals-new-activity-by-china-nexus-threat-actor-fire-ant-targeting-trusted-infrastructure",
          "is_primary": true
        },
        {
          "title": "China",
          "source": "Securityaffairs.Co",
          "pub_date": "2026-08-31T11:10:44+00:00",
          "url": "https://securityaffairs.com/198183/apt/china-linked-fire-ant-hides-inside-trusted-infrastructure.html",
          "is_primary": false
        },
        {
          "title": "Chinese Fire Ant hackers turn Cisco routers into spying platforms",
          "source": "Bleepingcomputer",
          "pub_date": "2026-08-31T14:52:03+00:00",
          "url": "https://www.bleepingcomputer.com/news/security/chinese-fire-ant-hackers-turn-cisco-routers-into-spying-platforms/",
          "is_primary": false
        },
        {
          "title": "Sygnia explains",
          "source": "www.sygnia.co",
          "pub_date": "2026-08-31T15:17:38.698103+00:00",
          "url": "https://www.sygnia.co/blog/fire-ant-evolves-from-hypervisors-to-trusted-infrastructure/",
          "is_primary": false
        }
      ],
      "entities": {
        "apt_group": [
          "Fire Ant",
          "Unc3886"
        ],
        "attack_type": [
          "Data Breach",
          "Malware"
        ],
        "country": [
          "China",
          "Israel",
          "Singapore"
        ]
      },
      "slug": "china-nexus-threat-actor-fire-ant-targets-critical-infrastru-98a55c29",
      "ioc_count": 0,
      "tier": "free"
    }
  ],
  "count": 2,
  "limit": 2,
  "offset": 0,
  "time_filter": "24h",
  "sort_by": "trending",
  "tier": "free",
  "lookback_days": 7
}
```

*Trimmed for the page: 1 of 2 clusters shown; the cluster's timeline (3 events) and entity map (9 types) are shortened. `tier` and `lookback_days` appear on free-key responses only.*

## One cluster in full

`GET /threats/{identifier}` — accepts the UUID, the 8-char short id, or the slug.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/threats/70c6fdc1-40ff-45f4-81a5-f71898a55c29"
```

```json
{
  "cluster_id": "70c6fdc1-40ff-45f4-81a5-f71898a55c29",
  "title": "Sygnia Reveals New Activity by China",
  "ai_title": "Fire Ant Threat Actor Targets Trusted Infrastructure in 2026",
  "ai_summary": "The China-nexus threat actor known as Fire Ant has evolved its tactics in 2026, transitioning from targeting VMware hypervisors to compromising trusted infrastructure, including Cisco routers, TACACS authentication servers, and Linux management hosts. This shift allows Fire Ant to collect credentials, traffic, and…",
  "timeline": [
    {
      "date": "2025-01-01",
      "event": "Fire Ant first reported",
      "detail": "Initial reports indicated Fire Ant's targeting of VMware hypervisors and virtualization infrastructure.",
      "source": "Sygnia",
      "source_url": "https://www.sygnia.co/blog/fire-ant-evolves-from-hypervisors-to-trusted-infrastructure/"
    },
    {
      "date": "2026-08-30",
      "event": "Sygnia releases findings on Fire Ant",
      "detail": "Sygnia reveals ongoing espionage activity by Fire Ant targeting trusted infrastructure, including Cisco routers.",
      "source": "Morningstar",
      "source_url": "https://www.morningstar.com/news/business-wire/20260830433829/sygnia-reveals-new-activity-by-china-nexus-threat-actor-fire-ant-targeting-trusted-infrastructure"
    },
    {
      "date": "2026-08-31",
      "event": "Fire Ant exploits Cisco routers",
      "detail": "Discovery of GRE tunnels on Cisco routers indicates Fire Ant's new tactic of using routers as spying platforms.",
      "source": "Bleepingcomputer",
      "source_url": "https://www.bleepingcomputer.com/news/security/chinese-fire-ant-hackers-turn-cisco-routers-into-spying-platforms/"
    }
  ],
  "article_count": 5,
  "threat_score": 77.75,
  "urgency_level": "medium",
  "keywords": [
    "reveals",
    "activity",
    "sygnia",
    "china",
    "incident",
    "response",
    "leader"
  ],
  "sources": [
    "Morningstar",
    "Sg.Finance.Yahoo"
  ],
  "date_range_earliest": "2026-08-30T17:05:25+00:00",
  "date_range_latest": "2026-08-30T18:03:55+00:00",
  "created_at": "2026-08-30T18:48:47.799134+00:00",
  "updated_at": "2026-08-31T16:33:04.191980+00:00",
  "articles": [
    {
      "title": "Sygnia Reveals New Activity by China",
      "source": "Sg.Finance.Yahoo",
      "pub_date": "2026-08-30T17:05:25+00:00",
      "url": "https://sg.finance.yahoo.com/news/sygnia-reveals-activity-china-nexus-170000050.html",
      "is_primary": false
    },
    {
      "title": "Sygnia Reveals New Activity by China",
      "source": "Morningstar",
      "pub_date": "2026-08-30T18:03:55+00:00",
      "url": "https://www.morningstar.com/news/business-wire/20260830433829/sygnia-reveals-new-activity-by-china-nexus-threat-actor-fire-ant-targeting-trusted-infrastructure",
      "is_primary": true
    }
  ],
  "entities": {
    "campaign": [
      "Fire Ant"
    ],
    "apt_group": [
      "Unc3886"
    ],
    "attack_type": [
      "Data Breach",
      "Malware"
    ],
    "country": [
      "China",
      "Israel",
      "Singapore"
    ]
  },
  "slug": "china-nexus-threat-actor-fire-ant-targets-critical-infrastru-98a55c29",
  "tier": "free"
}
```

*Trimmed for the page: 2 of 5 articles and 4 of 12 entity types shown.*

**What a paid key adds to the same call.** On Researcher and above the response has no `tier`/`lookback_days` markers, the summary and timeline are complete, articles carry full metadata — and these fields appear:

```
actionability_score  ai_prompts  coverage_score  credibility_score  enhanced_summary  entity_metadata  faq  geopolitical_score  insights  ranking_score  recency_score  sentiment_score  severity_indicators  severity_reason  severity_score  summary_generated_at
```

For instance `severity_reason` on this cluster reads: *"Fire Ant's activities represent a high-level threat due to their targeting of critical infrastructure and ongoing espionage."*

## The 7-day window, when you hit it

A free key asking for a cluster older than 7 days gets a `403`, not an empty page — so a script can tell "outside my window" from "does not exist" (`404`):

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/threats/8a04730d-f796-407e-9914-aa479df4301f"
```

```json
{
  "error": "Forbidden",
  "detail": {
    "error": "lookback_exceeded",
    "message": "This threat cluster is older than the 7-day window included with a free API key.",
    "lookback_days": 7,
    "upgrade_url": "/pricing"
  }
}
```

List endpoints never 403 on time: `days`, `hours` and `time_filter` are clamped to the window instead, and the response echoes what was applied (`"clamped"` plus the effective value).

## Validated IOCs for one cluster

`GET /threats/{identifier}/iocs` — only indicators that survived validation (allowlist of benign infrastructure, popularity checks, context re-check), each with a confidence and the reason it was kept.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/threats/32e38748-219f-4340-853f-7c4593fb80f8/iocs"
```

```json
{
  "iocs": [
    {
      "type": "domain",
      "value": "fine-work-team.com",
      "confidence": "high",
      "reason": "Identified as a delivery URL for a malicious script"
    },
    {
      "type": "domain",
      "value": "timelevel12.com",
      "confidence": "high",
      "reason": "Identified as a delivery URL for a malicious script"
    },
    {
      "type": "sha256",
      "value": "7447d0d0c34779d4c519823b39bf6ddc16d2b34a226b82ee69da6f5b4a77ad82",
      "confidence": "high",
      "reason": "SHA-256 hash of a stage-1 ELF loader created by the attacker"
    }
  ],
  "count": 3,
  "cluster_id": "32e38748-219f-4340-853f-7c4593fb80f8"
}
```

## The rolling IOC feed

`GET /iocs/feed` — all validated IOCs across the corpus for the last `hours`. `format=json|txt|csv`; the default `txt` is one indicator per line, ready for a blocklist.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/iocs/feed?hours=24&confidence=high&format=json"
```

```json
{
  "iocs": [
    {
      "type": "domain",
      "value": "fine-work-team.com",
      "confidence": "high",
      "reason": "Identified as a delivery URL for a malicious script"
    },
    {
      "type": "domain",
      "value": "san-sid.com",
      "confidence": "high",
      "reason": "Domain hosting obfuscated PowerShell payload used as RAT dropper"
    },
    {
      "type": "domain",
      "value": "timelevel12.com",
      "confidence": "high",
      "reason": "Identified as a delivery URL for a malicious script"
    },
    {
      "type": "ipv4",
      "value": "103.45.66.18",
      "confidence": "high",
      "reason": "IP address listed with multiple ports, likely used for malicious purposes"
    }
  ],
  "count": 10,
  "confidence_filter": "high",
  "hours": 24
}
```

*Trimmed for the page: 4 of 10 indicators shown.*

## STIX 2.1 bundle

`GET /threats/{identifier}/stix` — the cluster as a STIX bundle: report, threat actors, malware, indicators, relationships. Loads straight into OpenCTI / MISP / anything STIX-aware.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/threats/70c6fdc1-40ff-45f4-81a5-f71898a55c29/stix"
```

```json
{
  "type": "bundle",
  "id": "bundle--c877830d-12b2-48a8-819c-151c4eade846",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
      "created": "2026-08-31T16:47:09.04157Z",
      "modified": "2026-08-31T16:47:09.04157Z",
      "name": "ThreatCluster",
      "description": "Automated threat intelligence aggregation and clustering platform",
      "identity_class": "organization",
      "sectors": [
        "technology"
      ],
      "contact_information": "https://threatcluster.io"
    },
    {
      "type": "threat-actor",
      "spec_version": "2.1",
      "id": "threat-actor--c21bb600-b1bd-54ff-b252-05778b94a4ae",
      "created_by_ref": "identity--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
      "created": "2026-08-31T16:47:09.041844Z",
      "modified": "2026-08-31T16:47:09.041844Z",
      "name": "Unc3886",
      "threat_actor_types": [
        "nation-state"
      ],
      "sophistication": "advanced",
      "resource_level": "government",
      "object_marking_refs": [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
      ]
    }
  ]
}
```

*Trimmed for the page: 2 of 71 STIX objects shown.*

## Entity search

`GET /entities/search` — find the canonical name (and aliases) before asking for a profile.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/entities/search?q=lockbit&limit=3"
```

```json
{
  "entities": [
    {
      "entity_type": "ransomware_group",
      "entity_value": "Lockbit",
      "article_count": 154,
      "cluster_count": 87
    },
    {
      "entity_type": "ransomware_group",
      "entity_value": "Lockbit 3.0",
      "article_count": 7,
      "cluster_count": 7
    },
    {
      "entity_type": "ransomware_group",
      "entity_value": "LockBit3.0",
      "article_count": 2,
      "cluster_count": 2
    }
  ],
  "count": 3,
  "total": 9,
  "limit": 3,
  "offset": 0,
  "query": "lockbit"
}
```

## An entity profile

`GET /entities/{category}/{value}` — category slugs: `cve` `apt-group` `ransomware-group` `malware` `tool` `campaign` `mitre-attack` and more.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/entities/ransomware-group/lockbit"
```

```json
{
  "entity": {
    "entity_type": "ransomware_group",
    "entity_value": "Lockbit",
    "frequency": 138,
    "first_seen": "2025-10-23T10:00:58+00:00",
    "last_seen": "2026-08-27T16:31:53+00:00"
  },
  "clusters": [
    {
      "cluster_id": "60b31b89-a1b3-4fb9-8b8c-46b1c18ccc2a",
      "title": "PaperCut warns of NG, MF flaw exploited in zero",
      "ai_title": "PaperCut NG/MF Vulnerability Under Active Exploitation",
      "ai_summary": "On August 27, 2026, PaperCut issued an urgent advisory regarding a zero-day vulnerability affecting its NG and MF print management software. This flaw allows unauthenticated attackers to execute arbitrary Java code remotely, compromising server configurations. Emergency patches have been released for versions 25 and…",
      "article_count": 41,
      "threat_score": 72.9,
      "date_range_latest": "2026-08-27T16:48:35.471839+00:00",
      "slug": "critical-zero-day-exploitation-of-papercut-ngmf-vulnerabilit-c18ccc2a",
      "tier": "free"
    }
  ],
  "articles": [
    {
      "title": "PaperCut warns of NG, MF flaw exploited in zero",
      "source": "Bleepingcomputer",
      "pub_date": "2026-08-27T16:31:53+00:00",
      "url": "https://www.bleepingcomputer.com/news/security/papercut-warns-of-ng-mf-flaw-exploited-in-zero-day-attacks/"
    },
    {
      "title": "Mexico’s Cybersecurity Plan 2025-2030: Turning Ambition Into Defense",
      "source": "Recordedfuture",
      "pub_date": "2026-08-25T19:22:28+00:00",
      "url": "https://www.recordedfuture.com/fr/blog/mexico-cybersecurity-plan"
    }
  ],
  "co_entities": {
    "attack_type": [
      "Ransomware",
      "Data Breach",
      "Phishing"
    ],
    "ransomware_group": [
      "Qilin",
      "DragonForce",
      "Akira"
    ]
  },
  "aliases": [],
  "clusters_total": 50,
  "articles_total": 50,
  "tier": "free",
  "lookback_days": 7
}
```

*Trimmed for the page: 1 of 2 clusters, 2 of 3 articles, and a few of 109 co-occurring entities shown. `clusters_total`/`articles_total` give the size of the full (unwindowed) history a paid key would see; paid responses also add per-cluster co-occurrence counts.*

## Trending entities

`GET /entities/trending` — who is spiking, per entity type, vs the previous period.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/entities/trending?time_filter=24h&limit=5"
```

```json
{
  "trending": {
    "apt_group": [
      {
        "value": "Kimsuky",
        "frequency": 35,
        "change": 337.5,
        "is_new": false
      },
      {
        "value": "Mustang Panda",
        "frequency": 12,
        "change": 500.0,
        "is_new": false
      },
      {
        "value": "Salt Typhoon",
        "frequency": 11,
        "change": 120.0,
        "is_new": false
      }
    ],
    "attack_type": [
      {
        "value": "Phishing",
        "frequency": 634,
        "change": 10.3,
        "is_new": false
      },
      {
        "value": "Malware",
        "frequency": 669,
        "change": 7.2,
        "is_new": false
      },
      {
        "value": "Data Breach",
        "frequency": 941,
        "change": 1.3,
        "is_new": false
      }
    ]
  },
  "time_filter": "24h",
  "limit_per_type": 5,
  "tier": "free",
  "lookback_days": 7
}
```

*Trimmed for the page: 2 of 24 entity types, 3 rows each.*

## Vulnerabilities

`GET /vulnerabilities` — CVEs with CVSS, EPSS, KEV membership and exploit availability. Filters: `severity`, `kev_only`, `has_exploit`, `vendor`, `product`, `days`.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/vulnerabilities?kev_only=true&days=7&limit=3"
```

```json
{
  "cves": [
    {
      "cve_id": "CVE-2026-82078",
      "description": "An unsafe dynamic class loading vulnerability exists in the database connection utilities of PaperCut MF and PaperCut NG. The application instantiates database driver classes based on configurable driver names without validating against an allowlist of approved drivers. If an attacker can manipulate system configuration parameters, this enables the execution of arbitrary Java bytecode residing on the application classpath under the security context of the PaperCut server process.",
      "in_kev": true,
      "has_exploit": false,
      "epss_score": 0.0046,
      "epss_percentile": 0.3825,
      "published_date": "2026-08-28T16:18:31.240000",
      "last_modified": "2026-08-31T16:19:16.693000"
    }
  ],
  "total": 3,
  "page": 1,
  "limit": 3,
  "pages": 1,
  "days": 7,
  "tier": "free",
  "lookback_days": 7
}
```

*Trimmed for the page: 1 of 3 CVEs shown.*

`GET /vulnerabilities/{cve_id}` for the full record:

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/vulnerabilities/CVE-2026-82078"
```

```json
{
  "cve_id": "CVE-2026-82078",
  "description": "An unsafe dynamic class loading vulnerability exists in the database connection utilities of PaperCut MF and PaperCut NG. The application instantiates database driver classes based on configurable driver names without validating against an allowlist of approved drivers. If an attacker can manipulate system configuration parameters, this enables the execution of arbitrary Java bytecode residing on the application classpath under the security context of the PaperCut server process.",
  "in_kev": true,
  "has_exploit": false,
  "epss_score": 0.0046,
  "epss_percentile": 0.3825,
  "published_date": "2026-08-28T16:18:31.240000",
  "last_modified": "2026-08-31T16:19:16.693000",
  "id": 33282210,
  "cwe_ids": [
    "CWE-470"
  ],
  "reference_urls": [
    {
      "url": "https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/",
      "tags": [],
      "source": "eb41dac7-0af8-4f84-9f6d-0272772514f4"
    },
    {
      "url": "https://github.com/rapid7/metasploit-framework/pull/21842",
      "tags": [],
      "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0"
    },
    {
      "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-82078",
      "tags": [],
      "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0"
    }
  ],
  "kev_added_date": "2026-08-31",
  "kev_due_date": "2026-09-14",
  "ransomware_use": "Unknown",
  "exploit_count": 0,
  "fetched_at": "2026-08-31T16:33:29.832332",
  "epss_updated_at": "2026-08-31T05:00:07.350445",
  "cvss_v4_score": "9.4",
  "cvss_v4_severity": "CRITICAL",
  "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X"
}
```

## Ransomware leak-site victims

`GET /darkweb/ransomware/victims` — leak-site postings, with sector and country attribution. On the free tier since the same data is public on the site. Filters: `group`, `country`, `sector`, `days`.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/darkweb/ransomware/victims?days=7&limit=3"
```

```json
{
  "victims": [
    {
      "id": "1ef7f205ddde8b2b",
      "group": "settra",
      "name": "manhattanloft.co.uk",
      "discovered": "2026-08-31 16:01:46.752407+00:00",
      "country": "GB",
      "sector": "Hospitality",
      "description": "Manhattan Loft Corporation Limited Documents PROLOGUE The Manhattan Loft Corporation Limited (also k...",
      "website": "manhattanloft.co.uk",
      "screenshot_url": "https://images.ransomware.live/victims/5627600fe8c8221f53194b542c5916c1.png",
      "first_party": false,
      "delisted": false,
      "fp_has_note": false,
      "fp_cats": 0
    },
    {
      "id": "0166a20828d6ff82",
      "group": "interlock",
      "name": "Super Systems Inc",
      "discovered": "2026-08-31 15:57:55.854840+00:00",
      "country": "US",
      "sector": "Technology",
      "description": "Super Systems, Inc. develops and manufactures products for the heating industry. However, it is extremely…",
      "website": "https:supersystems.com",
      "screenshot_url": "https://images.ransomware.live/victims/ae2432d619878bb0ade487029a013508.png",
      "first_party": false,
      "delisted": false,
      "fp_has_note": false,
      "fp_cats": 0
    }
  ],
  "count": 3,
  "tier": "free",
  "lookback_days": 7
}
```

*Trimmed for the page: 2 of 3 victims shown, descriptions shortened.*

## One search across everything

`GET /search` — one term across clusters, entities and the dark web in a single call.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/search?q=akira&limit=3"
```

```json
{
  "query": "akira",
  "clusters": [],
  "entities": [
    {
      "entity_type": "ransomware_group",
      "entity_value": "Akira",
      "cluster_count": 83,
      "article_count": 140
    },
    {
      "entity_type": "ransomware_group",
      "entity_value": "Akira Ransomware",
      "cluster_count": 9,
      "article_count": 7
    },
    {
      "entity_type": "campaign",
      "entity_value": "Akira ransomware campaigns",
      "cluster_count": 5,
      "article_count": 3
    }
  ],
  "darkweb": [
    {
      "type": "victim",
      "name": "KFZ-MEISTERBETRIEB JOST GmbH",
      "id": "986032e070dc656e",
      "date": "2026-08-31T13:58:18.334898+00:00",
      "group": "akira",
      "country": "DE",
      "sector": "Transportation"
    },
    {
      "type": "victim",
      "name": "Gale Credit Union",
      "id": "98786520052f8b53",
      "date": "2026-08-31T13:22:14.569981+00:00",
      "group": "akira",
      "country": "US",
      "sector": "Financial Services"
    }
  ],
  "include_articles": false,
  "limit": 3,
  "days": 7,
  "total": 6,
  "tier": "free",
  "lookback_days": 7
}
```

*Trimmed for the page: 2 of 3 dark-web hits shown.*

## Corpus stats

`GET /stats/overview` — how much is behind the key.

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/stats/overview"
```

```json
{
  "total_clusters": 20898,
  "total_articles": 211652,
  "total_entities": 102253,
  "clusters_24h": 46,
  "articles_24h": 690
}
```

## Errors you will actually see

**Scope refusal** — asking for an endpoint your key's scopes don't cover:

```bash
curl -s -H "X-API-Key: $TC_KEY" \
  "https://threatcluster.io/api/public/v1/mssp/customers"
```

```json
{
  "error": "Forbidden",
  "detail": {
    "error": "insufficient_scope",
    "message": "This endpoint requires the 'mssp:read' scope.",
    "required_scope": "mssp:read",
    "granted_scopes": [
      "darkweb:read",
      "entities:read",
      "iocs:read",
      "threats:read",
      "vulns:read"
    ]
  }
}
```

**Rate limit** — `429` with a `Retry-After` header (seconds). Free keys are 30/minute and 100/day; back off and retry — the Python client in [`examples/python/tc_api.py`](examples/python/tc_api.py) does this for you.

**Not found** — `404` for an identifier that doesn't exist (distinct from the window `403` above).

