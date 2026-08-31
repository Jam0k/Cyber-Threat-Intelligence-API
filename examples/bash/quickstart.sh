#!/usr/bin/env bash
# curl walkthrough of the free-tier surface. Needs: curl, jq.
#   export TC_KEY=tc_live_…
#   bash quickstart.sh
set -euo pipefail
: "${TC_KEY:?set TC_KEY (mint one at https://threatcluster.io/settings#api)}"
B=https://threatcluster.io/api/public/v1
H="X-API-Key: $TC_KEY"

echo "== search?q=lockbit: one call across clusters, entities, dark web =="
curl -sS -H "$H" "$B/search?q=lockbit&limit=5" \
  | jq -r '(.clusters[] | "cluster\t\(.short_id)\t\(.ai_title)"),
           (.entities[] | "entity\t\(.entity_type)\t\(.entity_value)"),
           (.darkweb[]  | "darkweb\t\(.type)\t\(.name)")'

echo; echo "== Trending clusters, last 24h =="
curl -sS -H "$H" "$B/threats?time_filter=24h&limit=5" \
  | jq -r '.threats[] | "\(.threat_score // 0 | tostring | .[0:5])  \(.ai_title // .title)  [\(.cluster_id | gsub("-";"") | .[-8:])]"'

SHORT=$(curl -sS -H "$H" "$B/threats?time_filter=24h&limit=1" | jq -r '.threats[0].cluster_id | gsub("-";"") | .[-8:]')

echo; echo "== Cluster $SHORT =="
curl -sS -H "$H" "$B/threats/$SHORT" | jq '{ai_title, threat_score, urgency_level, article_count, keywords}'

echo; echo "== Its IOCs =="
curl -sS -H "$H" "$B/threats/$SHORT/iocs" | jq -r '.iocs[:10][] | "\(.type)\t\(.confidence)\t\(.value)"'

echo; echo "== As STIX 2.1 (object type counts) =="
curl -sS -H "$H" "$B/threats/$SHORT/stix" | jq -r '.objects | group_by(.type) | map("\(length)\t\(.[0].type)") | .[]'

echo; echo "== KEV-listed CVEs with a public exploit, last 30d =="
curl -sS -H "$H" "$B/vulnerabilities?days=30&kev_only=true&has_exploit=true&limit=10" \
  | jq -r '.cves[] | "\(.cve_id)\tCVSS \(.cvss_v3_score // "-")\tEPSS \(.epss_score // "-")\tKEV \(.in_kev)"'

echo; echo "== Entity search: qilin =="
curl -sS -H "$H" "$B/entities/search?q=qilin&limit=5" | jq -c '.'

echo; echo "== Confirmed IOCs, last 24h, plain text (first 10) =="
curl -sS -H "$H" "$B/iocs/feed?hours=24&confidence=confirmed&format=txt" | head -10
