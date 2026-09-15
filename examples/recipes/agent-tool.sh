#!/usr/bin/env bash
# agent-tool.sh: the raw call behind threatcluster_lookup(query): unified search, compact JSON with citations. 5 credits. Free tier OK.
# usage: ./agent-tool.sh lockbit
set -euo pipefail
: "${THREATCLUSTER_API_KEY:?set THREATCLUSTER_API_KEY (free keys: https://threatcluster.io/about/api)}"
BASE="${THREATCLUSTER_API_BASE:-https://threatcluster.io/api/public/v1}"
SITE="${THREATCLUSTER_SITE:-https://threatcluster.io}"
# A tc_... key goes in X-API-Key; anything else is a bearer (e.g. from `tc login`).
if [[ "$THREATCLUSTER_API_KEY" == tc_* ]]; then AUTH="X-API-Key: $THREATCLUSTER_API_KEY"; else AUTH="Authorization: Bearer $THREATCLUSTER_API_KEY"; fi
# tc_get <path> [curl -G args...]: prints the body; on HTTP >= 400 prints the API error to stderr and fails.
tc_get() { local path=$1; shift; local out code
  out=$(curl -sS -G -H "$AUTH" -w $'\n%{http_code}' "$BASE$path" "$@"); code=${out##*$'\n'}
  if [ "$code" -ge 400 ]; then echo "HTTP $code from $path: ${out%$'\n'*}" >&2; return 1; fi; printf '%s' "${out%$'\n'*}"; }
tc_get /search --data-urlencode "q=${1:?query}" --data-urlencode limit=5 \
 | jq --arg site "$SITE" '{query, window_days: .days,
     clusters: [.clusters[] | {title: .ai_title, threat_score, latest_activity: (.date_range_latest[:10]), url: "\($site)/cluster/\(.slug)"}],
     entities: [.entities[] | {type: .entity_type, value: .entity_value, clusters: .cluster_count}],
     darkweb:  [.darkweb[]  | {type, name, victim_count}],
     citations: [.clusters[] | "\($site)/cluster/\(.slug)"]}'
