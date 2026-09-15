#!/usr/bin/env bash
# vendor-in-the-news.sh: clusters >= 60 mentioning each vendor named on the command line, last 7 days. 1 credit per vendor. Free tier OK.
# usage: ./vendor-in-the-news.sh Microsoft Cisco Fortinet
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
MIN="${MIN_SCORE:-60}"
for vendor in "$@"; do
  tc_get /threats --data-urlencode "keyword=$vendor" --data-urlencode time_filter=7d --data-urlencode sort_by=threat_score --data-urlencode limit=25 \
   | jq -r --arg v "$vendor" --arg site "$SITE" --argjson min "$MIN" '.threats[] | select(.threat_score >= $min) | "\(.threat_score)\t\($v)\t\(.ai_title // .title)\t\($site)/cluster/\(.slug)"'
  sleep 2.1  # 30 requests/min on the free tier
done
