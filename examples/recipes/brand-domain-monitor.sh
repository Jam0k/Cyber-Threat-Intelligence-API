#!/usr/bin/env bash
# brand-domain-monitor.sh: dark-web keyword hits for the comma-separated keywords in arg 1. 3 credits. Free tier OK.
# usage: ./brand-domain-monitor.sh "acme,acme-corp.example"
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
tc_get /darkweb/keyword-hits --data-urlencode "keywords=${1:?comma-separated keywords}" --data-urlencode per_bucket_limit=25 \
 | jq -r --arg site "$SITE" '"total hits: \(.total)",
     (.hits.victims[]  | "VICTIM  \(.discovered[:10])  \(.group_name)  \(.victim_name)  (\(.country // "--"))  \($site)/dark-web/victim/\(.id)"),
     (.hits.groups[]   | "GROUP   \(.name // .group_name)")'
