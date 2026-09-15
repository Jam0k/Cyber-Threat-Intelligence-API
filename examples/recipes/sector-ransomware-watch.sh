#!/usr/bin/env bash
# sector-ransomware-watch.sh: leak-site victims for a sector (arg 1, optional) in the last 7 days. 1 credit. Free tier OK.
# usage: ./sector-ransomware-watch.sh Healthcare
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
SECTOR="${1:-}"
tc_get /darkweb/ransomware/victims --data-urlencode days=7 --data-urlencode limit=25 --data-urlencode "sector=$SECTOR" \
 | jq -r --arg site "$SITE" '"ThreatCluster ransomware watch: \(.count) victims", (.victims[] | "• \(.discovered[:10])  \(.group)  →  \(.name)  (\(.country // "--"))  \($site)/dark-web/victim/\(.id)")'
