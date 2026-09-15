#!/usr/bin/env bash
# trending-actors.sh: trending APT groups, ransomware groups and malware of the last 7 days. 1 credit. Free tier OK.
# usage: ./trending-actors.sh
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
tc_get /entities/trending --data-urlencode time_filter=7d --data-urlencode limit=10 \
 | jq -r '.trending | to_entries[] | select(.key == "apt_group" or .key == "ransomware_group" or .key == "malware")
          | "== \(.key) ==", (.value[] | "  \(.value)\t\(.frequency) mentions\t\(if .is_new then "NEW" else "\(.change)%" end)")'
