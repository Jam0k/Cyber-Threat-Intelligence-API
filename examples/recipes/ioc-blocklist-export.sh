#!/usr/bin/env bash
# ioc-blocklist-export.sh: confirmed malicious domains and IPs from the last 7 days, one per line, into two files. 3 credits. Free tier OK.
# usage: ./ioc-blocklist-export.sh [out-dir]
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
OUT="${1:-.}"; mkdir -p "$OUT"
tc_get /iocs/export --data-urlencode types=domain,ip --data-urlencode format=json --data-urlencode hours=168 > "$OUT/.iocs.json"
jq -r '.iocs[] | select(.type=="domain") | .value' "$OUT/.iocs.json" | sort -u > "$OUT/blocklist-domains.txt"
jq -r '.iocs[] | select(.type=="ipv4" or .type=="ipv6") | .value' "$OUT/.iocs.json" | sort -u > "$OUT/blocklist-ips.txt"
echo "domains: $(wc -l < "$OUT/blocklist-domains.txt")  ips: $(wc -l < "$OUT/blocklist-ips.txt")  pending validation: $(jq .pending_count "$OUT/.iocs.json")"
rm -f "$OUT/.iocs.json"
