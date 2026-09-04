#!/usr/bin/env bash
# Pull the live public OpenAPI schema into openapi/openapi.json, pretty-printed
# with sorted keys so diffs are stable.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp)"
curl -sSf --max-time 60 https://threatcluster.io/api/public/v1/openapi.json -o "$tmp"
python3 - "$tmp" <<'PY'
import json, sys
src = sys.argv[1]
data = json.load(open(src))
assert data.get("openapi", "").startswith("3."), "not an OpenAPI 3 document"
# Guard against an empty or broken response without blocking deliberate
# removals: refuse only if the schema shrank by more than 30% since the last
# snapshot (or has fewer than 20 paths outright).
import os
prev = 0
if os.path.exists("openapi/openapi.json"):
    try:
        prev = len(json.load(open("openapi/openapi.json")).get("paths", {}))
    except Exception:
        prev = 0
n = len(data.get("paths", {}))
assert n >= 20, f"only {n} paths — refusing to overwrite"
assert n >= prev * 0.7, f"{n} paths vs {prev} in the last snapshot — refusing to overwrite a >30% drop"
with open("openapi/openapi.json", "w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"{len(data['paths'])} paths written")
PY
rm -f "$tmp"
