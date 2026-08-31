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
assert len(data.get("paths", {})) > 20, "suspiciously few paths — refusing to overwrite"
with open("openapi/openapi.json", "w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"{len(data['paths'])} paths written")
PY
rm -f "$tmp"
