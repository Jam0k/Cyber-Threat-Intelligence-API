# Contributing

**Examples** live under `examples/<language>/`. Keep them dependency-light (stdlib or one well-known
HTTP library), read the key from `TC_KEY`, and make them runnable top-to-bottom. Add a row to the
table in `README.md`.

**API bugs** — open an issue with:
* the request (method, path, query; key redacted)
* the response status + body
* a UTC timestamp
* your plan tier

**Docs mismatches** — if a field in `openapi/openapi.json` doesn't match what you get on the wire,
that's a bug in the API, not the snapshot. Issue please.

**Feature requests** — endpoints, filters, formats. Say what you're building; that shapes priority.

Please don't commit keys. `.gitignore` covers `.env` and `*.key` but not your shell history.
