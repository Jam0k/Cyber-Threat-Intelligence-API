// Node 18+ — built-in fetch, no dependencies.
//   export TC_KEY=tc_live_…
//   node quickstart.mjs
const BASE = "https://threatcluster.io/api/public/v1";
const key = process.env.TC_KEY;
if (!key) { console.error("set TC_KEY (https://threatcluster.io/settings#api)"); process.exit(1); }
const headers = { "X-API-Key": key, "User-Agent": "threatcluster-api-examples/1.0" };

async function get(path, params = {}) {
  const url = new URL(`${BASE}/${path.replace(/^\//, "")}`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(url, { headers });
    if (res.status === 429 && attempt < 3) {
      const wait = Number(res.headers.get("retry-after") ?? 5);
      await new Promise(r => setTimeout(r, wait * 1000));
      continue;
    }
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    return res.headers.get("content-type")?.includes("json") ? res.json() : res.text();
  }
}

const found = await get("search", { q: "lockbit", limit: 5 });
console.log("== search?q=lockbit ==");
for (const c of found.clusters) console.log(`cluster  ${c.short_id}  ${c.ai_title}`);
for (const e of found.entities) console.log(`entity   ${e.entity_type}: ${e.entity_value}`);
for (const d of found.darkweb)  console.log(`darkweb  ${d.type}: ${d.name}`);

const { threats } = await get("threats", { time_filter: "24h", limit: 10 });
console.log("== Trending, last 24h ==");
for (const t of threats) {
  const short = t.cluster_id.replaceAll("-", "").slice(-8);
  console.log(`${(t.threat_score ?? 0).toFixed(1).padStart(5)}  ${t.ai_title ?? t.title}`);
  console.log(`       ${(t.keywords ?? []).join(", ").slice(0, 100)}`);
  console.log(`       ${BASE}/threats/${short}`);
}

const hits = await get("entities/search", { q: "qilin", limit: 5 });
console.log("\n== entities/search?q=qilin ==");
console.log(JSON.stringify(hits, null, 2).slice(0, 800));
