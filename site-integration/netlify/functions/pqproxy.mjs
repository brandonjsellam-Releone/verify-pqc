// Same-origin proxy so trelyan.foundation's strict CSP can stay intact.
// The browser fetches /api/pq/idx/... or /api/pq/throndar/... (same origin → connect-src 'self' OK);
// this function fetches the upstream server-side. Path-allowlisted, GET-only (+ throndar POST /api/v1/verify).
// Works whether routed by config.path (below) or by a netlify.toml redirect to /.netlify/functions/pqproxy/:splat.
const HOSTS = { idx: "https://testnet-idx.algonode.cloud", throndar: "https://throndar.ai" };

export default async (req) => {
  const url = new URL(req.url);
  const m = url.pathname.match(/\/(idx|throndar)\/(.*)$/);
  if (!m) return json({ error: "bad route" }, 400);
  const host = m[1], rest = m[2];
  const allowed = host === "idx"
    ? /^v2\/(transactions|applications)\b/.test(rest)
    : /^api\/(transparency|provenance|v1\/verify)\b/.test(rest);
  if (!allowed) return json({ error: "path not allowed" }, 403);
  if (req.method !== "GET" && !(host === "throndar" && req.method === "POST"))
    return json({ error: "method not allowed" }, 405);

  const target = HOSTS[host] + "/" + rest + (url.search || "");
  const init = { method: req.method, headers: { accept: "application/json" } };
  if (req.method === "POST") { init.body = await req.text(); init.headers["content-type"] = "application/json"; }
  let r;
  try { r = await fetch(target, init); } catch { return json({ error: "upstream fetch failed" }, 502); }
  const body = await r.text();
  return new Response(body, {
    status: r.status,
    headers: { "content-type": r.headers.get("content-type") || "application/json", "cache-control": "no-store" },
  });
};

function json(o, status) { return new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } }); }

export const config = { path: "/api/pq/*" };
