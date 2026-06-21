# Drop-in: CSP-safe post-quantum verifier for trelyan.foundation

These files let the verifiers run under the site's **strict CSP** (`script-src 'self'`,
`connect-src 'self'`) **without changing the CSP**. The browser only talks to same-origin
`/api/pq/*`, which a Netlify function proxies to the algonode indexer and throndar.ai.

## Install (from the FULL site checkout — the one that has `netlify/functions/`)

1. Copy `netlify/functions/pqproxy.mjs` → `website/v2/netlify/functions/pqproxy.mjs`
2. Copy the whole `pq/` folder → `website/v2/pq/`
3. *(Only if your Netlify runtime ignores `config.path`)* add to `netlify.toml` — **do not touch the
   existing `[[headers]]` CSP block:**
   ```toml
   [[redirects]]
     from = "/api/pq/*"
     to = "/.netlify/functions/pqproxy/:splat"
     status = 200
   ```
4. Deploy from the **complete** source so the existing functions aren't dropped:
   `cd website/v2 && netlify deploy --prod`
5. Tools live at `/pq/` — e.g. `https://trelyan.foundation/pq/verify-live.html`,
   `/pq/anchor.html`, `/pq/` (hub).

## Why a proxy and not a CSP change
`connect-src 'self'` deliberately blocks the browser from calling external hosts. Relaxing it
is a security-setting change. The proxy keeps the CSP **fully intact**: the page fetches
`/api/pq/idx/...` (same origin); the function calls the upstream server-side. The proxy is
**path-allowlisted** (`v2/transactions`, `v2/applications`, `api/transparency`,
`api/provenance`, `api/v1/verify`) and **GET-only** except the THRONDAR verify POST.

## What changed vs. the GitHub-Pages copy
- Inline `<script>` → external `pq/js/*.js` (satisfies `script-src 'self'`).
- `js-sha512` CDN → vendored `pq/vendor/sha512.min.js` (satisfies `script-src 'self'`).
- Fetch base `https://testnet-idx.algonode.cloud` → `/api/pq/idx`; `https://throndar.ai` → `/api/pq/throndar`.
