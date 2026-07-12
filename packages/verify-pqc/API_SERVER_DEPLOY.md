# TRELYAN API server — deploy (owner-gated)

One process, hosting the demo services behind the fail-closed metered gateway. The customer-useful surface is
**POST /verify** — hosted verification of an Evidence Pack / PQEF bundle / sign-bundle / timestamp / KT proof over
HTTPS, no SDK install. This is what an Evidence Pack buyer can hit to confirm their pack; it directly supports the
paid product. The console dashboard + mounted omega/mesh/search demos ride along.

## Endpoints

| Route | Auth | What |
|---|---|---|
| `GET /healthz` | open | liveness for the platform (leaks nothing) |
| `POST /verify` | key | `{type, artifact, trust?}` → verdict (validity + who signed; never factual accuracy) |
| `GET /` | key | product console dashboard |
| `/omega/*` `/mesh/*` `/search/*` | key | the mounted tested demos |
| `/api/*` | key | the console's one-shot product demos |

`type` ∈ evidence-pack, pqef, sign-bundle, tst, tst-restamp, kt-inclusion, … (see `pqverify-api.SUPPORTED`).

## Auth + metering (fail-closed)

Reads from env **by name**: `DEMO_API_TOKENS` (comma-separated bearer keys), optional `DEMO_QUOTA` (included
requests per key; empty = unlimited), `EXPOSE=1` (public deploy). **With `EXPOSE=1` and no tokens, every non-health
route returns 503** — an exposed service is never left open. A valid key is metered; over quota → **402 Payment
Required**. Response headers carry `x-ratelimit-used` / `x-trelyan-key` (a hash id, never the raw token).

The token→customer/plan mapping + billing is owner config (Stripe/entitlement store); this service is only the
enforcement point. Rotate a key by updating `DEMO_API_TOKENS`.

## Deploy

**Docker:**
```
docker build -f Dockerfile.api -t trelyan-api .
docker run -p 8080:8080 -e EXPOSE=1 -e DEMO_API_TOKENS=sk_live_alpha,sk_live_beta -e DEMO_QUOTA=1000 trelyan-api
```
**Render:** use `render.api.yaml` (Blueprint). Set `DEMO_API_TOKENS` in the dashboard (secret; `sync:false`).
**Fly / any container host:** the Dockerfile is self-contained; set the same env.

## Verify it's live (after deploy)

```
curl -s https://<host>/healthz                      # {"status":"ok"} — open
curl -s -o /dev/null -w '%{http_code}' https://<host>/        # 401 (key required) — NOT 200, NOT 503
curl -s https://<host>/verify -H "authorization: Bearer sk_live_alpha" \
     -H "content-type: application/json" -d '{"type":"evidence-pack","artifact":{...}}'
```
`GET /` returning **401** (not 503) confirms auth is configured; **not 200** confirms it isn't open.

## Honest posture

Reference/DRAFT composition over the tested cores. Verification attests cryptographic VALIDITY and reports the
signer — never the factual accuracy of the verified content. No "certified"/"quantum-safe" claims. The pinned
Evidence Pack signer identity is published at throndar.ai/api/v1/evidence-signer.
