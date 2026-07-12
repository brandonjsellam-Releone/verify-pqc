/*!
 * api-server — the single deployable "TRELYAN API" (reference, DRAFT). Collapses the demo services into ONE hostable
 * process behind the fail-closed demo-gateway (bearer auth + per-key metering), so the whole set is one owner deploy
 * instead of six. The genuinely useful surface for paying customers is POST /verify — HOSTED verification of an
 * Evidence Pack / PQEF bundle / sign-bundle / timestamp / KT proof WITHOUT installing the SDK (an Evidence Pack buyer
 * can confirm their pack over HTTPS). The console dashboard + the mounted omega/mesh/search demos ride along.
 *
 *   GET  /            product console dashboard (from trelyan-console)
 *   POST /verify      hosted verification (pqverify-api.verify) — the paid-adjacent endpoint
 *   /omega/* /mesh/* /search/*   the mounted tested services (via the console)
 *   /api/*            the console's one-shot product demos
 *   GET  /healthz     open (for the hosting platform) — no auth, leaks nothing
 *
 * AUTH + METERING (demo-gateway): reads DEMO_API_TOKENS (comma-separated) + optional DEMO_QUOTA + EXPOSE from env BY
 * NAME. FAIL CLOSED — with EXPOSE=1 and no tokens, every non-health route 503s (an exposed deploy is never left open).
 * The token→plan mapping + persistence is owner config (Stripe/entitlement store); this provides the enforcement point.
 * Owner go-live (L2): set DEMO_API_TOKENS (+ DEMO_QUOTA), EXPOSE=1, deploy (Dockerfile / render.yaml provided).
 * Honest posture: reference/DRAFT over the tested cores; verification attests VALIDITY + reports the signer, never
 * factual accuracy; no "certified"/"quantum-safe" claim. Self-test (socket-free): node api-server.mjs
 */
import * as demoGateway from './demo-gateway.mjs';
import * as pqverifyApi from './pqverify-api.mjs';
import * as trelyanConsole from './trelyan-console.mjs';

/** Composed handler. ASYNC because hosted verify is async. Returns { status, contentType, body }. */
export async function apiHandleRequest(method, path, body) {
  const json = (o, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(o) });
  if (path === '/verify' || path === '/api/verify') {
    if (method !== 'POST') return json({ error: 'POST required', usage: 'POST /verify {type, artifact, trust?}' }, 405);
    let req;
    try { req = typeof body === 'string' ? JSON.parse(body || '{}') : (body || {}); }
    catch { return json({ error: 'invalid JSON body' }, 400); }
    const verdict = await pqverifyApi.verify(req);
    // pqverify-api returns {ok:false,...} for a bad request type — surface that as 400, a real verdict as 200.
    return json(verdict, verdict && verdict.ok === false ? 400 : 200);
  }
  // Everything else → the console (its own dashboard + /api/* demos + mounted /omega /mesh /search).
  return trelyanConsole.handleRequest(method, path, body);
}

/** serve — host the whole thing behind the gateway. Owner entrypoint. */
export async function serve(port = Number(process.env.PORT) || 8080, env = (typeof process !== 'undefined' ? process.env : {})) {
  return demoGateway.serveGuardedAsync(apiHandleRequest, { port, env });
}

/* -------------------------------------------- self-test: node api-server.mjs -------------------------------------------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const j = (r) => JSON.parse(r.body);
  const { makeCtx, guardedHandleAsync } = demoGateway;

  // routing (no auth configured → dev-open, so the composed routes are reachable)
  const devCtx = makeCtx({});
  const dash = await guardedHandleAsync(apiHandleRequest, devCtx, 'GET', '/', '', {});
  ok(dash.status === 200 && /text\/html/.test(dash.contentType), 'GET / → console dashboard (html)');
  const mounted = await guardedHandleAsync(apiHandleRequest, devCtx, 'GET', '/omega/api/manifest', '', {});
  ok(j(mounted).layers && j(mounted).layers.length === 7, 'mounted /omega/api/manifest reachable through the composed server');

  // POST /verify — hosted verification actually runs the tested core
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { bytesToHex } = await import('@noble/hashes/utils.js');
  const { scanFiles } = await import('./pqcbom.mjs');
  const { buildEvidencePack, signEvidencePack } = await import('./pqcbom-report.mjs');
  const signer = ml_dsa87.keygen(new Uint8Array(32).fill(7));
  const pack = signEvidencePack(buildEvidencePack({ scan: scanFiles([{ name: 'a.js', text: 'RSA-2048; MD5;' }]), meta: { generated_ts: 1 } }), signer.secretKey, signer.publicKey); // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
  const good = await guardedHandleAsync(apiHandleRequest, devCtx, 'POST', '/verify', JSON.stringify({ type: 'evidence-pack', artifact: pack, trust: { signer_pub_hex: bytesToHex(signer.publicKey) } }), {});
  ok(good.status === 200 && j(good).ok === true && j(good).verdict.verified === true, 'POST /verify verifies an evidence pack under a pinned key');
  const bad = await guardedHandleAsync(apiHandleRequest, devCtx, 'POST', '/verify', JSON.stringify({ type: 'nonsense' }), {});
  ok(bad.status === 400 && j(bad).ok === false, 'POST /verify unknown type → 400 ok:false');
  const notPost = await guardedHandleAsync(apiHandleRequest, devCtx, 'GET', '/verify', '', {});
  ok(notPost.status === 405, 'GET /verify → 405 (POST required)');

  // fail-closed exposure: EXPOSE=1 + no tokens → non-health 503, health still open
  const closed = makeCtx({ EXPOSE: '1' });
  ok((await guardedHandleAsync(apiHandleRequest, closed, 'GET', '/', '', {})).status === 503, 'EXPOSE=1 + no tokens → 503 fail-closed');
  ok((await guardedHandleAsync(apiHandleRequest, closed, 'GET', '/healthz', '', {})).status === 200, 'health open even under fail-closed');

  // metered auth: a valid key verifies + is metered; a missing key 401s
  const authCtx = makeCtx({ EXPOSE: '1', DEMO_API_TOKENS: 'sk_customer', DEMO_QUOTA: '2' });
  const h = { authorization: 'Bearer sk_customer' };
  ok((await guardedHandleAsync(apiHandleRequest, authCtx, 'GET', '/', '', {})).status === 401, 'exposed + no key → 401');
  const a1 = await guardedHandleAsync(apiHandleRequest, authCtx, 'GET', '/', '', h);
  ok(a1.status === 200 && a1.headers['x-ratelimit-used'] === '1', 'valid key → 200 + metered (used=1)');
  await guardedHandleAsync(apiHandleRequest, authCtx, 'GET', '/', '', h); // used=2
  ok((await guardedHandleAsync(apiHandleRequest, authCtx, 'GET', '/', '', h)).status === 402, 'over DEMO_QUOTA → 402 Payment Required');

  console.log(`\napi-server self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes('--serve')) { const i = process.argv.indexOf('--serve'); serve(Number(process.argv[i + 1]) || undefined); }
  else selfTest();
}
