/*!
 * demo-gateway — the monetization + safe-exposure wrapper for the runnable TRELYAN demo services (reference, DRAFT).
 *
 * PROBLEM it solves: trelyan-console / omega-server / pqmesh-server / pqsearch-server / pqverify-api / witness-service all
 * expose `handleRequest(method, path, body) -> {status, contentType, body}` and each logs "no auth, do not expose". This
 * wrapper turns any such handler into something that is (a) SAFE to host publicly (fail-closed bearer auth) and (b) SELLABLE
 * (per-key request metering + a 402-over-quota hook — the mechanism to charge for API access). It is composition over the
 * tested handlers; it never touches crypto.
 *
 * TRUST / HONEST POSTURE:
 *   - Bearer tokens are read from env `DEMO_API_TOKENS` (comma-separated) BY NAME — never hardcoded, never logged.
 *   - FAIL CLOSED: if the operator marks this a public deploy (`EXPOSE=1`) but configured NO tokens, every non-health route
 *     returns 503 — an un-authed public service is refused, not silently opened (security-rules #6/#7).
 *   - Metering is an in-memory per-token counter + optional monthly quota (`DEMO_QUOTA`). Over quota -> 402 Payment Required.
 *     This is the SELL-KEYS MECHANISM, not a billing system: the token->paid-plan mapping + persistence is owner config
 *     (Stripe/entitlement store). The gateway provides the enforcement point; the owner provisions the plans + activates keys.
 *   - Health endpoints (`/healthz`,`/livez`) are always open and leak nothing (needed by hosting platforms).
 *   - Timing-safe token comparison (node:crypto timingSafeEqual, length-guarded).
 *
 * Owner go-live (L2, owner-directed): set DEMO_API_TOKENS (+ optional DEMO_QUOTA), EXPOSE=1, then
 *   import { serveGuarded } from './demo-gateway.mjs'; import * as svc from './pqverify-api.mjs' (or any); serveGuarded(svc.handleRequest, { port })
 * The token->customer/plan mapping is wired to the existing payment rail out of band. Claims stay self-attested (never
 * "certified"/"quantum-safe"); this file adds NO cryptographic claim.
 *
 * Self-test (socket-free): node demo-gateway.mjs
 */
import { timingSafeEqual } from 'node:crypto';

const HEALTH_PATHS = new Set(['/healthz', '/livez', '/readyz']);

/** Parse env into an immutable-ish config + fresh in-memory meter state. Reads tokens BY NAME; never stores raw in output. */
export function makeCtx(env = {}) {
  const raw = String(env.DEMO_API_TOKENS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const tokens = Array.from(new Set(raw)); // dedupe; keep as bytes for timing-safe compare
  const quota = Number.isFinite(+env.DEMO_QUOTA) && +env.DEMO_QUOTA > 0 ? Math.floor(+env.DEMO_QUOTA) : Infinity;
  const expose = String(env.EXPOSE || '') === '1' || String(env.NODE_ENV || '') === 'production';
  return {
    tokenBufs: tokens.map((t) => Buffer.from(t, 'utf8')),
    // stable short id per token for metering/response headers — a hash prefix, NOT the token itself
    tokenIds: tokens.map((t) => 'k_' + shortHash(t)),
    quota,
    expose,
    usage: new Map(), // tokenId -> count (in-memory; owner persists via the entitlement store)
  };
}

function shortHash(s) {
  // tiny non-crypto id derived from the token, used only to label a key in metering/headers (never reveals the token)
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(16).padStart(8, '0');
}

function eqTiming(aBuf, bBuf) {
  if (aBuf.length !== bBuf.length) { // timingSafeEqual throws on unequal length — do a constant dummy compare, return false
    try { timingSafeEqual(aBuf, aBuf); } catch { /* noop */ }
    return false;
  }
  try { return timingSafeEqual(aBuf, bBuf); } catch { return false; }
}

/** Extract a bearer token from headers (case-insensitive Authorization: Bearer <t>, or X-Api-Key: <t>). */
export function extractToken(headers = {}) {
  let auth = '', apiKey = '';
  for (const k of Object.keys(headers || {})) {
    const lk = k.toLowerCase();
    if (lk === 'authorization') auth = String(headers[k] || '');
    else if (lk === 'x-api-key') apiKey = String(headers[k] || '');
  }
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  if (m) return m[1].trim();
  if (apiKey.trim()) return apiKey.trim();
  return '';
}

/** authorize: fail-closed bearer check. Returns {ok, tokenId} or {ok:false, status, body}. */
export function authorize(ctx, headers) {
  // No tokens configured:
  if (ctx.tokenBufs.length === 0) {
    if (ctx.expose) {
      return { ok: false, status: 503, body: { error: 'service_unconfigured', notice: 'DEMO_API_TOKENS not set on an exposed deploy — refusing to serve un-authenticated (fail-closed).' } };
    }
    return { ok: true, tokenId: null, devOpen: true }; // local/dev convenience only (EXPOSE unset)
  }
  const presented = extractToken(headers);
  if (!presented) return { ok: false, status: 401, body: { error: 'missing_bearer', notice: 'Authorization: Bearer <api-key> required.' } };
  const pBuf = Buffer.from(presented, 'utf8');
  // Constant-work: check EVERY configured token (no early return on match) so
  // response time never depends on which key matched or how many precede it.
  // eqTiming is itself length-guarded + timing-safe. (Defense-in-depth: the only
  // thing an early return could leak is the index of a key the caller already
  // holds, but a money/auth path should not depend on that being harmless.)
  let matchIdx = -1;
  for (let i = 0; i < ctx.tokenBufs.length; i++) {
    if (eqTiming(pBuf, ctx.tokenBufs[i])) matchIdx = i;
  }
  if (matchIdx >= 0) return { ok: true, tokenId: ctx.tokenIds[matchIdx] };
  return { ok: false, status: 401, body: { error: 'invalid_key', notice: 'API key not recognized.' } };
}

/** meter: increment + enforce quota. Returns {ok, used} or {ok:false, status, body}. */
export function meter(ctx, tokenId) {
  if (tokenId == null) return { ok: true, used: 0 }; // dev-open path is unmetered
  const used = (ctx.usage.get(tokenId) || 0) + 1;
  if (used > ctx.quota) {
    // do NOT count the rejected call beyond the ceiling; report the ceiling
    return { ok: false, status: 402, used: ctx.quota, body: { error: 'quota_exceeded', quota: ctx.quota, notice: 'Included request quota exhausted for this key. Upgrade the plan to continue.' } };
  }
  ctx.usage.set(tokenId, used);
  return { ok: true, used };
}

const SEC_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'cache-control': 'no-store',
};

/**
 * guardedHandle — compose health + auth + metering + security headers around a tested `inner(method,path,body)` handler.
 * Pure + socket-free (testable). Returns {status, contentType, body, headers}.
 */
export function guardedHandle(inner, ctx, method, path, body, headers = {}) {
  // health is always open and leaks nothing
  if (HEALTH_PATHS.has(path)) {
    return { status: 200, contentType: 'application/json', headers: { ...SEC_HEADERS }, body: JSON.stringify({ status: 'ok', authRequired: ctx.tokenBufs.length > 0 || ctx.expose }) };
  }
  const a = authorize(ctx, headers);
  if (!a.ok) return { status: a.status, contentType: 'application/json', headers: { ...SEC_HEADERS }, body: JSON.stringify(a.body) };

  const m = meter(ctx, a.tokenId);
  if (!m.ok) return { status: m.status, contentType: 'application/json', headers: { ...SEC_HEADERS, 'x-ratelimit-used': String(m.used), 'x-ratelimit-limit': String(ctx.quota) }, body: JSON.stringify(m.body) };

  let r;
  try { r = inner(method, path, body); }
  catch (e) {
    // Do NOT echo the inner handler's error to the client — it can carry DB
    // strings, hostnames, file paths, or stack detail. Log server-side; return
    // a generic message (this wrapper is network-exposed).
    console.error('demo-gateway: inner handler threw:', String((e && e.stack) || (e && e.message) || e));
    return { status: 500, contentType: 'application/json', headers: { ...SEC_HEADERS }, body: JSON.stringify({ error: 'handler_error' }) };
  }

  const outHeaders = { ...SEC_HEADERS };
  if (a.tokenId != null) { outHeaders['x-ratelimit-used'] = String(m.used); if (Number.isFinite(ctx.quota)) outHeaders['x-ratelimit-limit'] = String(ctx.quota); outHeaders['x-trelyan-key'] = a.tokenId; }
  else if (a.devOpen) { outHeaders['x-trelyan-auth'] = 'disabled-dev'; } // loud signal that this must not be a public deploy
  return { status: r.status, contentType: r.contentType, headers: outHeaders, body: r.body };
}

/**
 * guardedHandleAsync — same fail-closed auth + metering + headers as guardedHandle,
 * but AWAITS an async inner(method,path,body) (e.g. the hosted verify API, whose
 * verify() is async). Auth + metering are unchanged (sync); only the inner call awaits.
 */
export async function guardedHandleAsync(inner, ctx, method, path, body, headers = {}) {
  if (HEALTH_PATHS.has(path)) {
    return { status: 200, contentType: 'application/json', headers: { ...SEC_HEADERS }, body: JSON.stringify({ status: 'ok', authRequired: ctx.tokenBufs.length > 0 || ctx.expose }) };
  }
  const a = authorize(ctx, headers);
  if (!a.ok) return { status: a.status, contentType: 'application/json', headers: { ...SEC_HEADERS }, body: JSON.stringify(a.body) };
  const m = meter(ctx, a.tokenId);
  if (!m.ok) return { status: m.status, contentType: 'application/json', headers: { ...SEC_HEADERS, 'x-ratelimit-used': String(m.used), 'x-ratelimit-limit': String(ctx.quota) }, body: JSON.stringify(m.body) };

  let r;
  try { r = await inner(method, path, body); }
  catch (e) {
    console.error('demo-gateway(async): inner handler threw:', String((e && e.stack) || (e && e.message) || e));
    return { status: 500, contentType: 'application/json', headers: { ...SEC_HEADERS }, body: JSON.stringify({ error: 'handler_error' }) };
  }
  const outHeaders = { ...SEC_HEADERS };
  if (a.tokenId != null) { outHeaders['x-ratelimit-used'] = String(m.used); if (Number.isFinite(ctx.quota)) outHeaders['x-ratelimit-limit'] = String(ctx.quota); outHeaders['x-trelyan-key'] = a.tokenId; }
  else if (a.devOpen) { outHeaders['x-trelyan-auth'] = 'disabled-dev'; }
  return { status: r.status, contentType: r.contentType, headers: outHeaders, body: r.body };
}

/** serveGuardedAsync — serveGuarded for an async handler (uses guardedHandleAsync). */
export async function serveGuardedAsync(inner, { port = 8080, env = (typeof process !== 'undefined' ? process.env : {}), bodyCap = 8_000_000 } = {}) {
  const http = await import('node:http');
  const ctx = makeCtx(env);
  if (ctx.expose && ctx.tokenBufs.length === 0) console.error('demo-gateway(async): EXPOSE=1 but DEMO_API_TOKENS empty — non-health routes 503 (fail-closed).');
  const srv = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > bodyCap) req.destroy(); });
    req.on('end', async () => {
      const r = await guardedHandleAsync(inner, ctx, req.method, (req.url || '/').split('?')[0], b, req.headers || {});
      res.statusCode = r.status;
      res.setHeader('content-type', r.contentType);
      for (const [k, v] of Object.entries(r.headers || {})) res.setHeader(k, v);
      res.end(r.body);
    });
  });
  srv.listen(port, () => console.log(`demo-gateway(async) on http://localhost:${port} — auth ${ctx.tokenBufs.length ? 'ENABLED' : (ctx.expose ? 'FAIL-CLOSED (no tokens)' : 'dev-open')}, quota ${Number.isFinite(ctx.quota) ? ctx.quota : '∞'}`));
  return srv;
}

/** serveGuarded — owner entrypoint: host any tested handler behind the gateway. Reads env at call time. */
export async function serveGuarded(inner, { port = 8080, env = (typeof process !== 'undefined' ? process.env : {}) } = {}) {
  const http = await import('node:http');
  const ctx = makeCtx(env);
  if (ctx.expose && ctx.tokenBufs.length === 0) {
    console.error('demo-gateway: EXPOSE=1 but DEMO_API_TOKENS empty — every non-health route will 503 (fail-closed). Set tokens to go live.');
  }
  const bodyCap = 5_000_000;
  const srv = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > bodyCap) req.destroy(); });
    req.on('end', () => {
      const r = guardedHandle(inner, ctx, req.method, (req.url || '/').split('?')[0], b, req.headers || {});
      res.statusCode = r.status;
      res.setHeader('content-type', r.contentType);
      for (const [k, v] of Object.entries(r.headers || {})) res.setHeader(k, v);
      res.end(r.body);
    });
  });
  srv.listen(port, () => console.log(`demo-gateway on http://localhost:${port} — auth ${ctx.tokenBufs.length ? 'ENABLED' : (ctx.expose ? 'FAIL-CLOSED (no tokens)' : 'dev-open')}, quota ${Number.isFinite(ctx.quota) ? ctx.quota : '∞'}`));
  return srv;
}

/* ------------------------------------------- self-test: node demo-gateway.mjs ------------------------------------------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const j = (r) => JSON.parse(r.body);
  const inner = (method, path) => ({ status: 200, contentType: 'application/json', body: JSON.stringify({ ran: true, path }) });

  // 1. health open with no token, no config
  let ctx = makeCtx({});
  ok(guardedHandle(inner, ctx, 'GET', '/healthz', '', {}).status === 200, 'health open without auth');

  // 2. EXPOSE=1 + no tokens => non-health route fails closed (503), NOT open
  ctx = makeCtx({ EXPOSE: '1' });
  const closed = guardedHandle(inner, ctx, 'GET', '/', '', {});
  ok(closed.status === 503 && j(closed).error === 'service_unconfigured', 'exposed + no tokens => 503 fail-closed');
  ok(guardedHandle(inner, ctx, 'GET', '/healthz', '', {}).status === 200, 'health still open under fail-closed');

  // 3. tokens set + no auth header => 401
  ctx = makeCtx({ EXPOSE: '1', DEMO_API_TOKENS: 'sk_live_alpha,sk_live_beta' });
  ok(guardedHandle(inner, ctx, 'GET', '/', '', {}).status === 401, 'tokens set + no header => 401');

  // 4. wrong token => 401 (and wrong-length token does not throw)
  ok(guardedHandle(inner, ctx, 'GET', '/', '', { authorization: 'Bearer nope' }).status === 401, 'wrong token => 401 (length-mismatch safe)');
  ok(guardedHandle(inner, ctx, 'GET', '/', '', { authorization: 'Bearer sk_live_alphaX' }).status === 401, 'near-miss token => 401');

  // 5. correct token => inner runs, usage header present, X-Trelyan-Key labels the key (not the token)
  const good = guardedHandle(inner, ctx, 'POST', '/api/x', '{}', { authorization: 'Bearer sk_live_alpha' });
  ok(good.status === 200 && j(good).ran === true, 'valid token => inner handler runs');
  ok(good.headers['x-ratelimit-used'] === '1', 'usage metered (used=1)');
  ok(typeof good.headers['x-trelyan-key'] === 'string' && !good.headers['x-trelyan-key'].includes('sk_live'), 'response labels a key id, never the raw token');

  // 6. quota enforcement => 3rd call on quota=2 => 402 Payment Required
  ctx = makeCtx({ EXPOSE: '1', DEMO_API_TOKENS: 'sk_q', DEMO_QUOTA: '2' });
  const h = { authorization: 'Bearer sk_q' };
  ok(guardedHandle(inner, ctx, 'GET', '/a', '', h).status === 200, 'quota: call 1 ok');
  ok(guardedHandle(inner, ctx, 'GET', '/a', '', h).status === 200, 'quota: call 2 ok');
  const over = guardedHandle(inner, ctx, 'GET', '/a', '', h);
  ok(over.status === 402 && j(over).error === 'quota_exceeded', 'quota: call 3 => 402 Payment Required (sell-keys mechanism)');

  // 7. X-Api-Key header also accepted
  ctx = makeCtx({ EXPOSE: '1', DEMO_API_TOKENS: 'sk_h' });
  ok(guardedHandle(inner, ctx, 'GET', '/', '', { 'x-api-key': 'sk_h' }).status === 200, 'X-Api-Key header accepted');

  // 8. dev-open path (no EXPOSE, no tokens) allowed but LOUDLY flagged
  ctx = makeCtx({});
  const dev = guardedHandle(inner, ctx, 'GET', '/', '', {});
  ok(dev.status === 200 && dev.headers['x-trelyan-auth'] === 'disabled-dev', 'dev-open allowed but flagged disabled-dev');

  // 9. malformed Authorization header does not crash => 401
  ctx = makeCtx({ EXPOSE: '1', DEMO_API_TOKENS: 'sk_ok' });
  ok(guardedHandle(inner, ctx, 'GET', '/', '', { authorization: 'Basic zzz' }).status === 401, 'malformed auth header => 401, no crash');

  // 10. inner handler throw => 500 (contained), security headers present, and the
  //     inner error message is NOT leaked to the client (only a generic error).
  const boom = () => { throw new Error('DB at postgres://prod-secret.internal:5432 failed'); };
  const e = guardedHandle(boom, makeCtx({}), 'GET', '/x', '', {});
  ok(e.status === 500 && e.headers['x-content-type-options'] === 'nosniff', 'inner throw contained => 500 + sec headers');
  ok(!/postgres|internal|5432|failed/.test(e.body), 'inner error detail is NOT leaked to the client');
  ok(j(e).error === 'handler_error' && j(e).message === undefined, 'client gets a generic handler_error, no message');

  // 11. authorize checks ALL tokens (constant work) — a valid key at ANY index authenticates,
  //     and the returned key id corresponds to the matched token (not the first).
  ctx = makeCtx({ EXPOSE: '1', DEMO_API_TOKENS: 'sk_first,sk_middle,sk_last' });
  const last = guardedHandle(inner, ctx, 'GET', '/', '', { authorization: 'Bearer sk_last' });
  ok(last.status === 200, 'a valid key at the LAST index still authenticates (no early-return dependence)');

  // 12. async variant: awaits the inner handler, same auth/metering + error containment.
  const asyncInner = async (method, path) => { await Promise.resolve(); return { status: 200, contentType: 'application/json', body: JSON.stringify({ async: true, path }) }; };
  ctx = makeCtx({ EXPOSE: '1', DEMO_API_TOKENS: 'sk_a' });
  const okA = j(await guardedHandleAsync(asyncInner, ctx, 'POST', '/verify', '{}', { authorization: 'Bearer sk_a' }));
  ok(okA.async === true, 'guardedHandleAsync awaits + returns the async handler result under a valid key');
  ok((await guardedHandleAsync(asyncInner, ctx, 'POST', '/verify', '{}', {})).status === 401, 'guardedHandleAsync enforces auth (no key => 401)');
  const boomAsync = async () => { throw new Error('secret://leak me not'); };
  const eA = await guardedHandleAsync(boomAsync, makeCtx({}), 'GET', '/x', '', {});
  ok(eA.status === 500 && !/leak me not/.test(eA.body), 'guardedHandleAsync contains a thrown async error (no leak)');
  ok((await guardedHandleAsync(asyncInner, makeCtx({}), 'GET', '/healthz', '', {})).status === 200, 'guardedHandleAsync health open');

  console.log(`\ndemo-gateway self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTest();
