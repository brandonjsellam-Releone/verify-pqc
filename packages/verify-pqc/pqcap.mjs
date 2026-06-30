/*!
 * pqcap — verifiable agent capability tokens (post-quantum least-privilege tool authorization). Reference, DRAFT.
 *
 * The authorization primitive for agentic AI (ThrondarAgent / QuantumFlow): a principal issues a hybrid-signed
 * capability that says "agent A may invoke tool T, under these arg constraints, for this audience, until this expiry,
 * at most N times." A tool gateway verifies the capability BEFORE executing — and verifies the presenter actually
 * holds agent A's keys (holder proof-of-possession), so a stolen token alone is useless. pqauditlog records what an
 * agent DID; pqcap authorizes what it is ALLOWED to do, first.
 *
 * FALSIFIABLE PROPERTIES (given the token + the PINNED issuer keys): the issuer authorized THIS exact tool + caveats
 * for THIS agent (forging needs a classical AND a lattice [AND hash-based] break); the actual request is checked
 * against the signed caveats (over-broad calls are rejected); the token is unexpired, audience-bound, holder-bound
 * (PoP), and consumable at most max_uses times (with a durable ledger). Unaudited reference implementation.
 *
 * Self-test: node pqcap.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';

const CAP_CTX = utf8ToBytes('trelyan-agent-capability-v1');      // signing domain (Ed25519 + ML-DSA legs)
const CAP_SLH_CTX = utf8ToBytes('trelyan-agent-capability-slh-v1'); // distinct domain for the optional SLH leg
const CAP_POP_CTX = utf8ToBytes('trelyan-agent-cap-pop-v1');     // distinct domain for the holder proof-of-possession

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
// id binds the COMPLETE hybrid key set (full 256-bit). Used for both the issuer (principal) and the agent (holder).
function makeId(prefix, keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('keys must be { ed, mldsa[, slh] }');
  return prefix + bytesToHex(sha256(concatBytes(utf8ToBytes(prefix), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}
export const makePrincipalId = (keys) => makeId('cap:trelyan:principal:v1:', keys);
export const makeAgentId = (keys) => makeId('cap:trelyan:agent:v1:', keys);

/* ---------- caveats: the least-privilege constraints checked against the actual tool call ---------- */
// Supported caveat families (all optional; an empty caveat set means "the tool, unconstrained"):
//   arg_equals {name: value} · arg_prefix {name: prefix} · arg_max {name: number} · arg_in {name: [values]}
//   deny_unlisted true — reject ANY request arg not named in a caveat / args_allowed (closes ambient-authority
//     privilege escalation: an agent smuggling an extra arg the tool honors). · args_allowed [names] — explicit
//     allowed-arg whitelist (implies deny_unlisted). arg_max requires a real finite NUMBER (no string/array coercion).
function normCaveats(c) {
  const out = {};
  const obj = (x) => (x && typeof x === 'object' && !Array.isArray(x) ? x : {});
  for (const k of ['arg_equals', 'arg_prefix', 'arg_max', 'arg_in']) {
    const m = obj(c && c[k]); const keys = Object.keys(m).sort();
    if (keys.length) { out[k] = {}; for (const kk of keys) out[k][kk] = m[kk]; }
  }
  if (c && c.deny_unlisted === true) out.deny_unlisted = true;
  if (c && Array.isArray(c.args_allowed)) out.args_allowed = [...new Set(c.args_allowed.map(String))].sort();
  return out;
}
// Evaluate the signed caveats against a concrete request's args. TOTAL: any failure → {ok:false, reason}.
export function evalCaveats(caveats, args) {
  try {
    const c = caveats || {};
    const isPlainObj = args != null && typeof args === 'object' && !Array.isArray(args);
    const hasConstraints = !!(c.arg_equals || c.arg_prefix || c.arg_max || c.arg_in || c.deny_unlisted === true || Array.isArray(c.args_allowed));
    // FAIL-CLOSED on non-plain-object args under ANY constraint: the tool receives the ORIGINAL args, so silently
    // coercing an array/primitive to {} would hide it from the caveat + deny_unlisted checks (DeepSeek 1 Jul). A token
    // with NO constraints is "tool unconstrained" by design, so any args shape is permitted there.
    if (hasConstraints && args != null && !isPlainObj) return { ok: false, reason: 'non-object args cannot be constrained (array/primitive under caveats)' };
    const a = isPlainObj ? args : {};
    if (c.arg_equals) for (const [k, v] of Object.entries(c.arg_equals)) if (canon(a[k]) !== canon(v)) return { ok: false, reason: `arg_equals ${k}` };
    if (c.arg_prefix) for (const [k, p] of Object.entries(c.arg_prefix)) { if (typeof a[k] !== 'string' || !a[k].startsWith(String(p))) return { ok: false, reason: `arg_prefix ${k}` }; }
    // arg_max: STRICT number — reject strings/arrays/objects (Number() coercion of [50] / "50" / {valueOf} is a bypass)
    if (c.arg_max) for (const [k, mx] of Object.entries(c.arg_max)) { if (typeof a[k] !== 'number' || !Number.isFinite(a[k]) || a[k] > Number(mx)) return { ok: false, reason: `arg_max ${k}` }; }
    if (c.arg_in) for (const [k, arr] of Object.entries(c.arg_in)) { const allowed = Array.isArray(arr) ? arr.map(canon) : []; if (!allowed.includes(canon(a[k]))) return { ok: false, reason: `arg_in ${k}` }; }
    // deny-unlisted-args (least-privilege strict mode): NO request arg may exist beyond the named/allowed set
    if (c.deny_unlisted === true || Array.isArray(c.args_allowed)) {
      const allowed = new Set([...(c.args_allowed || []),
        ...Object.keys(c.arg_equals || {}), ...Object.keys(c.arg_prefix || {}), ...Object.keys(c.arg_max || {}), ...Object.keys(c.arg_in || {})]);
      for (const k of Object.keys(a)) if (!allowed.has(k)) return { ok: false, reason: `unlisted arg ${k}` };
    }
    return { ok: true };
  } catch { return { ok: false, reason: 'caveat eval error' }; }
}

function capCore(m) {
  return { v: '1', issuer: m.issuer, agent: m.agent, tool: m.tool, caveats: m.caveats,
    scope: m.scope ?? null, nonce: m.nonce, issued_at: m.issued_at ?? null, expires_at: m.expires_at ?? null,
    max_uses: m.max_uses ?? null, audience: m.audience ?? null };
}

// issuerKeys = principal { ed, mldsa[, slh] }. agent = the holder's keys/pubkeys { ed, mldsa[, slh] } (bound by id +
// embedded for PoP). tool = string ('*' = any). caveats = see normCaveats. max_uses = positive int or null (unbounded).
export function issueCapability({ issuerKeys, agent, tool, caveats, scope, nonce, issuedAt, expiresAt, maxUses, audience }) {
  if (!issuerKeys || !issuerKeys.ed || !issuerKeys.mldsa) throw new Error('issuerKeys must be { ed, mldsa[, slh] }');
  if (!agent || !agent.ed || !agent.mldsa) throw new Error('agent must be the holder keys/pubkeys { ed, mldsa[, slh] }');
  if (!tool || typeof tool !== 'string') throw new Error('tool (string) is required');
  if (maxUses != null && (!Number.isInteger(maxUses) || maxUses < 1)) throw new Error('maxUses must be a positive integer or null');
  const core = capCore({ issuer: makePrincipalId(issuerKeys), agent: makeAgentId(agent), tool: String(tool),
    caveats: normCaveats(caveats), scope: scope ?? null, nonce: String(nonce ?? bytesToHex(randomBytes(16))),
    issued_at: issuedAt ?? null, expires_at: expiresAt ?? null, max_uses: maxUses ?? null, audience: audience ?? null });
  const coreBytes = utf8ToBytes(canon(core));
  const token = { ...core,
    agent_pub: { ed: bytesToHex(_pub(agent.ed)), mldsa: bytesToHex(_pub(agent.mldsa)) },
    issuer_pub: { ed: bytesToHex(_pub(issuerKeys.ed)), mldsa: bytesToHex(_pub(issuerKeys.mldsa)) },
    ed_sig: bytesToHex(ed25519.sign(concatBytes(CAP_CTX, coreBytes), issuerKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, issuerKeys.mldsa.secretKey, { context: CAP_CTX })) };
  if (agent.slh) token.agent_pub.slh = bytesToHex(_pub(agent.slh));
  if (issuerKeys.slh) { token.issuer_pub.slh = bytesToHex(_pub(issuerKeys.slh)); token.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, issuerKeys.slh.secretKey, { context: CAP_SLH_CTX })); }
  return token;
}

// the holder (agent) proves possession of its keys over a fresh, request-bound challenge. Presented at use time.
export function proveHolder(agentKeys, challenge) {
  const msg = concatBytes(CAP_POP_CTX, utf8ToBytes(String(challenge)));
  const p = { challenge: String(challenge), ed_sig: bytesToHex(ed25519.sign(msg, agentKeys.ed.secretKey)), mldsa_sig: bytesToHex(ml_dsa87.sign(msg, agentKeys.mldsa.secretKey, { context: CAP_POP_CTX })) };
  if (agentKeys.slh) p.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(msg, agentKeys.slh.secretKey, { context: CAP_POP_CTX }));
  return p;
}

// TOTAL / fail-closed. trustedIssuer = pinned principal { ed, mldsa[, slh] }.
// opts: request {tool, args} (checked vs caveats), now (expiry), audience (must match), challenge + holderProof
// (require holder PoP — STRONGLY recommended; bind a FRESH single-use request-specific challenge, else PoP is
// replayable), requireHolderProof, useLedger ({has,add} over the token nonce for max_uses), requireSlhHolder,
// allowUnmeteredCheck (permit a NON-consuming validity check of a max_uses token without a ledger).
export function verifyCapability(token, trustedIssuer, opts = {}) {
  try {
    if (!token || typeof token !== 'object' || !trustedIssuer || !trustedIssuer.ed || !trustedIssuer.mldsa) return { verified: false };
    if (token.issuer !== makePrincipalId(trustedIssuer)) return { verified: false, reason: 'issuer id != pinned issuer keys' };
    if (token.max_uses != null && (!Number.isInteger(token.max_uses) || token.max_uses < 1)) return { verified: false, reason: 'bad max_uses' };
    const coreBytes = utf8ToBytes(canon(capCore(token)));
    // issuer hybrid signature over the core
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(token.ed_sig), concatBytes(CAP_CTX, coreBytes), trustedIssuer.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(token.mldsa_sig), coreBytes, trustedIssuer.mldsa, { context: CAP_CTX }); } catch { pqOk = false; }
    if (trustedIssuer.slh) { try { slhOk = !!(token.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(token.slh_sig), coreBytes, trustedIssuer.slh, { context: CAP_SLH_CTX })); } catch { slhOk = false; } }
    if (!edOk || !pqOk || !slhOk) return { verified: false, reason: 'issuer hybrid signature invalid (or required leg missing)' };
    // the embedded agent_pub must match the agent id the issuer signed (no holder substitution)
    let agentPub; try { agentPub = { ed: hexToBytes(token.agent_pub.ed), mldsa: hexToBytes(token.agent_pub.mldsa), ...(token.agent_pub.slh ? { slh: hexToBytes(token.agent_pub.slh) } : {}) }; } catch { return { verified: false, reason: 'bad agent_pub' }; }
    if (makeAgentId(agentPub) !== token.agent) return { verified: false, reason: 'agent_pub does not match signed agent id' };
    // expiry / not-yet-valid
    if (token.expires_at != null && opts.now == null && opts.allowNoExpiryClock !== true) return { verified: false, reason: 'expires_at declared but no clock (opts.now) supplied — cannot verify freshness' };
    if (token.expires_at != null && opts.now != null && Number(opts.now) >= Number(token.expires_at)) return { verified: false, reason: 'expired' };
    if (token.issued_at != null && opts.now != null && Number(opts.now) < Number(token.issued_at)) return { verified: false, reason: 'not yet valid' };
    // audience binding
    if (token.audience != null && opts.audience !== token.audience) return { verified: false, reason: 'audience mismatch' };
    // tool + caveat enforcement against the actual request
    if (opts.request !== undefined) {
      const req = opts.request || {};
      if (token.tool !== '*' && req.tool !== token.tool) return { verified: false, reason: 'tool not authorized by this capability' };
      const cav = evalCaveats(token.caveats, req.args);
      if (!cav.ok) return { verified: false, reason: 'caveat: ' + cav.reason };
    }
    // holder proof-of-possession (bind the bearer to the agent keys — a stolen token alone is useless)
    if (opts.requireHolderProof) {
      const pf = opts.holderProof;
      if (!pf || opts.challenge == null || pf.challenge !== String(opts.challenge)) return { verified: false, reason: 'holder proof: missing / wrong challenge' };
      const msg = concatBytes(CAP_POP_CTX, utf8ToBytes(String(opts.challenge)));
      let he = false, hp = false, hs = true;
      try { he = ed25519.verify(hexToBytes(pf.ed_sig), msg, agentPub.ed); } catch { he = false; }
      try { hp = ml_dsa87.verify(hexToBytes(pf.mldsa_sig), msg, agentPub.mldsa, { context: CAP_POP_CTX }); } catch { hp = false; }
      if (opts.requireSlhHolder) { try { hs = !!(agentPub.slh && pf.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(pf.slh_sig), msg, agentPub.slh, { context: CAP_POP_CTX })); } catch { hs = false; } }
      if (!he || !hp || !hs) return { verified: false, reason: 'holder proof invalid' };
    }
    // replay / max_uses — FAIL-CLOSED: a max_uses token requires a durable, atomic ledger ({has(nonce)->count, add}).
    // Without one the limit is unenforceable, so reject — unless the caller explicitly asks for a non-consuming check.
    if (token.max_uses != null) {
      if (opts.useLedger && typeof opts.useLedger.has === 'function') {
        const used = Number(opts.useLedger.has(token.nonce) || 0);
        if (used >= token.max_uses) return { verified: false, reason: 'max_uses exhausted' };
      } else if (!opts.allowUnmeteredCheck) {
        return { verified: false, reason: 'max_uses set but no useLedger (pass a durable ledger, or allowUnmeteredCheck for a non-consuming check)' };
      }
    }
    return { verified: true, issuer: token.issuer, agent: token.agent, tool: token.tool, scope: token.scope };
  } catch { return { verified: false }; }
}

// in-memory use counter. PRODUCTION needs a DURABLE atomic store; an in-process counter resets on restart.
export function makeUseLedger() {
  const m = new Map();
  // `consume(nonce, maxUses)` is an ATOMIC check-and-increment (returns false if the count already reached maxUses) —
  // it closes the has()/add() TOCTOU window (DeepSeek 1 Jul). Single-threaded JS makes the read+write uninterruptible;
  // a DISTRIBUTED ledger MUST back this with an atomic primitive (a conditional increment / Lua / CAS).
  return { has: (n) => m.get(String(n)) || 0, add: (n) => m.set(String(n), (m.get(String(n)) || 0) + 1),
    consume: (n, maxUses) => { const k = String(n); const used = m.get(k) || 0; if (maxUses != null && used >= Number(maxUses)) return false; m.set(k, used + 1); return true; },
    get size() { return m.size; } };
}
// correct-usage path: verify + consume one use exactly once ON SUCCESS only. Prefers the ledger's ATOMIC consume() to
// eliminate the check-then-increment race; falls back to has()-during-verify + add()-on-success (safe in synchronous JS).
export function verifyAndConsume(token, trustedIssuer, ledger, opts = {}) {
  try { // TOTAL: reading token.max_uses to choose the path must not throw on adversarial input (e.g. a throwing getter)
    if (token && token.max_uses != null && ledger && typeof ledger.consume === 'function') {
      const r = verifyCapability(token, trustedIssuer, { ...opts, allowUnmeteredCheck: true }); // all NON-max_uses checks first
      if (!r.verified) return r;
      if (!ledger.consume(token.nonce, token.max_uses)) return { ...r, verified: false, reason: 'max_uses exhausted (atomic consume)' };
      return r;
    }
    const r = verifyCapability(token, trustedIssuer, { ...opts, useLedger: ledger });
    if (r.verified && token && token.max_uses != null && ledger && typeof ledger.add === 'function') ledger.add(token.nonce);
    return r;
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqcap.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const principal = { ed: ed(1), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)) };
  const tIssuer = { ed: principal.ed.publicKey, mldsa: principal.mldsa.publicKey };
  const agent = { ed: ed(3), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(4)) };
  const agentPubOnly = { ed: agent.ed.publicKey, mldsa: agent.mldsa.publicKey };
  const attacker = { ed: ed(9), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)) };

  const tok = issueCapability({ issuerKeys: principal, agent: agentPubOnly, tool: 'DatabaseQuery',
    caveats: { arg_prefix: { table: 'public.' }, arg_max: { limit: 100 }, arg_in: { op: ['select'] } },
    scope: 'read-only', expiresAt: 1000, audience: 'orch-1', nonce: 'cap-1' });
  ok(tok.agent === makeAgentId(agentPubOnly) && tok.issuer === makePrincipalId(principal), 'token binds issuer + agent ids');

  // happy path: an in-bounds request verifies
  const goodReq = { tool: 'DatabaseQuery', args: { table: 'public.users', op: 'select', limit: 50 } };
  ok(verifyCapability(tok, tIssuer, { request: goodReq, now: 1, audience: 'orch-1' }).verified === true, 'in-bounds request verifies');
  // wrong issuer
  ok(verifyCapability(tok, { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }, { request: goodReq, now: 1, audience: 'orch-1' }).verified === false, 'wrong pinned issuer -> FAILS');
  // caveat violations
  ok(verifyCapability(tok, tIssuer, { request: { tool: 'DatabaseQuery', args: { table: 'secret.creds', op: 'select', limit: 10 } }, now: 1, audience: 'orch-1' }).verified === false, 'arg_prefix violation (table outside public.) -> FAILS');
  ok(verifyCapability(tok, tIssuer, { request: { tool: 'DatabaseQuery', args: { table: 'public.users', op: 'select', limit: 9999 } }, now: 1, audience: 'orch-1' }).verified === false, 'arg_max violation (limit>100) -> FAILS');
  ok(verifyCapability(tok, tIssuer, { request: { tool: 'DatabaseQuery', args: { table: 'public.users', op: 'delete', limit: 10 } }, now: 1, audience: 'orch-1' }).verified === false, 'arg_in violation (op=delete not allowed) -> FAILS');
  // wrong tool entirely (confused-deputy)
  ok(verifyCapability(tok, tIssuer, { request: { tool: 'CodeExecutor', args: {} }, now: 1, audience: 'orch-1' }).verified === false, 'capability for DatabaseQuery cannot authorize CodeExecutor -> FAILS');
  // APEX-TEAM FIX: deny-unlisted-args (ambient-authority escalation) — the unanimous #1 finding
  const strict = issueCapability({ issuerKeys: principal, agent: agentPubOnly, tool: 'execCommand', caveats: { arg_equals: { cmd: 'ls' }, deny_unlisted: true }, nonce: 'strict-1' });
  ok(verifyCapability(strict, tIssuer, { request: { tool: 'execCommand', args: { cmd: 'ls' } } }).verified === true, 'deny_unlisted: only the named arg present -> verifies');
  ok(verifyCapability(strict, tIssuer, { request: { tool: 'execCommand', args: { cmd: 'ls', sudo: true, raw: 'rm -rf /' } } }).verified === false, 'deny_unlisted: an EXTRA unconstrained arg (sudo/raw) -> REJECTED (no ambient-authority escalation)');
  // APEX-TEAM FIX: arg_max strict number (no Number() coercion of arrays / numeric strings / valueOf objects)
  ok(verifyCapability(tok, tIssuer, { request: { tool: 'DatabaseQuery', args: { table: 'public.users', op: 'select', limit: [50] } }, now: 1, audience: 'orch-1' }).verified === false, 'arg_max rejects a non-number (array would Number()-coerce, but the strict type check blocks it)');
  ok(verifyCapability(tok, tIssuer, { request: { tool: 'DatabaseQuery', args: { table: 'public.users', op: 'select', limit: '50' } }, now: 1, audience: 'orch-1' }).verified === false, 'arg_max rejects a numeric STRING (strict number type required)');
  // expiry + audience
  ok(verifyCapability(tok, tIssuer, { request: goodReq, now: 1000, audience: 'orch-1' }).verified === false, 'expired (now>=expires_at) -> FAILS');
  ok(verifyCapability(tok, tIssuer, { request: goodReq, now: 1, audience: 'orch-2' }).verified === false, 'audience mismatch -> FAILS');

  // tamper: widen a caveat without re-sign
  const t2 = JSON.parse(JSON.stringify(tok)); t2.caveats.arg_max.limit = 1000000;
  ok(verifyCapability(t2, tIssuer, { request: { tool: 'DatabaseQuery', args: { table: 'public.users', op: 'select', limit: 999 } }, now: 1, audience: 'orch-1' }).verified === false, 'tampered caveat (re-sign-free) -> issuer sig FAILS');
  // holder substitution: swap agent_pub to the attacker's keys
  const t3 = JSON.parse(JSON.stringify(tok)); t3.agent_pub.ed = bytesToHex(attacker.ed.publicKey); t3.agent_pub.mldsa = bytesToHex(attacker.mldsa.publicKey);
  ok(verifyCapability(t3, tIssuer, { request: goodReq, now: 1, audience: 'orch-1' }).verified === false, 'agent_pub substitution -> agent id mismatch -> FAILS');

  // holder proof-of-possession
  const chal = 'req-nonce-xyz';
  ok(verifyCapability(tok, tIssuer, { request: goodReq, now: 1, audience: 'orch-1', requireHolderProof: true, challenge: chal, holderProof: proveHolder(agent, chal) }).verified === true, 'valid holder PoP over the challenge -> verifies');
  ok(verifyCapability(tok, tIssuer, { request: goodReq, now: 1, audience: 'orch-1', requireHolderProof: true, challenge: chal, holderProof: proveHolder(attacker, chal) }).verified === false, 'holder PoP by the WRONG keys (stolen token) -> FAILS');
  ok(verifyCapability(tok, tIssuer, { request: goodReq, now: 1, audience: 'orch-1', requireHolderProof: true, challenge: 'different', holderProof: proveHolder(agent, chal) }).verified === false, 'holder PoP replay with a different challenge -> FAILS');
  ok(verifyCapability(tok, tIssuer, { request: goodReq, now: 1, audience: 'orch-1', requireHolderProof: true }).verified === false, 'requireHolderProof with no proof -> FAILS');

  // max_uses via ledger (commit-on-success) — a token that declares a use limit
  const tokU = issueCapability({ issuerKeys: principal, agent: agentPubOnly, tool: 'DatabaseQuery', caveats: { arg_in: { op: ['select'] } }, expiresAt: 1000, maxUses: 2, audience: 'orch-1', nonce: 'cap-u' });
  const useReq = { tool: 'DatabaseQuery', args: { op: 'select' } };
  ok(verifyCapability(tokU, tIssuer, { request: useReq, now: 1, audience: 'orch-1' }).verified === false, 'APEX-TEAM FIX: max_uses set but NO ledger -> fail-closed (limit unenforceable)');
  ok(verifyCapability(tokU, tIssuer, { request: useReq, now: 1, audience: 'orch-1', allowUnmeteredCheck: true }).verified === true, 'allowUnmeteredCheck -> explicit non-consuming validity check passes');
  const led = makeUseLedger();
  ok(verifyAndConsume(tokU, tIssuer, led, { request: useReq, now: 1, audience: 'orch-1' }).verified === true, 'use 1/2 verifies + consumes');
  ok(verifyAndConsume(tokU, tIssuer, led, { request: useReq, now: 1, audience: 'orch-1' }).verified === true, 'use 2/2 verifies + consumes');
  ok(verifyAndConsume(tokU, tIssuer, led, { request: useReq, now: 1, audience: 'orch-1' }).verified === false, 'use 3 -> max_uses exhausted -> FAILS');
  const led2 = makeUseLedger(); verifyAndConsume(tokU, { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }, led2, { request: useReq, now: 1, audience: 'orch-1' });
  ok(led2.size === 0, 'commit-on-success: a FAILED verify does NOT consume a use');

  // DeepSeek 1 Jul hardenings:
  // (1) non-object args under constraints fail closed — an array would coerce to {} and slip deny_unlisted
  ok(verifyCapability(strict, tIssuer, { request: { tool: 'execCommand', args: ['ls', '--sudo'] } }).verified === false, 'non-object (array) args under caveats → REJECTED (no coercion bypass of deny_unlisted)');
  // (2) a token declaring expires_at must not verify without a clock
  ok(verifyCapability(tok, tIssuer, { request: goodReq, audience: 'orch-1' }).verified === false, 'declared expires_at + no opts.now → refused (no silent expiry bypass)');
  ok(verifyCapability(tok, tIssuer, { request: goodReq, audience: 'orch-1', allowNoExpiryClock: true }).verified === true, 'explicit allowNoExpiryClock → permits a deliberately time-less check');
  // (3) atomic consume (check-and-increment) closes the has/add TOCTOU
  const ul = makeUseLedger();
  ok(ul.consume('k', 2) === true && ul.consume('k', 2) === true && ul.consume('k', 2) === false, 'atomic consume: increments to max_uses then refuses (check-and-increment)');

  // unconstrained '*' tool + empty caveats
  const wild = issueCapability({ issuerKeys: principal, agent: agentPubOnly, tool: '*', caveats: {}, nonce: 'w-1' });
  ok(verifyCapability(wild, tIssuer, { request: { tool: 'AnyTool', args: { x: 1 } } }).verified === true, 'wildcard tool + no caveats -> any request verifies');

  // 3-leg hash-based hardening
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5));
  const principal3 = { ed: principal.ed, mldsa: principal.mldsa, slh };
  const tIssuer3 = { ed: tIssuer.ed, mldsa: tIssuer.mldsa, slh: slh.publicKey };
  const tok3 = issueCapability({ issuerKeys: principal3, agent: agentPubOnly, tool: 'X', caveats: {}, nonce: 'c3' });
  ok(typeof tok3.slh_sig === 'string' && verifyCapability(tok3, tIssuer3, { request: { tool: 'X', args: {} } }).verified === true, '3-leg issuer signature verifies');
  const tok3s = JSON.parse(JSON.stringify(tok3)); tok3s.slh_sig = '00';
  ok(verifyCapability(tok3s, tIssuer3, { request: { tool: 'X', args: {} } }).verified === false, 'stripped SLH leg fails when issuer.slh pinned (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { tool: 'x' }, { ...tok, ed_sig: 'zz' }]) { try { if (verifyCapability(bad, tIssuer, { request: { tool: 'x', args: {} } }).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed tokens -> verified:false, never throws');

  console.log('pqcap self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqcap\.mjs$/.test(process.argv[1] || '')) selfTest();
