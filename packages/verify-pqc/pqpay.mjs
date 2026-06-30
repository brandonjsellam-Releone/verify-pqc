/*!
 * pqpay — QuantumPay: post-quantum payment-AUTHORIZATION signing (reference, DRAFT).
 *
 * A payer cryptographically authorizes a specific payment INTENT — { payer, payee, amount, currency, nonce, expiry } —
 * with a HYBRID signature (Ed25519 ∧ ML-DSA-87 ∧ optional SLH-DSA-256f). A processor/broker can then verify the
 * authorization is authentic, unaltered, amount/payee-bound, unexpired, and not replayed BEFORE acting on it.
 *
 * HONEST SCOPE (the line that keeps this legal + truthful): pqpay signs and verifies an AUTHORIZATION. It does NOT move
 * money, hold funds, settle, or custody anything — settlement is a regulated payment rail (a licensed PSP, card network,
 * broker such as Alpaca, or chain). This is the cryptographic authorization layer that rail can check; the rail does the
 * money. Anti-replay / double-spend is the verifier's job: use verifyAndConsume() against a DURABLE, atomic nonce store
 * (DB / Redis SETNX). makeNonceLedger() is in-memory + dev-only — a process restart REOPENS the replay window (apex-team-flagged).
 *
 * FALSIFIABLE PROPERTIES: given the authorization + the PINNED payer keys, a third party can verify (1) the payer (whose
 * id binds its keys) authorized THIS exact { payee, amount, currency } — forging needs a classical AND lattice [AND
 * hash-based] break; (2) it is unexpired and (with the verifier's nonce ledger) un-replayed; (3) amount caps / payee /
 * currency expectations hold. Tampering any field breaks the hybrid signature. Unaudited reference implementation.
 *
 * Dependency-light: @noble/curves (ed25519) + @noble/post-quantum (ml-dsa-87, slh-dsa) + @noble/hashes (sha256).
 * Self-test: node pqpay.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';

const PAY_CTX = utf8ToBytes('trelyan-quantumpay-auth-v1');         // signing domain (Ed25519 + ML-DSA legs)
const PAY_SLH_CTX = utf8ToBytes('trelyan-quantumpay-auth-slh-v1'); // distinct domain for the optional SLH-DSA leg

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
// payer id binds the COMPLETE hybrid key set (full 256-bit; same hardening as did:trelyan).
export function makePayerId(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('payer keys must be { ed, mldsa[, slh] }');
  return 'pay:trelyan:' + bytesToHex(sha256(concatBytes(utf8ToBytes('pay:trelyan:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}
// signable core. amount is an INTEGER in MINOR units (cents / satoshi) — never a float.
function authCore(a) {
  return { v: '1', id: a.id, payer: a.payer, payee: a.payee, amount: a.amount, currency: a.currency, nonce: a.nonce, issued_at: a.issued_at ?? null, expires_at: a.expires_at ?? null, memo: a.memo ?? null };
}

// payerKeys = { ed, mldsa[, slh] }. amount = positive integer minor units. Returns a signed authorization object.
export function createAuthorization({ payerKeys, id, payee, amount, currency, nonce, issuedAt, expiresAt, memo }) {
  if (!payerKeys || !payerKeys.ed || !payerKeys.mldsa) throw new Error('payerKeys must be { ed, mldsa[, slh] }');
  if (!Number.isInteger(amount) || amount <= 0) throw new Error('amount must be a POSITIVE INTEGER in minor units (cents/sats)');
  if (!id || !payee || !currency) throw new Error('id, payee and currency are required');
  const core = authCore({ id: String(id), payer: makePayerId(payerKeys), payee: String(payee), amount, currency: String(currency),
    nonce: String(nonce ?? bytesToHex(randomBytes(16))), issued_at: issuedAt ?? null, expires_at: expiresAt ?? null, memo: memo ?? null });
  const coreBytes = utf8ToBytes(canon(core));
  const auth = { ...core,
    payer_pub: { ed: bytesToHex(_pub(payerKeys.ed)), mldsa: bytesToHex(_pub(payerKeys.mldsa)) },
    ed_sig: bytesToHex(ed25519.sign(concatBytes(PAY_CTX, coreBytes), payerKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, payerKeys.mldsa.secretKey, { context: PAY_CTX })) };
  if (payerKeys.slh) { auth.payer_pub.slh = bytesToHex(_pub(payerKeys.slh)); auth.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, payerKeys.slh.secretKey, { context: PAY_SLH_CTX })); }
  return auth;
}

// TOTAL / fail-closed. trustedPayer = { ed, mldsa[, slh] } pinned payer pubkeys. opts: now (expiry), seenNonces
// ({has,add} ledger — replay), maxAmount (cap), expectedPayee / expectedCurrency (bind), allowUnmeteredCheck (permit a
// NON-consuming validity check without a ledger). FAIL-CLOSED: an otherwise-valid auth WITHOUT a seenNonces ledger is
// rejected (replay = double-spend) unless allowUnmeteredCheck — the caller owns a DURABLE ledger (use verifyAndConsume).
export function verifyAuthorization(auth, trustedPayer, opts = {}) {
  try {
    if (!auth || typeof auth !== 'object' || !trustedPayer || !trustedPayer.ed || !trustedPayer.mldsa) return { verified: false };
    if (!Number.isInteger(auth.amount) || auth.amount <= 0) return { verified: false, reason: 'amount not a positive integer' };
    if (auth.payer !== makePayerId(trustedPayer)) return { verified: false, reason: 'payer id != pinned payer keys' };
    const coreBytes = utf8ToBytes(canon(authCore(auth)));
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(auth.ed_sig), concatBytes(PAY_CTX, coreBytes), trustedPayer.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(auth.mldsa_sig), coreBytes, trustedPayer.mldsa, { context: PAY_CTX }); } catch { pqOk = false; }
    if (trustedPayer.slh) { try { slhOk = !!(auth.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(auth.slh_sig), coreBytes, trustedPayer.slh, { context: PAY_SLH_CTX })); } catch { slhOk = false; } }
    if (!edOk || !pqOk || !slhOk) return { verified: false, reason: 'hybrid signature invalid (or required leg missing)' };
    // a declared expiry MUST be checkable: refuse to verify an auth that carries expires_at when no clock (opts.now) is
    // supplied — silently skipping expiry on a PAYMENT would let an expired authorization pass (DeepSeek 1 Jul). Explicit
    // opt-out (allowNoExpiryClock) only for a pure signature/well-formedness check that deliberately ignores time.
    if (auth.expires_at != null && opts.now == null && opts.allowNoExpiryClock !== true) return { verified: false, reason: 'expires_at declared but no clock (opts.now) supplied — cannot verify freshness' };
    const expired = auth.expires_at != null && opts.now != null && Number(opts.now) > Number(auth.expires_at);
    const replayed = opts.seenNonces && typeof opts.seenNonces.has === 'function' && opts.seenNonces.has(String(auth.nonce));
    const overCap = opts.maxAmount != null && auth.amount > Number(opts.maxAmount);
    const wrongPayee = opts.expectedPayee != null && auth.payee !== String(opts.expectedPayee);
    const wrongCurrency = opts.expectedCurrency != null && auth.currency !== String(opts.expectedCurrency);
    const verified0 = !expired && !replayed && !overCap && !wrongPayee && !wrongCurrency;
    // FAIL-CLOSED (apex-team): a payment authorization always carries a nonce, so replay = double-spend. Do NOT report a
    // clean verify without a durable seen-nonce ledger enforcing single-use — unless the caller explicitly asks for a
    // NON-consuming check (allowUnmeteredCheck). Failures for other reasons (expiry/cap/payee/currency) are unaffected.
    if (verified0 && !(opts.seenNonces && typeof opts.seenNonces.has === 'function') && opts.allowUnmeteredCheck !== true) {
      return { verified: false, reason: 'seenNonces ledger required for replay protection (or set allowUnmeteredCheck for a non-consuming check)', expired, replayed: false, overCap, wrongPayee, wrongCurrency };
    }
    const verified = verified0;
    return { verified, expired, replayed, overCap, wrongPayee, wrongCurrency, payer: auth.payer, payee: auth.payee, amount: auth.amount, currency: auth.currency, id: auth.id };
  } catch { return { verified: false }; }
}

// anti-replay helper. IN-MEMORY ONLY — production MUST back this with a durable, atomic store; a restart reopens the
// replay window. Nonces are normalised to strings (kills number/string type-confusion in the ledger).
export function makeNonceLedger() {
  const seen = new Set();
  // `consume` is an ATOMIC test-and-set (returns false if the nonce was already seen) — it closes the has()/add() TOCTOU
  // window (DeepSeek 1 Jul). In single-threaded JS the test+set is uninterruptible; a DISTRIBUTED ledger MUST back this
  // with an atomic primitive (Redis SETNX, a unique-insert, a CAS) — exposing it on the interface makes that contract explicit.
  return { has: (n) => seen.has(String(n)), add: (n) => seen.add(String(n)),
    consume: (n) => { const k = String(n); if (seen.has(k)) return false; seen.add(k); return true; },
    get size() { return seen.size; } };
}
// verify + consume the nonce exactly once (the correct-usage path). Prefers the ledger's ATOMIC consume() to eliminate the
// check-then-set race; falls back to has()-during-verify + add()-on-success (safe in a single synchronous JS context).
export function verifyAndConsume(auth, trustedPayer, ledger, opts = {}) {
  if (ledger && typeof ledger.consume === 'function') {
    const r = verifyAuthorization(auth, trustedPayer, { ...opts, allowUnmeteredCheck: true }); // all NON-replay checks first
    if (!r.verified) return r;
    if (!ledger.consume(String(auth.nonce))) return { ...r, verified: false, replayed: true, reason: 'replayed (atomic consume)' };
    return { ...r, replayed: false };
  }
  const r = verifyAuthorization(auth, trustedPayer, { ...opts, seenNonces: ledger });
  if (r.verified && ledger && typeof ledger.add === 'function') ledger.add(auth.nonce);  // commit-on-success
  return r;
}

/* ---------- self-test: node pqpay.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const payer = { ed: ed(1), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)) };
  const tPayer = { ed: payer.ed.publicKey, mldsa: payer.mldsa.publicKey };
  const attacker = { ed: ed(9), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)) };

  const auth = createAuthorization({ payerKeys: payer, id: 'pay-1', payee: 'merchant:acme', amount: 4999, currency: 'USD', nonce: 'n1', expiresAt: 5000 });
  ok(makePayerId(payer).startsWith('pay:trelyan:') && auth.payer === makePayerId(payer), 'payer id binds the payer keys');
  ok(verifyAuthorization(auth, tPayer, { now: 2000, allowUnmeteredCheck: true }).verified === true, 'valid authorization verifies under the pinned payer (non-consuming check)');
  ok(verifyAuthorization(auth, tPayer, { now: 2000 }).verified === false, 'APEX-TEAM FIX: an otherwise-valid auth with NO seenNonces ledger -> fail-closed (replay unprotected)');
  ok(verifyAuthorization(auth, { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }, { now: 2000 }).verified === false, 'wrong pinned payer -> FAILS');
  // tamper amount (the classic attack) -> hybrid sig fails
  const t = JSON.parse(JSON.stringify(auth)); t.amount = 1;
  ok(verifyAuthorization(t, tPayer, { now: 2000 }).verified === false, 'tampered amount (4999->1) -> verify FAILS');
  // expiry, replay, cap, payee, currency binding
  ok(verifyAuthorization(auth, tPayer, { now: 9000 }).verified === false, 'expired authorization -> FAILS');
  ok(verifyAuthorization(auth, tPayer, { now: 2000, seenNonces: new Set(['n1']) }).verified === false, 'replayed nonce -> FAILS (verifier ledger)');
  ok(verifyAuthorization(auth, tPayer, { now: 2000, maxAmount: 1000 }).verified === false, 'over amount cap -> FAILS');
  ok(verifyAuthorization(auth, tPayer, { now: 2000, expectedPayee: 'merchant:evil' }).verified === false, 'payee mismatch -> FAILS');
  ok(verifyAuthorization(auth, tPayer, { now: 2000, expectedCurrency: 'EUR' }).verified === false, 'currency mismatch -> FAILS');
  ok(verifyAuthorization(auth, tPayer, { now: 2000, maxAmount: 5000, expectedPayee: 'merchant:acme', expectedCurrency: 'USD', allowUnmeteredCheck: true }).verified === true, 'within cap + correct payee/currency -> verifies');

  // amount must be a positive integer in minor units
  let badAmt = false; try { createAuthorization({ payerKeys: payer, id: 'x', payee: 'p', amount: 49.99, currency: 'USD' }); } catch { badAmt = true; }
  ok(badAmt, 'float amount rejected at creation (minor-units integer only)');
  let negAmt = false; try { createAuthorization({ payerKeys: payer, id: 'x', payee: 'p', amount: -5, currency: 'USD' }); } catch { negAmt = true; }
  ok(negAmt, 'negative amount rejected');

  // 3-leg hash-based hardening
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5));
  const payer3 = { ed: payer.ed, mldsa: payer.mldsa, slh };
  const tPayer3 = { ed: tPayer.ed, mldsa: tPayer.mldsa, slh: slh.publicKey };
  const auth3 = createAuthorization({ payerKeys: payer3, id: 'pay-3', payee: 'm', amount: 100, currency: 'USD', nonce: 'n3' });
  ok(typeof auth3.slh_sig === 'string' && verifyAuthorization(auth3, tPayer3, { allowUnmeteredCheck: true }).verified === true, '3-leg (Ed25519∧ML-DSA∧SLH-DSA) authorization verifies');
  const auth3s = JSON.parse(JSON.stringify(auth3)); auth3s.slh_sig = '00';
  ok(verifyAuthorization(auth3s, tPayer3, {}).verified === false, 'stripped SLH leg fails when payer.slh pinned (anti-downgrade)');

  // APEX-TEAM hardening: nonce normalized to string + verifyAndConsume/makeNonceLedger close the replay footgun
  const num = createAuthorization({ payerKeys: payer, id: 'pay-n', payee: 'm', amount: 10, currency: 'USD', nonce: 777 });
  ok(num.nonce === '777', 'nonce normalized to a string at creation (no number/string type-confusion in the ledger)');
  const ledger = makeNonceLedger();
  ok(verifyAndConsume(num, tPayer, ledger, { now: 1 }).verified === true, 'verifyAndConsume: first use verifies + records the nonce');
  ok(verifyAndConsume(num, tPayer, ledger, { now: 1 }).verified === false, 'verifyAndConsume: re-use of the same nonce -> replay REJECTED');
  const led2 = makeNonceLedger(); verifyAndConsume(JSON.parse(JSON.stringify(num)), { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }, led2, { now: 1 });
  ok(led2.size === 0, 'commit-on-success: a FAILED authorization does NOT consume the nonce');

  // expiry strictness (DeepSeek 1 Jul): an auth that DECLARES expires_at must not verify when no clock is supplied
  ok(verifyAuthorization(auth, tPayer, { allowUnmeteredCheck: true }).verified === false, 'declared expires_at + no opts.now → refused (no silent expiry bypass)');
  ok(verifyAuthorization(auth, tPayer, { allowUnmeteredCheck: true, allowNoExpiryClock: true }).verified === true, 'explicit allowNoExpiryClock → permits a deliberately time-less well-formedness check');
  // atomic consume (closes the has/add TOCTOU window): test-and-set
  const al = makeNonceLedger();
  ok(al.consume('z') === true && al.consume('z') === false, 'atomic consume: first claim true, replay false (test-and-set)');
  const al2 = makeNonceLedger();
  const num2 = createAuthorization({ payerKeys: payer, id: 'pay-n2', payee: 'm', amount: 10, currency: 'USD', nonce: 'n2-atomic' });
  ok(verifyAndConsume(num2, tPayer, al2, { now: 1 }).verified === true && verifyAndConsume(num2, tPayer, al2, { now: 1 }).verified === false, 'verifyAndConsume via atomic consume: first verifies, replay rejected');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { amount: 5 }, { ...auth, amount: 'lots' }]) { try { if (verifyAuthorization(bad, tPayer).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed authorizations -> verified:false, never throws');

  console.log('pqpay self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqpay\.mjs$/.test(process.argv[1] || '')) selfTest();
