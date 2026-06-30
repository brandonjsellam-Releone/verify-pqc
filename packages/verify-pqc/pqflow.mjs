/*!
 * pqflow — QuantumPay authorization-LIFECYCLE engine (reference, DRAFT). A pqpay authorization is a single signed
 * intent; pqflow tracks its lifecycle — authorize → capture(s) → settle / void / refund — as a merchant-signed,
 * hash-CHAINED transition log with recompute-verifiable state. This is what a processor/PSP integration needs on top
 * of a one-shot authorization, and the merchant-signed chain + durable nonce ledger close pqpay's residual replay gap.
 *
 * Invariants enforced (at append AND re-checked in verifyFlow by recomputing the state from the signed transitions):
 *   - genesis is a pqpay authorization, VERIFIED under the pinned payer (fail-dangerous — never open on an invalid auth);
 *   - NEVER over-capture (Σcaptures ≤ authorized); no capture after settle/void; void only before any capture;
 *   - refund ≤ Σcaptures; nonces are unique across the flow (replay-safe) + optional cross-flow durable ledger;
 *   - tamper-evident chain (each transition binds prev_hash; altering any breaks every hash after).
 *
 * HONEST SCOPE (keeps it truthful + legal): this signs and verifies AUTHORIZATION + capture INTENT — it does NOT move,
 * hold, settle, or custody money. Settlement is a regulated rail (licensed PSP / card network / broker / chain); pqflow
 * is the cryptographic, tamper-evident, replay-safe record the rail can check. It neither initiates a payment nor
 * holds/reserves funds, so the engine itself is not a PSD2 payment service or e-money — the licensed rail owns that.
 * Unaudited reference. Self-test: node pqflow.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { verifyAuthorization, makePayerId } from './pqpay.mjs';

const FLOW_CTX = utf8ToBytes('trelyan-quantumpay-flow-v1');         // merchant-signing domain (Ed25519 + ML-DSA legs)
const FLOW_SLH_CTX = utf8ToBytes('trelyan-quantumpay-flow-slh-v1'); // distinct domain for the optional SLH leg

function canon(v) {
  if (v === undefined) return 'null';
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
const h = (s) => bytesToHex(sha256(utf8ToBytes(s)));

export function makeMerchantId(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('merchant keys must be { ed, mldsa[, slh] }');
  return 'merchant:trelyan:' + bytesToHex(sha256(concatBytes(utf8ToBytes('merchant:trelyan:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}

const transitionCore = (t) => ({ v: '1', seq: t.seq, prev_hash: t.prev_hash, auth_id: t.auth_id, type: t.type, amount: t.amount ?? null, nonce: t.nonce, auth_sha256: t.auth_sha256 ?? null, merchant: t.merchant, at: t.at ?? null });

// fold the ordered transitions into a state, enforcing the lifecycle invariants. Pure → used at append + at verify.
export function foldState(transitions) {
  if (!Array.isArray(transitions) || transitions.length === 0) return { valid: false, error: 'empty flow' };
  let authorized = 0, captured = 0, refunded = 0, status = 'open';
  for (let i = 0; i < transitions.length; i++) {
    const t = transitions[i];
    if (i === 0) { if (t.type !== 'authorize') return { valid: false, error: 'genesis is not an authorize' }; if (!Number.isInteger(t.amount) || t.amount <= 0) return { valid: false, error: 'bad authorized amount' }; authorized = t.amount; continue; }
    if (t.type === 'capture') {
      if (status !== 'open') return { valid: false, error: 'capture after ' + status };
      if (!Number.isInteger(t.amount) || t.amount <= 0) return { valid: false, error: 'bad capture amount' };
      if (captured + t.amount > authorized) return { valid: false, error: 'over-capture (Σcaptures > authorized)' };
      captured += t.amount;
    } else if (t.type === 'void') {
      if (status !== 'open') return { valid: false, error: 'void after ' + status };
      if (captured !== 0) return { valid: false, error: 'void after a capture (refund instead)' };
      status = 'voided';
    } else if (t.type === 'settle') {
      if (status !== 'open') return { valid: false, error: 'settle after ' + status };
      status = 'settled';
    } else if (t.type === 'refund') {
      if (status !== 'open' && status !== 'settled') return { valid: false, error: 'refund when ' + status };
      if (captured === 0) return { valid: false, error: 'refund with no capture' };
      if (!Number.isInteger(t.amount) || t.amount <= 0) return { valid: false, error: 'bad refund amount' };
      if (refunded + t.amount > captured) return { valid: false, error: 'over-refund (Σrefunds > Σcaptures)' };
      refunded += t.amount;
    } else return { valid: false, error: 'unknown transition type: ' + t.type };
  }
  return { valid: true, authorized, captured, refunded, remaining: authorized - captured, status };
}

function signTransition(core, merchantKeys) {
  const coreBytes = utf8ToBytes(canon(core));
  const sig = { merchant_pub: { ed: bytesToHex(_pub(merchantKeys.ed)), mldsa: bytesToHex(_pub(merchantKeys.mldsa)) }, slh_signer_pub_hex: merchantKeys.slh ? bytesToHex(_pub(merchantKeys.slh)) : null,
    ed_sig: bytesToHex(ed25519.sign(concatBytes(FLOW_CTX, coreBytes), merchantKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, merchantKeys.mldsa.secretKey, { context: FLOW_CTX })) };
  if (merchantKeys.slh) { sig.merchant_pub.slh = bytesToHex(_pub(merchantKeys.slh)); sig.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, merchantKeys.slh.secretKey, { context: FLOW_SLH_CTX })); }
  return { ...core, ...sig, entry_hash: h(canon(core)) };
}
function verifyEntrySig(entry, merchantPub) {
  const coreBytes = utf8ToBytes(canon(transitionCore(entry)));
  let edOk = false, pqOk = false, slhOk = true;
  try { edOk = ed25519.verify(hexToBytes(entry.ed_sig), concatBytes(FLOW_CTX, coreBytes), merchantPub.ed); } catch { edOk = false; }
  try { pqOk = ml_dsa87.verify(hexToBytes(entry.mldsa_sig), coreBytes, merchantPub.mldsa, { context: FLOW_CTX }); } catch { pqOk = false; }
  if (merchantPub.slh) { try { slhOk = !!(entry.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(entry.slh_sig), coreBytes, merchantPub.slh, { context: FLOW_SLH_CTX })); } catch { slhOk = false; } }
  return edOk && pqOk && slhOk;
}

// open a flow on a VERIFIED pqpay authorization. payerPub = pinned payer { ed, mldsa[, slh] }. Pass seenNonces (a
// durable {has,add} ledger) to CONSUME the auth nonce — preventing the same authorization from opening two flows.
export function openFlow({ auth, payerPub, merchantKeys, at = null, now = null, seenNonces, allowUnmeteredOpen = false }) {
  if (!merchantKeys || !merchantKeys.ed || !merchantKeys.mldsa) throw new Error('merchantKeys must be { ed, mldsa[, slh] }');
  // FAIL-CLOSED single-use (council fix — OpenAI): without consuming the auth nonce in a durable ledger, the SAME
  // pqpay authorization could open multiple flows, each locally satisfying Σcaptures≤authorized → global double-spend.
  // Require a durable seenNonces ledger to consume the nonce, unless the caller explicitly opts into a dev/non-metered open.
  const hasLedger = seenNonces && typeof seenNonces.has === 'function' && typeof seenNonces.add === 'function';
  if (!hasLedger && !allowUnmeteredOpen) throw new Error('openFlow requires a durable seenNonces ledger to consume the auth nonce (single-use — blocks double-open/double-spend); pass allowUnmeteredOpen:true for a dev/non-metered open');
  const v = verifyAuthorization(auth, payerPub, { now, seenNonces: hasLedger ? seenNonces : undefined, allowUnmeteredCheck: !hasLedger });
  if (!v.verified) throw new Error('cannot open a flow on an UNVERIFIED / replayed authorization (fail-dangerous): ' + (v.reason || 'invalid'));
  if (hasLedger) seenNonces.add(String(auth.nonce)); // consume → the same auth cannot open a second flow
  const merchant = makeMerchantId(merchantKeys);
  const core = transitionCore({ seq: 0, prev_hash: null, auth_id: auth.id, type: 'authorize', amount: auth.amount, nonce: auth.nonce, auth_sha256: h(canon(auth)), merchant, at });
  const genesis = { ...signTransition(core, merchantKeys), auth };
  return { v: '1', auth_id: auth.id, payer: auth.payer, payee: auth.payee, currency: auth.currency, transitions: [genesis] };
}

// append a lifecycle transition (capture/void/settle/refund). Validates the invariant BEFORE appending (fail-dangerous)
// and refuses a reused nonce. Mutates + returns the flow.
function append(flow, { type, amount = null, nonce, merchantKeys, at = null }) {
  if (!flow || !Array.isArray(flow.transitions) || !flow.transitions.length) throw new Error('not a flow');
  if (!merchantKeys || !merchantKeys.ed || !merchantKeys.mldsa) throw new Error('merchantKeys must be { ed, mldsa[, slh] }');
  if (nonce == null) throw new Error('a fresh nonce is required (replay safety)');
  if (flow.transitions.some((t) => String(t.nonce) === String(nonce))) throw new Error('nonce already used in this flow (replay)');
  const candidate = { type, amount };
  const probe = foldState(flow.transitions.concat([candidate]));
  if (!probe.valid) throw new Error('illegal transition: ' + probe.error);
  const prev = flow.transitions[flow.transitions.length - 1];
  const core = transitionCore({ seq: flow.transitions.length, prev_hash: prev.entry_hash, auth_id: flow.auth_id, type, amount, nonce: String(nonce), auth_sha256: null, merchant: makeMerchantId(merchantKeys), at });
  flow.transitions.push(signTransition(core, merchantKeys));
  return flow;
}
export const capture = (flow, o) => append(flow, { ...o, type: 'capture' });
export const voidFlow = (flow, o) => append(flow, { ...o, type: 'void', amount: null });
export const settle = (flow, o) => append(flow, { ...o, type: 'settle', amount: null });
export const refund = (flow, o) => append(flow, { ...o, type: 'refund' });

// TOTAL / fail-closed. Verifies the chain + every transition's merchant signature + the genesis pqpay auth (under the
// pinned payer) + RECOMPUTES the lifecycle state and its invariants. opts.seenNonces = optional cross-flow replay set.
export function verifyFlow(flow, merchantPub, payerPub, opts = {}) {
  try {
    if (!flow || typeof flow !== 'object' || !Array.isArray(flow.transitions) || !flow.transitions.length) return { verified: false };
    if (!merchantPub || !merchantPub.ed || !merchantPub.mldsa || !payerPub || !payerPub.ed || !payerPub.mldsa) return { verified: false };
    const merchantId = makeMerchantId(merchantPub);
    const nonces = new Set();
    let prevHash = null;
    for (let i = 0; i < flow.transitions.length; i++) {
      const t = flow.transitions[i];
      if (i > 0 && t.auth_sha256 != null) return { verified: false, reason: 'non-genesis transition carries an auth binding at ' + i }; // only genesis embeds the auth (no unconstrained signed field — council hardening)
      if (t.seq !== i || t.prev_hash !== prevHash) return { verified: false, reason: 'chain broken at ' + i };
      if (t.entry_hash !== h(canon(transitionCore(t)))) return { verified: false, reason: 'entry_hash mismatch at ' + i };
      if (t.merchant !== merchantId) return { verified: false, reason: 'transition not by the pinned merchant at ' + i };
      if (!verifyEntrySig(t, merchantPub)) return { verified: false, reason: 'merchant signature invalid at ' + i };
      if (t.auth_id !== flow.auth_id) return { verified: false, reason: 'auth_id mismatch at ' + i };
      if (nonces.has(String(t.nonce))) return { verified: false, reason: 'duplicate nonce in flow at ' + i };
      nonces.add(String(t.nonce));
      if (opts.seenNonces && typeof opts.seenNonces.has === 'function' && opts.seenNonces.has(String(t.nonce))) return { verified: false, reason: 'nonce seen in another flow (cross-flow replay) at ' + i };
      prevHash = t.entry_hash;
    }
    // genesis: a real pqpay authorization, valid under the pinned payer, bound into the chain
    const g = flow.transitions[0];
    if (g.type !== 'authorize' || !g.auth) return { verified: false, reason: 'genesis is not an authorize with an embedded auth' };
    if (g.auth_sha256 !== h(canon(g.auth))) return { verified: false, reason: 'embedded auth hash != bound auth_sha256 (auth swapped)' };
    const av = verifyAuthorization(g.auth, payerPub, { now: opts.now, allowUnmeteredCheck: true });
    if (!av.verified) return { verified: false, reason: 'embedded authorization invalid under the pinned payer: ' + (av.reason || '') };
    if (g.amount !== g.auth.amount || g.nonce !== g.auth.nonce || g.auth.id !== flow.auth_id) return { verified: false, reason: 'genesis does not match the embedded authorization' };
    const st = foldState(flow.transitions);
    if (!st.valid) return { verified: false, reason: 'lifecycle invariant violated: ' + st.error };
    return { verified: true, state: { auth_id: flow.auth_id, payer: flow.payer, payee: flow.payee, currency: flow.currency, authorized: st.authorized, captured: st.captured, refunded: st.refunded, remaining: st.remaining, status: st.status } };
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqflow.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { createAuthorization, makeNonceLedger } = await import('./pqpay.mjs');
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const ks = (a, b) => ({ ed: ed(a), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(b)) });
  const payer = ks(1, 2), merchant = ks(3, 4);
  const tPayer = { ed: payer.ed.publicKey, mldsa: payer.mldsa.publicKey };
  const tMerch = { ed: merchant.ed.publicKey, mldsa: merchant.mldsa.publicKey };
  const auth = createAuthorization({ payerKeys: payer, id: 'pay-1', payee: 'merchant:acme', amount: 10000, currency: 'USD', nonce: 'n-auth' });

  // open + partial captures within authorized
  const led = makeNonceLedger();
  const flow = openFlow({ auth, payerPub: tPayer, merchantKeys: merchant, at: 1, seenNonces: led });
  ok(flow.transitions.length === 1 && verifyFlow(flow, tMerch, tPayer).verified === true, 'open on a verified auth → valid 1-entry flow');
  capture(flow, { amount: 4000, nonce: 'c1', merchantKeys: merchant, at: 2 });
  capture(flow, { amount: 3000, nonce: 'c2', merchantKeys: merchant, at: 3 });
  const v = verifyFlow(flow, tMerch, tPayer);
  ok(v.verified && v.state.captured === 7000 && v.state.remaining === 3000 && v.state.status === 'open', 'two partial captures → captured 7000, remaining 3000');

  // NEVER over-capture
  let over = false; try { capture(flow, { amount: 4000, nonce: 'c3', merchantKeys: merchant, at: 4 }); } catch { over = true; }
  ok(over && verifyFlow(flow, tMerch, tPayer).state.captured === 7000, 'over-capture (7000+4000 > 10000) REFUSED at append');

  // settle, then refund within captured; over-refund refused
  settle(flow, { nonce: 's1', merchantKeys: merchant, at: 5 });
  refund(flow, { amount: 2000, nonce: 'r1', merchantKeys: merchant, at: 6 });
  const v2 = verifyFlow(flow, tMerch, tPayer);
  ok(v2.verified && v2.state.status === 'settled' && v2.state.refunded === 2000, 'settle + refund 2000 → settled, refunded 2000');
  let overR = false; try { refund(flow, { amount: 6000, nonce: 'r2', merchantKeys: merchant, at: 7 }); } catch { overR = true; }
  ok(overR, 'over-refund (2000+6000 > 7000 captured) REFUSED');
  let capAfter = false; try { capture(flow, { amount: 100, nonce: 'c9', merchantKeys: merchant, at: 8 }); } catch { capAfter = true; }
  ok(capAfter, 'capture after settle REFUSED');

  // reused nonce refused
  let dup = false; try { refund(flow, { amount: 100, nonce: 'r1', merchantKeys: merchant, at: 9 }); } catch { dup = true; }
  ok(dup, 'reused nonce REFUSED (replay safety)');

  // void only before capture
  const auth2 = createAuthorization({ payerKeys: payer, id: 'pay-2', payee: 'merchant:acme', amount: 500, currency: 'USD', nonce: 'n-auth2' });
  const flow2 = openFlow({ auth: auth2, payerPub: tPayer, merchantKeys: merchant, at: 1, allowUnmeteredOpen: true });
  voidFlow(flow2, { nonce: 'vd', merchantKeys: merchant, at: 2 });
  ok(verifyFlow(flow2, tMerch, tPayer).state.status === 'voided', 'void an uncaptured auth → voided');
  const flow3 = openFlow({ auth: createAuthorization({ payerKeys: payer, id: 'pay-3', payee: 'm', amount: 500, currency: 'USD', nonce: 'n3' }), payerPub: tPayer, merchantKeys: merchant, allowUnmeteredOpen: true });
  capture(flow3, { amount: 100, nonce: 'c', merchantKeys: merchant });
  let voidAfter = false; try { voidFlow(flow3, { nonce: 'v', merchantKeys: merchant }); } catch { voidAfter = true; }
  ok(voidAfter, 'void after a capture REFUSED (refund instead)');

  // fail-dangerous open on a bad auth
  let badOpen = false; try { openFlow({ auth, payerPub: ks(8, 9), merchantKeys: merchant, allowUnmeteredOpen: true }); } catch { badOpen = true; }
  ok(badOpen, 'fail-dangerous: open on an auth that does not verify under the payer → REFUSED');
  // council fix (OpenAI): the SAME auth cannot open two flows (global double-spend) — a durable ledger consumes its nonce
  const ledX = makeNonceLedger();
  const authX = createAuthorization({ payerKeys: payer, id: 'pay-x', payee: 'm', amount: 100, currency: 'USD', nonce: 'n-x' });
  openFlow({ auth: authX, payerPub: tPayer, merchantKeys: merchant, seenNonces: ledX });
  let dbl = false; try { openFlow({ auth: authX, payerPub: tPayer, merchantKeys: merchant, seenNonces: ledX }); } catch { dbl = true; }
  ok(dbl, 'double-open REFUSED: the same auth cannot open a second flow when a durable ledger consumes its nonce (no double-spend)');
  let noLedger = false; try { openFlow({ auth: authX, payerPub: tPayer, merchantKeys: merchant }); } catch { noLedger = true; }
  ok(noLedger, 'openFlow fail-closed: refuses to open without a durable seenNonces ledger (or explicit allowUnmeteredOpen)');

  // tamper-evident + forgery
  const tam = JSON.parse(JSON.stringify(flow)); tam.transitions[1].amount = 9000;
  ok(verifyFlow(tam, tMerch, tPayer).verified === false, 'altered capture amount → entry_hash/sig FAILS (tamper-evident)');
  ok(verifyFlow(flow, { ed: ed(8).publicKey, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(8)).publicKey }, tPayer).verified === false, 'wrong pinned merchant → FAILS');
  ok(verifyFlow(flow, tMerch, { ed: ed(8).publicKey, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(7)).publicKey }).verified === false, 'wrong pinned payer (genesis auth) → FAILS');
  const swap = JSON.parse(JSON.stringify(flow2)); swap.transitions[0].auth = JSON.parse(JSON.stringify(flow.transitions[0].auth));
  ok(verifyFlow(swap, tMerch, tPayer).verified === false, 'swapped embedded auth → auth_sha256 mismatch → FAILS');
  const ab = JSON.parse(JSON.stringify(flow)); ab.transitions[1].auth_sha256 = 'beef';
  ok(verifyFlow(ab, tMerch, tPayer).verified === false && /auth binding/.test(verifyFlow(ab, tMerch, tPayer).reason || ''), 'non-genesis transition with an auth binding → REJECTED (council hardening: no unconstrained signed field)');

  // 3-leg hybrid
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5));
  const merch3 = { ed: merchant.ed, mldsa: merchant.mldsa, slh };
  const tMerch3 = { ed: tMerch.ed, mldsa: tMerch.mldsa, slh: slh.publicKey };
  const f3 = openFlow({ auth: createAuthorization({ payerKeys: payer, id: 'p4', payee: 'm', amount: 200, currency: 'USD', nonce: 'n4' }), payerPub: tPayer, merchantKeys: merch3, allowUnmeteredOpen: true });
  capture(f3, { amount: 200, nonce: 'cc', merchantKeys: merch3 });
  ok(typeof f3.transitions[1].slh_sig === 'string' && verifyFlow(f3, tMerch3, tPayer).verified === true, '3-leg (Ed25519∧ML-DSA∧SLH) flow verifies');
  const f3s = JSON.parse(JSON.stringify(f3)); f3s.transitions[1].slh_sig = '00';
  ok(verifyFlow(f3s, tMerch3, tPayer).verified === false, 'stripped SLH leg fails when merchant.slh pinned (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { transitions: 'x' }, { transitions: [{ seq: 5 }] }]) { try { if (verifyFlow(bad, tMerch, tPayer).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed flows → verified:false, never throws');
  let totalF = true; for (const bad of [null, undefined, 42, [], [{ type: 'capture', amount: 1 }]]) { try { if (foldState(bad).valid !== false) totalF = false; } catch { totalF = false; } }
  ok(totalF, 'TOTAL: foldState on garbage → valid:false, never throws');

  console.log('pqflow self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqflow\.mjs$/.test(process.argv[1] || '')) selfTest();
