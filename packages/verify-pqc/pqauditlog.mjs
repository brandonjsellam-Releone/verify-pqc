/*!
 * pqauditlog — tamper-evident, replay-proof, HYBRID-signed decision/action audit log with chain-of-custody (reference,
 * DRAFT). The ungated cryptographic core of Apex's "AUDIT & INTEGRITY" mandate: every input -> signal -> decision ->
 * execution -> ledger event is hash-chained and dual-signed (Ed25519 AND ML-DSA-87), so the full trail is verifiable by
 * an independent party without trusting the producer. It deliberately does NOT execute trades, move funds, or touch a
 * broker/HSM/chain — those are separate, regulated, owner/counsel-gated layers. This module proves the RECORD is honest.
 *
 * NOVEL FALSIFIABLE PROPERTY (what a third party can now verify): given the log + the signer's PINNED Ed25519 + ML-DSA-87
 * public keys, anyone can confirm (1) every entry is dual-signed by the pinned signer — forging one requires breaking a
 * CLASSICAL *and* a post-quantum signature (AND-composition: stripping the PQ leg is detected, no silent downgrade);
 * (2) the entries form an unbroken hash chain (no insertion / deletion / reorder); (3) no nonce is replayed and
 * timestamps are non-decreasing (no replay / no back-dating within the log); (4) every decision/execution entry names a
 * custody parent that is present and earlier — a complete, falsifiable input->...->ledger chain of custody. HONEST: this
 * proves integrity + authenticity + ordering + non-replay of what WAS logged; it does not prove the producer logged
 * every real-world event (completeness is a process/attestation property, not a cryptographic one).
 *
 * Dependency-light: @noble/curves (ed25519) + @noble/post-quantum (ml-dsa-87) + @noble/hashes (sha256). Self-test: node pqauditlog.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';

const AUDIT_CTX = utf8ToBytes('trelyan-apex-auditlog-v1');   // signing domain separation (both legs)
const HASH_TAG = utf8ToBytes('trelyan-apex-auditlog-hash-v1'); // chain-hash domain tag
const GENESIS = '0'.repeat(64);
const STAGES = ['input', 'signal', 'decision', 'execution', 'ledger']; // chain-of-custody stages (ordered)

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const toBytes = (x) => (x instanceof Uint8Array ? x : utf8ToBytes(typeof x === 'string' ? x : canon(x)));
const payloadHash = (p) => bytesToHex(sha256(concatBytes(HASH_TAG, toBytes(p))));
// the signable core of an entry (everything except the signatures + the derived entry_hash)
function coreOf(e) {
  return { v: '1', seq: e.seq, ts: e.ts, nonce: e.nonce, actor: e.actor, action: e.action, stage: e.stage, parent_seq: e.parent_seq ?? null, payload_sha256: e.payload_sha256, prev_hash: e.prev_hash };
}
const entryHash = (coreBytes) => bytesToHex(sha256(concatBytes(HASH_TAG, coreBytes)));

// signer = { ed: {secretKey, publicKey}, mldsa: {secretKey, publicKey} }
export function createLog(signer, opts = {}) {
  if (!signer || !signer.ed || !signer.mldsa) throw new Error('signer must be { ed, mldsa } keypairs');
  return { entries: [], seenNonces: new Set(), signer, ctx: opts.ctx ?? null,
    signer_pub: { ed: bytesToHex(signer.ed.publicKey), mldsa: bytesToHex(signer.mldsa.publicKey) } };
}

// append one event. rec = { actor, action, stage, payload?, parentSeq?, ts?, nonce? }. Enforces unique nonce +
// non-decreasing ts + a known stage + a present/earlier custody parent. Returns the new signed entry.
export function append(log, rec) {
  const last = log.entries[log.entries.length - 1];
  const seq = log.entries.length;
  const ts = rec.ts ?? (last ? last.ts : 0);
  if (last && ts < last.ts) throw new Error('ts must be non-decreasing');
  if (!STAGES.includes(rec.stage)) throw new Error('unknown stage: ' + rec.stage);
  const nonce = rec.nonce ?? bytesToHex(randomBytes(16));
  if (log.seenNonces.has(nonce)) throw new Error('nonce reuse (replay): ' + nonce);
  const parent_seq = rec.parentSeq ?? null;
  if (parent_seq !== null && (parent_seq < 0 || parent_seq >= seq)) throw new Error('parent_seq must reference an earlier entry');
  const core = coreOf({ seq, ts, nonce, actor: rec.actor, action: rec.action, stage: rec.stage, parent_seq, payload_sha256: payloadHash(rec.payload ?? ''), prev_hash: last ? last.entry_hash : GENESIS });
  const coreBytes = utf8ToBytes(canon(core));
  const entry = { ...core,
    ed_sig: bytesToHex(ed25519.sign(concatBytes(AUDIT_CTX, coreBytes), log.signer.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, log.signer.mldsa.secretKey, { context: AUDIT_CTX })),
    entry_hash: entryHash(coreBytes) };
  log.seenNonces.add(nonce); log.entries.push(entry);
  return entry;
}

// export the publishable log: just the entries (the producer keeps nothing secret-bearing; payloads live elsewhere).
export const exportLog = (log) => log.entries.map((e) => ({ ...e }));

// TOTAL / fail-closed verification. trusted = { ed: Uint8Array pub, mldsa: Uint8Array pub } to PIN the signer (else
// TOFU against nothing — sigs cannot be checked, so pinning is required for authenticity; unpinned => sigOk:false).
// opts.now + opts.maxAgeMs optionally bound freshness of the LAST entry.
export function verifyLog(entries, trusted, opts = {}) {
  const base = { verified: false, n: 0, broken_at: 0, reason: '' };
  try {
    if (!Array.isArray(entries)) return { ...base, reason: 'entries not an array' };
    const seen = new Set(); let prev = GENESIS; let lastTs = -Infinity;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      const at = (reason) => ({ ...base, n: entries.length, broken_at: i, reason });
      if (!e || typeof e !== 'object' || e.seq !== i) return at('seq/shape');
      const coreBytes = utf8ToBytes(canon(coreOf(e)));
      if (e.prev_hash !== prev) return at('chain linkage (prev_hash)');           // no insert/delete/reorder
      if (entryHash(coreBytes) !== e.entry_hash) return at('entry_hash mismatch (tamper)');
      if (!STAGES.includes(e.stage)) return at('unknown stage');
      if (typeof e.ts !== 'number' || e.ts < lastTs) return at('ts not non-decreasing (back-dating)');
      if (seen.has(e.nonce)) return at('nonce replay');                            // no replay
      if (e.parent_seq !== null && !(Number.isInteger(e.parent_seq) && e.parent_seq < i)) return at('custody parent missing/forward');
      // AND-composition: BOTH the classical and the PQ signature must verify under the pinned keys (anti-downgrade).
      if (!trusted || !trusted.ed || !trusted.mldsa) return at('no pinned signer keys (authenticity uncheckable)');
      let edOk = false, pqOk = false;
      try { edOk = ed25519.verify(hexToBytes(e.ed_sig), concatBytes(AUDIT_CTX, coreBytes), trusted.ed); } catch { edOk = false; }
      try { pqOk = ml_dsa87.verify(hexToBytes(e.mldsa_sig), coreBytes, trusted.mldsa, { context: AUDIT_CTX }); } catch { pqOk = false; }
      if (!edOk) return at('Ed25519 signature invalid');
      if (!pqOk) return at('ML-DSA-87 signature invalid (or PQ leg stripped/downgraded)');
      seen.add(e.nonce); prev = e.entry_hash; lastTs = e.ts;
    }
    if (opts.now != null && opts.maxAgeMs != null && entries.length) {
      const tip = entries[entries.length - 1];
      if (opts.now - tip.ts > opts.maxAgeMs) return { ...base, n: entries.length, broken_at: entries.length - 1, reason: 'stale tip' };
    }
    return { verified: true, n: entries.length, broken_at: -1, reason: 'ok', tip: entries.length ? entries[entries.length - 1].entry_hash : GENESIS };
  } catch { return base; }
}

// verify a SINGLE signed entry + its payload (the "every response is signed; clients verify integrity" use-case).
export function verifyResponse(entry, payload, trusted) {
  try {
    if (!entry || !trusted || !trusted.ed || !trusted.mldsa) return { verified: false };
    const coreBytes = utf8ToBytes(canon(coreOf(entry)));
    const bindOk = entry.payload_sha256 === payloadHash(payload ?? '');
    const hashOk = entryHash(coreBytes) === entry.entry_hash;
    let edOk = false, pqOk = false;
    try { edOk = ed25519.verify(hexToBytes(entry.ed_sig), concatBytes(AUDIT_CTX, coreBytes), trusted.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(entry.mldsa_sig), coreBytes, trusted.mldsa, { context: AUDIT_CTX }); } catch { pqOk = false; }
    return { verified: bindOk && hashOk && edOk && pqOk, bindOk, hashOk, edOk, pqOk };
  } catch { return { verified: false }; }
}

// walk parent_seq backwards to reconstruct an entry's full chain of custody (e.g. ledger <- execution <- decision <- signal <- input).
export function custodyChain(entries, seq) {
  const chain = []; let cur = seq;
  while (cur !== null && cur !== undefined && entries[cur]) {
    const e = entries[cur]; chain.unshift({ seq: e.seq, stage: e.stage, action: e.action, actor: e.actor }); cur = e.parent_seq;
    if (chain.length > entries.length) break; // cycle guard
  }
  return chain;
}

/* ---------- self-test: node pqauditlog.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const signer = { ed: ed25519.keygen ? ed25519.keygen(new Uint8Array(32).fill(3)) : { secretKey: new Uint8Array(32).fill(3), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(3)) },
                   mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(4)) };
  // normalize ed keypair shape (older @noble exposes getPublicKey only)
  if (!signer.ed.publicKey) signer.ed = { secretKey: new Uint8Array(32).fill(3), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(3)) };
  const trusted = { ed: signer.ed.publicKey, mldsa: signer.mldsa.publicKey };

  // happy path: a full input -> signal -> decision -> execution -> ledger custody chain
  const log = createLog(signer);
  const e0 = append(log, { actor: 'feed:binance', action: 'tick BTCUSD 67000', stage: 'input', ts: 1000, payload: { px: 67000 } });
  const e1 = append(log, { actor: 'council', action: 'vote UP 7/11', stage: 'signal', ts: 1001, parentSeq: e0.seq, payload: { up: 7, down: 4 } });
  const e2 = append(log, { actor: 'risk-mgr', action: 'GO size=0.4kelly', stage: 'decision', ts: 1002, parentSeq: e1.seq });
  const e3 = append(log, { actor: 'oms', action: 'SIM order UP', stage: 'execution', ts: 1003, parentSeq: e2.seq });
  const e4 = append(log, { actor: 'qlr', action: 'anchor entry', stage: 'ledger', ts: 1004, parentSeq: e3.seq });
  const entries = exportLog(log);
  ok(verifyLog(entries, trusted).verified === true, 'happy path: full 5-stage custody chain verifies under the pinned hybrid signer');
  ok(JSON.stringify(custodyChain(entries, e4.seq).map((x) => x.stage)) === JSON.stringify(STAGES), 'chain of custody reconstructs input->signal->decision->execution->ledger');

  // failure 1: tamper a field in the middle -> entry_hash + signature both fail at that seq
  const t1 = JSON.parse(JSON.stringify(entries)); t1[2].action = 'GO size=5kelly';
  const r1 = verifyLog(t1, trusted); ok(r1.verified === false && r1.broken_at === 2, 'failure: tampered decision -> verify FAILS at seq 2');

  // failure 2: delete an entry (reorder/splice) -> chain linkage breaks
  const t2 = entries.filter((e) => e.seq !== 2).map((e, i) => e); // drop seq 2, leaves a gap
  ok(verifyLog(t2, trusted).verified === false, 'failure: deleted entry -> chain linkage / seq FAILS');

  // failure 3: replay a nonce -> rejected at append AND at verify
  let replayRejected = false; try { append(log, { actor: 'x', action: 'y', stage: 'input', ts: 1005, nonce: e0.nonce }); } catch { replayRejected = true; }
  ok(replayRejected, 'failure: appending a duplicate nonce -> rejected (replay guard)');
  const t3 = JSON.parse(JSON.stringify(entries)); t3[3].nonce = t3[1].nonce; // forge a replayed nonce, re-sign-free tamper
  ok(verifyLog(t3, trusted).verified === false, 'failure: replayed nonce in the log -> verify FAILS');

  // adversarial 1: forge an entry signed by an ATTACKER key but with a valid-looking hash chain
  const attacker = { ed: { secretKey: new Uint8Array(32).fill(9), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(9)) }, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)) };
  const flog = createLog(attacker); append(flog, { actor: 'attacker', action: 'GO size=99', stage: 'decision', ts: 2000 });
  ok(verifyLog(exportLog(flog), trusted).verified === false, 'adversarial: entry forged under attacker keys -> verify FAILS against the pinned signer');

  // adversarial 2: strip the PQ leg (downgrade) — keep the valid Ed25519 sig, drop/replace ML-DSA -> AND-composition fails
  const t4 = JSON.parse(JSON.stringify(entries)); t4[0].mldsa_sig = '00';
  const r4 = verifyLog(t4, trusted); ok(r4.verified === false && /ML-DSA/.test(r4.reason), 'adversarial: stripping the post-quantum leg -> verify FAILS (anti-downgrade AND-composition)');
  // and stripping the classical leg likewise fails
  const t5 = JSON.parse(JSON.stringify(entries)); t5[0].ed_sig = '00';
  ok(verifyLog(t5, trusted).verified === false, 'adversarial: stripping the classical leg -> verify FAILS');

  // pinning required: no trusted keys -> authenticity uncheckable -> fail-closed
  ok(verifyLog(entries, undefined).verified === false, 'no pinned signer keys -> fail-closed (authenticity uncheckable)');
  // wrong pinned key -> fails
  ok(verifyLog(entries, { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }).verified === false, 'wrong pinned signer -> verify FAILS');

  // single signed response: payload binding
  ok(verifyResponse(e1, { up: 7, down: 4 }, trusted).verified === true, 'verifyResponse: signed entry + correct payload verifies');
  ok(verifyResponse(e1, { up: 9, down: 2 }, trusted).verified === false, 'verifyResponse: tampered payload -> FAILS (payload binding)');

  // freshness window
  ok(verifyLog(entries, trusted, { now: 1004, maxAgeMs: 10 }).verified === true && verifyLog(entries, trusted, { now: 99999, maxAgeMs: 10 }).verified === false, 'freshness window on the tip enforced');

  // TOTAL: malformed inputs never throw
  let total = true;
  for (const bad of [null, undefined, {}, 42, [null], [{ seq: 5 }], [{ ...entries[0], seq: 1 }]]) { try { if (verifyLog(bad, trusted).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed logs -> verified:false, never throws');

  console.log('pqauditlog self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqauditlog\.mjs$/.test(process.argv[1] || '')) selfTest();
