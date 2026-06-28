/*!
 * pqkt — Key Transparency for issuer public keys + a monitor (reference, DRAFT, standalone).
 *
 * Closes the tracked gap "a real key-transparency log + monitors for issuer keys". Trust across the SDK rests on
 * PINNED issuer/authority keys; KT makes key lifecycle ACCOUNTABLE: bind/revoke events live in an append-only,
 * ML-DSA-87-signed Merkle log; a MONITOR proves the log never rewrote history (RFC-6962 consistency) and detects
 * equivocation/rollback.
 *
 * ISSUER AUTHORIZATION (CONIKS-style; hardened over two council rounds — Grok, then OpenAI):
 *   - Every event carries a per-issuer MONOTONIC seq, signed. resolveIssuerKey is a VERIFYING replay enforcing a
 *     strict state machine UNSEEN -> ACTIVE(key,seq) -> REVOKED with EXACT next-seq (seq = cur+1):
 *       * bootstrap (seq 0, prev=null, self-signed) accepted ONLY from UNSEEN, and ONLY if it matches an
 *         out-of-band pin (opts.expectedBootstrap) OR opts.allowTofu is explicitly set (TOFU is NOT the default).
 *       * rotation accepted only if prev_key_hex === current key, seq === cur+1, auth_sig verifies under the CURRENT
 *         key (AUTH ctx) AND possession_sig verifies under the NEW key (POSSESSION ctx — distinct contexts).
 *       * revoke accepted only if pubkey === current, seq === cur+1, auth_sig under the current key -> REVOKED.
 *     Any event failing these is IGNORED. This defeats: a log operator minting a key it doesn't control; REPLAY /
 *     reorder / duplicate / stale events (wrong seq); conflicting branches (exact-seq => first-wins); and
 *     POST-REVOKE REBIND (REVOKED is terminal — no fresh self-bootstrap can seize a revoked issuer).
 *
 * Built on pqsign's RFC-6962 log (inclusion bound to index+tree_size + consistency proofs). HONEST LIMITS:
 *  - COMPLETENESS / client-specific view: a single log can serve a victim a view that OMITS events and still be
 *    internally consistent. Detecting that needs the RP to check inclusion against an STH obtained via GOSSIP /
 *    independent WITNESSES. resolveIssuerKey assumes its `events` were drawn IN ORDER from an inclusion/STH-verified
 *    log view (the monitor + verifyKeyEventInclusion provide that); it does not itself re-bind ordering.
 *  - Re-enrollment after revoke is an explicit out-of-band policy (not auto). This is the core, not a witness network.
 *  - PRIVACY / GDPR (Mistral): an append-only PUBLIC log of `issuer_id` + key can be personal data (data-minimization
 *    / right-to-erasure vs immutability). Deployers SHOULD use pseudonymous/opaque or salted issuer_ids (never raw
 *    PII) and run a DPIA; this reference does not impose an identifier scheme (issuer_id is caller-supplied).
 *  Self-test: node pqkt.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { PQTransparencyLog, verifySTH, leafHash, entryLeafHash, verifyInclusionRFC, verifyConsistency } from './pqsign.mjs';

const AUTH_CTX = utf8ToBytes('trelyan-pqkt-auth-v1');        // authorizes the change (signed by the authorizing key)
const POSS_CTX = utf8ToBytes('trelyan-pqkt-possession-v1');  // proves possession of the NEW key (distinct context)
const keyHash = (pub) => bytesToHex(sha256(pub instanceof Uint8Array ? pub : hexToBytes(pub)));
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const coreOf = (e) => { const { auth_sig, possession_sig, ...core } = e; return core; };
const sigOk = (core, sigHex, pubHex, ctx) => { try { return ml_dsa87.verify(hexToBytes(sigHex), utf8ToBytes(canon(core)), hexToBytes(pubHex), { context: ctx }); } catch { return false; } };

/* ---------- issuer-authorized key events (the log leaves) ---------- */
export function makeBindEvent({ issuer_id, newKey, priorKey = null, seq, alg = 'ML-DSA-87', valid_from = null, ts = null }) {
  const core = { kind: 'pqkt-key-event', op: 'bind', issuer_id, alg, pubkey_hex: bytesToHex(newKey.publicKey), prev_key_hex: priorKey ? bytesToHex(priorKey.publicKey) : null, seq, valid_from, ts };
  const authKey = priorKey || newKey;
  const auth_sig = bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), authKey.secretKey, { context: AUTH_CTX }));
  const possession_sig = priorKey ? bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), newKey.secretKey, { context: POSS_CTX })) : null;
  return { ...core, auth_sig, possession_sig };
}
export function makeRevokeEvent({ issuer_id, key, seq, ts = null }) {
  const core = { kind: 'pqkt-key-event', op: 'revoke', issuer_id, alg: 'ML-DSA-87', pubkey_hex: bytesToHex(key.publicKey), prev_key_hex: bytesToHex(key.publicKey), seq, valid_from: null, ts };
  return { ...core, auth_sig: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), key.secretKey, { context: AUTH_CTX })), possession_sig: null };
}
export function appendKeyEvent(log, event) { return { index: log.append(event), event }; }

/* ---------- inclusion proof that a key event is in the signed log (RFC-bound) ---------- */
export function verifyKeyEventInclusion(arg, logPub) {
  const FAIL = { verified: false, sthOk: false, incOk: false, leafBound: false, treeSizeOk: false };
  try { // TOTAL: fail-closed on any malformed input (fuzz-robustness)
    const { event, inclusion, sth } = arg || {};
    if (!event || !inclusion || !sth) return FAIL;
    const sthOk = verifySTH(sth, logPub);
    const expectedLeaf = entryLeafHash(event);
    const leafBound = bytesToHex(expectedLeaf) === bytesToHex(inclusion.leaf);
    const treeSizeOk = inclusion.tree_size === sth.tree_size;
    const incOk = leafBound && treeSizeOk && verifyInclusionRFC(expectedLeaf, inclusion.index, sth.tree_size, (inclusion.proof || []).map((p) => p.sibling), hexToBytes(sth.root_hex));
    return { verified: sthOk && incOk, sthOk, incOk, leafBound, treeSizeOk };
  } catch { return FAIL; }
}

/* ---------- VERIFYING replay: resolve the issuer's current key (state machine + monotonic seq) ---------- */
// opts: { atTime, expectedBootstrap: <pubkey_hash hex pin>, allowTofu: false }. Returns the active key object or null.
export function resolveIssuerKey(events, issuer_id, opts = {}) {
  if (!Array.isArray(events)) return null; // TOTAL: fail-closed on a non-array event list (fuzz-robustness)
  const atTime = opts.atTime ?? Infinity;
  // ORDER INDEPENDENCE (4th sweep, state-ordering): reconstruct the true sequence from the SIGNED monotonic seq —
  // NEVER trust the log's array/append order. Otherwise a malicious log places a signed revoke (seq=2) BEFORE the
  // rotation (seq=1) it follows, the revoke fails the exact-next-seq check + is dropped -> REVOKE-ROLLBACK (a revoked
  // issuer key resolves ACTIVE). seq is signed inside the event core, so an attacker cannot forge the sort key.
  let ev;
  try { ev = events.filter((e) => e && e.kind === 'pqkt-key-event' && e.issuer_id === issuer_id).sort((a, b) => (a.seq - b.seq)); } catch { return null; }
  let state = 'unseen'; let cur = null; const rejected = []; const timeline = [];
  const mark = (e) => timeline.push({ ts: e.ts ?? -Infinity, snap: cur ? { ...cur } : null, state }); // record each accepted transition
  ev.forEach((e, index) => {
    if (!e || e.kind !== 'pqkt-key-event' || e.issuer_id !== issuer_id) return;
    const rej = (reason) => rejected.push({ index, seq: e.seq, reason });
    try { // TOTAL: a malformed leaf (e.g. non-hex pubkey_hex) is IGNORED per the contract, never thrown
      const core = coreOf(e);
      if (e.op === 'bind') {
        if (state === 'unseen') {
          const pinOk = opts.expectedBootstrap ? keyHash(e.pubkey_hex) === opts.expectedBootstrap : !!opts.allowTofu;
          if (e.prev_key_hex === null && e.seq === 0 && sigOk(core, e.auth_sig, e.pubkey_hex, AUTH_CTX) && pinOk) { cur = { pubkey_hex: e.pubkey_hex, pubkey_hash: keyHash(e.pubkey_hex), alg: e.alg, seq: 0, index, valid_from: e.valid_from, bootstrap: true }; state = 'active'; mark(e); }
          else rej(e.prev_key_hex !== null || e.seq !== 0 ? 'bad bootstrap shape (prev/seq)' : !pinOk ? 'bootstrap not pinned + TOFU not allowed' : 'bootstrap signature invalid');
        } else if (state === 'active') { // rotation: authorized by CURRENT key + possession by NEW key + exact next seq
          if (e.prev_key_hex === cur.pubkey_hex && e.seq === cur.seq + 1 && sigOk(core, e.auth_sig, cur.pubkey_hex, AUTH_CTX) && e.possession_sig && sigOk(core, e.possession_sig, e.pubkey_hex, POSS_CTX)) {
            cur = { pubkey_hex: e.pubkey_hex, pubkey_hash: keyHash(e.pubkey_hex), alg: e.alg, seq: e.seq, index, valid_from: e.valid_from, bootstrap: false }; mark(e); }
          else rej('unauthorized/stale rotation (prev/seq/auth/possession)');
        } else rej('bind after REVOKED (post-revoke rebind blocked; re-enrollment is out-of-band)');
      } else if (e.op === 'revoke') {
        if (state === 'active' && e.pubkey_hex === cur.pubkey_hex && e.seq === cur.seq + 1 && sigOk(core, e.auth_sig, cur.pubkey_hex, AUTH_CTX)) { cur = null; state = 'revoked'; mark(e); }
        else rej('unauthorized/stale revoke');
      }
    } catch { rej('malformed event'); }
  });
  // POINT-IN-TIME (4th sweep): NEVER structurally drop an event by ts during the walk — that strands the seq chain and
  // rolls back a later revoke for an atTime query. Walk the FULL signed-seq chain, then resolve atTime from the
  // transition timeline: state as-of atTime = the snapshot of the LAST accepted transition whose effective ts <= atTime.
  if (atTime !== Infinity) {
    let snap = null, snapState = 'unseen';
    for (const t of timeline) { if (t.ts <= atTime) { snap = t.snap; snapState = t.state; } }
    if (snap) { snap.state = snapState; snap.rejected = rejected; }
    return snap;
  }
  if (cur) { cur.state = state; cur.rejected = rejected; }
  return cur;
}

/* ---------- the MONITOR ---------- */
export function monitorUpdate(pinnedSTH, newSTH, consistencyProof, logPub) {
  try { // TOTAL: fail-closed (accept:false) on any malformed pinned anchor / proof element, never throw
    if (!verifySTH(newSTH, logPub)) return { accept: false, alert: 'new STH signature invalid / not the pinned log key' };
    if (newSTH.tree_size < pinnedSTH.tree_size) return { accept: false, alert: 'new STH is SMALLER than the pinned one (truncation / rollback)' };
    if (newSTH.tree_size === pinnedSTH.tree_size) return newSTH.root_hex === pinnedSTH.root_hex ? { accept: true, sameView: true } : { accept: false, alert: 'EQUIVOCATION: same tree_size, different root (split view)' };
    const proof = (consistencyProof || []).map((h) => (typeof h === 'string' ? hexToBytes(h) : h));
    const consistent = verifyConsistency(pinnedSTH.tree_size, newSTH.tree_size, hexToBytes(pinnedSTH.root_hex), hexToBytes(newSTH.root_hex), proof);
    return consistent ? { accept: true, advanced_to: newSTH.tree_size } : { accept: false, alert: 'NON-APPEND-ONLY: not a consistent extension (log rewrote history)' };
  } catch { return { accept: false, alert: 'malformed STH / consistency proof' }; }
}
export function detectEquivocation(sthA, sthB, logPub) {
  if (!verifySTH(sthA, logPub) || !verifySTH(sthB, logPub)) return { equivocation: false, reason: 'one or both STHs not validly signed by the log key' };
  if (sthA.tree_size === sthB.tree_size && sthA.root_hex !== sthB.root_hex) return { equivocation: true, reason: 'two validly-signed STHs at the same tree_size with different roots (split view)' };
  return { equivocation: false, reason: 'no same-size divergence (use monitorUpdate for cross-size consistency)' };
}
export function detectUnexpectedRotation(events, issuer_id, expectedPubkeyHash, opts = {}) {
  const cur = resolveIssuerKey(events, issuer_id, opts);
  if (!cur) return { changed: true, current: null, reason: 'issuer has NO currently-valid key (revoked / never bootstrapped / unpinned) — confirm out-of-band' };
  if (cur.pubkey_hash !== expectedPubkeyHash) return { changed: true, current: cur, reason: 'issuer key ROTATED to one you did not expect — confirm out-of-band before trusting' };
  return { changed: false, current: cur, reason: 'current key matches expectation' };
}

/* ---------- witness co-signing / gossip (NARROWS the split-view limit of a single log) ----------
 * A WITNESS independently verifies an STH and co-signs (log_pub, tree_size, root). It REFUSES to co-sign a DIFFERENT
 * root at a tree_size it already attested (local non-equivocation). verifyWitnessedSTH requires k-of-n distinct
 * trusted witness co-signatures.
 *
 * HONEST SCOPE (Hermes review — this NARROWS, does not alone CLOSE, split-view):
 *  - GOVERNANCE: split-view resistance holds only if the log controls ≤ k-1 of the n trusted witnesses (≥ n-k+1
 *    independent + honest). Weaker threshold or shared control collapses to trusting the log.
 *  - DURABILITY: the per-witness `seen` map MUST be persistent in production — a witness that restarts and loses it
 *    could re-attest a conflicting root at a known size. This reference keeps it in-memory (documented limit).
 *  - PARTITION: the local check alone does NOT stop a log that shows view A to some witnesses and view B to others
 *    (each subset co-signs its own view). GOSSIP is required: `gossipDetectEquivocation` aggregates co-signatures
 *    gathered across witnesses/relying parties and flags any tree_size attested with two distinct roots — making the
 *    partition VISIBLE. RESIDUAL owner-gated part: running ≥1 INDEPENDENT witness + an actual gossip channel.
 *  - ANCHORING: a witness's FIRST observation is trust-on-first-use; a trusted notary SHOULD be initialised with a
 *    trusted head (`makeWitness(seed, {anchor:{size,root}})`) or set `{requireAnchor:true}` to refuse pre-anchor TOFU.
 *    `seen`/`last` MUST be durable across restarts. OPTIONAL defence-in-depth (not implemented): an STH-freshness
 *    window to avoid being pinned to a stale-but-consistent branch. */
const WITNESS_CTX = utf8ToBytes('trelyan-pqkt-witness-v1');
const witnessMsg = (logPubHex, tree_size, root_hex) => utf8ToBytes(canon({ log_pub: logPubHex.toLowerCase(), tree_size, root: root_hex }));

export class Witness {
  // opts.anchor = {size, root} trusted starting head (out-of-band); opts.requireAnchor refuses first-observation TOFU.
  constructor(secretKey, publicKey, opts = {}) {
    this.secretKey = secretKey; this.publicKey = publicKey; this.seen = new Map(); this.last = null; this.requireAnchor = !!opts.requireAnchor; // seen/last PERSIST in prod
    if (opts.anchor) { this.last = { size: opts.anchor.size, root: opts.anchor.root }; this.seen.set(opts.anchor.size, opts.anchor.root); }
  }
  // verify STH + (a) refuse a conflicting same-size root, (b) — DeepSeek fix — refuse a head that is NOT an append-only
  // extension of THIS witness's last-signed head (no fork-following; caller supplies the RFC-6962 consistency proof),
  // (c) — DeepSeek follow-up — optionally refuse first-observation TOFU (a trusted notary should be anchored).
  cosign(sth, logPub, consistencyProof) {
    if (this.requireAnchor && !this.last) return { ok: false, reason: 'witness not anchored to a trusted head (refusing first-observation TOFU)' };
    if (!verifySTH(sth, logPub)) return { ok: false, reason: 'STH not validly signed by the log key' };
    const prior = this.seen.get(sth.tree_size);
    if (prior && prior !== sth.root_hex) return { ok: false, equivocation: true, reason: 'EQUIVOCATION: a different root at tree_size ' + sth.tree_size + ' than this witness already co-signed' };
    if (this.last && !prior && sth.tree_size !== this.last.size) {
      const [m, n, rm, rn] = sth.tree_size > this.last.size ? [this.last.size, sth.tree_size, this.last.root, sth.root_hex] : [sth.tree_size, this.last.size, sth.root_hex, this.last.root];
      const proof = (consistencyProof || []).map((h) => (typeof h === 'string' ? hexToBytes(h) : h));
      if (!verifyConsistency(m, n, hexToBytes(rm), hexToBytes(rn), proof)) return { ok: false, fork: true, reason: 'INCONSISTENT: proposed head is not an append-only extension of this witness’s last-signed head (fork)' };
    }
    this.seen.set(sth.tree_size, sth.root_hex);
    if (!this.last || sth.tree_size > this.last.size) this.last = { size: sth.tree_size, root: sth.root_hex };
    // cosig is SELF-DESCRIBING (carries size+root) so gossip can detect cross-witness equivocation
    return { ok: true, cosig: { witness_pub: bytesToHex(this.publicKey), tree_size: sth.tree_size, root_hex: sth.root_hex, sig: bytesToHex(ml_dsa87.sign(witnessMsg(bytesToHex(logPub), sth.tree_size, sth.root_hex), this.secretKey, { context: WITNESS_CTX })) } };
  }
}
export function makeWitness(seed, opts = {}) { const kp = ml_dsa87.keygen(seed); return new Witness(kp.secretKey, kp.publicKey, opts); }

// require the STH to be log-signed AND co-signed by >= k DISTINCT trusted witnesses.
export function verifyWitnessedSTH(sth, logPub, cosigs, trustedWitnessPubs, k = 1) {
 try { // TOTAL (fuzz): throwing getter/Proxy/BigInt in sth or a cosig fails CLOSED, never DoS
  const sthOk = verifySTH(sth, logPub);
  const trusted = (Array.isArray(trustedWitnessPubs) ? trustedWitnessPubs : []).map((p) => bytesToHex(p).toLowerCase());
  const seen = new Set();
  for (const c of Array.isArray(cosigs) ? cosigs : []) { // TOTAL: tolerate a non-array cosig list (fuzz-robustness)
    try {
      const wp = (c && c.witness_pub || '').toLowerCase();
      if (!trusted.includes(wp) || seen.has(wp)) continue;
      if (c.tree_size !== sth.tree_size || c.root_hex !== sth.root_hex) continue; // cosig must attest THIS STH
      let ok = false; try { ok = ml_dsa87.verify(hexToBytes(c.sig), witnessMsg(bytesToHex(logPub), c.tree_size, c.root_hex), hexToBytes(c.witness_pub), { context: WITNESS_CTX }); } catch { ok = false; }
      if (ok) seen.add(wp);
    } catch { /* skip a malformed/adversarial cosig */ }
  }
  return { verified: sthOk && seen.size >= k, sthOk, witness_count: seen.size, threshold: k };
 } catch { return { verified: false, sthOk: false, witness_count: 0, threshold: k }; }
}

// GOSSIP detector: given co-signatures gathered across witnesses/RPs, flag any tree_size attested with two distinct
// roots — this catches a log that PARTITIONED witnesses into conflicting views (which k-of-n alone cannot).
export function gossipDetectEquivocation(cosigs, logPub, trustedWitnessPubs) {
  if (!Array.isArray(cosigs)) return { equivocation: false, reason: 'no co-signatures' }; // TOTAL (fuzz-robustness)
  const trusted = (trustedWitnessPubs || []).map((p) => bytesToHex(p).toLowerCase());
  const bySize = new Map(); // tree_size -> Set(root_hex) from VALID trusted cosigs
  for (const c of cosigs) {
    if (!c || typeof c !== 'object') continue; // TOTAL: skip non-object cosig elements (fuzz-robustness)
    if (trusted.length && !trusted.includes((c.witness_pub || '').toLowerCase())) continue;
    let ok = false; try { ok = ml_dsa87.verify(hexToBytes(c.sig), witnessMsg(bytesToHex(logPub), c.tree_size, c.root_hex), hexToBytes(c.witness_pub), { context: WITNESS_CTX }); } catch { ok = false; }
    if (!ok) continue;
    if (!bySize.has(c.tree_size)) bySize.set(c.tree_size, new Set());
    bySize.get(c.tree_size).add(c.root_hex);
  }
  for (const [tree_size, roots] of bySize) if (roots.size > 1) return { equivocation: true, tree_size, roots: [...roots], reason: 'two distinct roots co-signed at the same tree_size (log partitioned witnesses)' };
  return { equivocation: false, reason: 'no conflicting roots across the gathered co-signatures' };
}

/* ---------- self-test: node pqkt.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(71));
  const A = ml_dsa87.keygen(new Uint8Array(32).fill(72));
  const Anew = ml_dsa87.keygen(new Uint8Array(32).fill(73));
  const attacker = ml_dsa87.keygen(new Uint8Array(32).fill(99));
  const pinA = keyHash(A.publicKey);
  const log = new PQTransparencyLog();

  // 1. bootstrap bind for issuer A (seq 0, self-signed) + RFC-bound inclusion
  const { index: idxBind } = appendKeyEvent(log, makeBindEvent({ issuer_id: 'issuer:A', newKey: A, seq: 0, ts: 1000 }));
  appendKeyEvent(log, makeBindEvent({ issuer_id: 'issuer:B', newKey: ml_dsa87.keygen(new Uint8Array(32).fill(80)), seq: 0, ts: 1001 }));
  const sth1 = log.signedTreeHead(logKey.secretKey, { ts: 2000 });
  ok(verifyKeyEventInclusion({ event: log.entries[idxBind], inclusion: log.inclusion(idxBind), sth: sth1 }, logKey.publicKey).verified === true, 'bootstrap bind event included in the signed KT log');

  // 2. BOOTSTRAP PINNING (OpenAI fix): TOFU is NOT the default
  ok(resolveIssuerKey(log.entries, 'issuer:A') === null, 'no pin + no allowTofu -> bootstrap NOT auto-trusted (TOFU off by default)');
  ok(resolveIssuerKey(log.entries, 'issuer:A', { expectedBootstrap: pinA }).pubkey_hash === pinA, 'bootstrap matching the out-of-band PIN -> resolves');
  ok(resolveIssuerKey(log.entries, 'issuer:A', { expectedBootstrap: keyHash(attacker.publicKey) }) === null, 'bootstrap NOT matching the pin -> rejected');
  ok(resolveIssuerKey(log.entries, 'issuer:A', { allowTofu: true }).pubkey_hash === pinA, 'explicit allowTofu -> bootstrap resolves');
  const opt = { expectedBootstrap: pinA };

  // 3. AUTHORIZED rotation A->Anew (seq 1, prev=A, possession by Anew)
  appendKeyEvent(log, makeBindEvent({ issuer_id: 'issuer:A', newKey: Anew, priorKey: A, seq: 1, ts: 1100 }));
  ok(resolveIssuerKey(log.entries, 'issuer:A', opt).pubkey_hash === keyHash(Anew.publicKey), 'authorized rotation (seq1) -> resolves to NEW key');

  // 4. REPLAY (OpenAI fix): re-append the SAME old A->Anew rotation -> stale seq -> IGNORED
  appendKeyEvent(log, makeBindEvent({ issuer_id: 'issuer:A', newKey: Anew, priorKey: A, seq: 1, ts: 1101 }));
  ok(resolveIssuerKey(log.entries, 'issuer:A', opt).seq === 1, 'replayed old rotation (stale seq) -> IGNORED (no rollback)');

  // 5. ROGUE operator bind (no authority over A) -> ignored
  appendKeyEvent(log, makeBindEvent({ issuer_id: 'issuer:A', newKey: attacker, priorKey: attacker, seq: 2, ts: 1200 }));
  ok(resolveIssuerKey(log.entries, 'issuer:A', opt).pubkey_hash === keyHash(Anew.publicKey), 'rogue operator bind (not authorized by current key) -> IGNORED');

  // 6. CONTEXT SEPARATION (OpenAI fix): swap auth_sig <-> possession_sig on a valid rotation -> rejected
  const A2 = ml_dsa87.keygen(new Uint8Array(32).fill(74));
  const rot = makeBindEvent({ issuer_id: 'issuer:X', newKey: A2, priorKey: A, seq: 1, ts: 1 });
  // bootstrap X with A first so there is a current key A for issuer:X
  const logX = new PQTransparencyLog();
  appendKeyEvent(logX, makeBindEvent({ issuer_id: 'issuer:X', newKey: A, seq: 0, ts: 0 }));
  const swapped = { ...rot, auth_sig: rot.possession_sig, possession_sig: rot.auth_sig };
  appendKeyEvent(logX, swapped);
  ok(resolveIssuerKey(logX.entries, 'issuer:X', { expectedBootstrap: pinA }).pubkey_hash === pinA, 'auth/possession sigs swapped (distinct contexts) -> rotation REJECTED, key unchanged');

  // 7. AUTHORIZED revoke (seq 2) by the current key -> REVOKED (terminal)
  appendKeyEvent(log, makeRevokeEvent({ issuer_id: 'issuer:A', key: Anew, seq: 2, ts: 1300 }));
  ok(resolveIssuerKey(log.entries, 'issuer:A', opt) === null, 'authorized revoke -> issuer has no valid key (REVOKED)');

  // 7b. REVOKE-ROLLBACK regression (4th sweep, state-ordering): a malicious log that REORDERS a signed revoke before
  // the rotation it follows must NOT resurrect the key — resolveIssuerKey sorts by the SIGNED seq (unforgeable).
  const Rk = ml_dsa87.keygen(new Uint8Array(32).fill(77)), Rk2 = ml_dsa87.keygen(new Uint8Array(32).fill(78));
  const rPin = keyHash(Rk.publicKey);
  const e0 = makeBindEvent({ issuer_id: 'issuer:R', newKey: Rk, seq: 0, ts: 1 });
  const e1 = makeBindEvent({ issuer_id: 'issuer:R', newKey: Rk2, priorKey: Rk, seq: 1, ts: 2 });
  const e2 = makeRevokeEvent({ issuer_id: 'issuer:R', key: Rk2, seq: 2, ts: 3 });
  ok(resolveIssuerKey([e0, e1, e2], 'issuer:R', { expectedBootstrap: rPin }) === null, 'honest order [bind,rot,revoke] -> REVOKED');
  ok(resolveIssuerKey([e0, e2, e1], 'issuer:R', { expectedBootstrap: rPin }) === null, 'REORDERED [bind,revoke,rot] -> STILL REVOKED (sort-by-signed-seq defeats the rollback)');
  ok(resolveIssuerKey([e2, e1, e0], 'issuer:R', { expectedBootstrap: rPin }) === null, 'fully shuffled -> STILL REVOKED');
  // 7c. atTime + NON-MONOTONIC ts (4th sweep, resume): a future-dated rotation must NOT strand a later revoke for a
  // point-in-time query (the atTime filter previously broke the seq chain -> revoke dropped -> key resurrected).
  const Sk = ml_dsa87.keygen(new Uint8Array(32).fill(79)), Sk2 = ml_dsa87.keygen(new Uint8Array(32).fill(80));
  const sPin = keyHash(Sk.publicKey);
  const s0 = makeBindEvent({ issuer_id: 'issuer:S', newKey: Sk, seq: 0, ts: 1000 });
  const s1 = makeBindEvent({ issuer_id: 'issuer:S', newKey: Sk2, priorKey: Sk, seq: 1, ts: 2000 }); // FUTURE-dated rotation
  const s2 = makeRevokeEvent({ issuer_id: 'issuer:S', key: Sk2, seq: 2, ts: 1500 });                 // revoke ts < rotation ts
  ok(resolveIssuerKey([s0, s1, s2], 'issuer:S', { expectedBootstrap: sPin, atTime: 1700 }) === null, 'atTime=1700 w/ non-monotonic ts -> REVOKED (no atTime-strand rollback)');
  ok(resolveIssuerKey([s0, s1, s2], 'issuer:S', { expectedBootstrap: sPin, atTime: 1200 }).pubkey_hash === sPin, 'atTime=1200 (before rotation/revoke) -> historical bootstrap key K0');

  // 8. POST-REVOKE REBIND ATTACK (OpenAI critical fix): attacker appends a fresh self-signed bootstrap -> IGNORED
  appendKeyEvent(log, makeBindEvent({ issuer_id: 'issuer:A', newKey: attacker, seq: 0, ts: 1400 }));
  ok(resolveIssuerKey(log.entries, 'issuer:A', { allowTofu: true }) === null, 'post-revoke fresh bootstrap by an attacker -> IGNORED (REVOKED is terminal)');

  // 9. monitor: consistent append-only extension accepted; rollback + rewrite + equivocation rejected
  const sth2 = log.signedTreeHead(logKey.secretKey, { ts: 2001 });
  const cons = log.consistency(sth1.tree_size);
  ok(monitorUpdate(sth1, sth2, cons.proof.map(bytesToHex), logKey.publicKey).accept === true, 'monitor accepts a consistent (append-only) STH extension');
  ok(monitorUpdate(sth2, sth1, [], logKey.publicKey).accept === false, 'monitor rejects a SMALLER new STH (rollback)');
  ok(monitorUpdate({ ...sth1, root_hex: bytesToHex(sha256(utf8ToBytes('forged'))) }, sth2, cons.proof.map(bytesToHex), logKey.publicKey).accept === false, 'monitor rejects an inconsistent extension (rewrite caught)');
  const fork = { tree_size: sth2.tree_size, root_hex: bytesToHex(sha256(utf8ToBytes('other-view'))), ts: sth2.ts };
  fork.sig = bytesToHex(ml_dsa87.sign(utf8ToBytes(JSON.stringify({ tree_size: fork.tree_size, root: fork.root_hex, ts: fork.ts })), logKey.secretKey, { context: utf8ToBytes('trelyan-pqsign-sth-v1') }));
  ok(detectEquivocation(sth2, fork, logKey.publicKey).equivocation === true, 'EQUIVOCATION detected (same size, different root, both signed)');

  // 10. WITNESS co-signing closes split-view: honest witnesses co-sign the real STH and REFUSE the fork
  const w1 = makeWitness(new Uint8Array(32).fill(40)), w2 = makeWitness(new Uint8Array(32).fill(41));
  const c1 = w1.cosign(sth2, logKey.publicKey), c2 = w2.cosign(sth2, logKey.publicKey);
  ok(c1.ok && c2.ok, 'two independent witnesses co-sign the real STH');
  ok(verifyWitnessedSTH(sth2, logKey.publicKey, [c1.cosig, c2.cosig], [w1.publicKey, w2.publicKey], 2).verified === true, '2-of-2 witnessed STH verifies (split-view resistant)');
  ok(verifyWitnessedSTH(sth2, logKey.publicKey, [c1.cosig], [w1.publicKey, w2.publicKey], 2).verified === false, 'only 1 witness co-sig -> 2-of-2 threshold NOT met');
  // the equivocating fork at the same size: a witness that already co-signed sth2 REFUSES the fork
  const refuse = w1.cosign(fork, logKey.publicKey);
  ok(refuse.ok === false && refuse.equivocation === true, 'a witness REFUSES to co-sign a different root at a size it already attested (catches the log equivocating)');
  ok(verifyWitnessedSTH(fork, logKey.publicKey, [], [w1.publicKey, w2.publicKey], 1).verified === false, 'the fork view cannot gather any witness co-signature -> NOT a witnessed STH');
  // an untrusted witness key does not count toward the threshold
  const wEvil = makeWitness(new Uint8Array(32).fill(42)); const cEvil = wEvil.cosign(sth2, logKey.publicKey);
  ok(verifyWitnessedSTH(sth2, logKey.publicKey, [cEvil.cosig], [w1.publicKey, w2.publicKey], 1).verified === false, 'a co-sig from an untrusted witness does not count');

  // 11. PARTITION attack (Hermes fix): the log shows view A to w1 and view B (fork) to a FRESH witness w3 — each
  // co-signs its own view (NO local catch). GOSSIP aggregating both cosigs detects the same-size/different-root conflict.
  const w3 = makeWitness(new Uint8Array(32).fill(43));
  const cB = w3.cosign(fork, logKey.publicKey); // w3 never saw sth2 -> co-signs the fork locally
  ok(cB.ok === true, 'a partitioned (fresh) witness locally co-signs the fork — local checks alone miss the partition');
  ok(gossipDetectEquivocation([c1.cosig, cB.cosig], logKey.publicKey, [w1.publicKey, w3.publicKey]).equivocation === true, 'GOSSIP detects the partition: same tree_size co-signed with two distinct roots');
  ok(gossipDetectEquivocation([c1.cosig, c2.cosig], logKey.publicKey, [w1.publicKey, w2.publicKey]).equivocation === false, 'consistent co-signatures across witnesses -> no equivocation flagged');

  // 12. WITNESS APPEND-ONLY (DeepSeek fix): a witness co-signs an earlier head, then is offered a LARGER head.
  const w4 = makeWitness(new Uint8Array(32).fill(44));
  ok(w4.cosign(sth1, logKey.publicKey).ok === true, 'witness co-signs the size-S1 head (first observation)');
  // (a) the REAL consistent extension to sth2 is accepted (consistency proof verifies)
  ok(w4.cosign(sth2, logKey.publicKey, log.consistency(sth1.tree_size).proof.map(bytesToHex)).ok === true, 'consistent append-only extension S1->S2 accepted');
  // (b) a FORK: a validly log-signed head at a NEW larger size whose root is NOT consistent with S1 -> refused
  const w5 = makeWitness(new Uint8Array(32).fill(45));
  w5.cosign(sth1, logKey.publicKey);
  const forkBig = { tree_size: sth2.tree_size + 5, root_hex: bytesToHex(sha256(utf8ToBytes('forked-branch-root'))), ts: 9 };
  forkBig.sig = bytesToHex(ml_dsa87.sign(utf8ToBytes(JSON.stringify({ tree_size: forkBig.tree_size, root: forkBig.root_hex, ts: forkBig.ts })), logKey.secretKey, { context: utf8ToBytes('trelyan-pqsign-sth-v1') }));
  const forkRes = w5.cosign(forkBig, logKey.publicKey, []);
  ok(forkRes.ok === false && forkRes.fork === true, 'witness REFUSES a larger head that is NOT a consistent extension of its last-signed head (fork-following blocked)');

  // 13. WITNESS ANCHORING (DeepSeek follow-up): no first-observation TOFU for a trusted notary
  ok(makeWitness(new Uint8Array(32).fill(46), { requireAnchor: true }).cosign(sth1, logKey.publicKey).ok === false, 'requireAnchor witness refuses to co-sign before being anchored (no first-observation TOFU)');
  const wAnch = makeWitness(new Uint8Array(32).fill(47), { anchor: { size: sth1.tree_size, root: sth1.root_hex } });
  ok(wAnch.cosign(sth2, logKey.publicKey, log.consistency(sth1.tree_size).proof.map(bytesToHex)).ok === true, 'anchored witness co-signs a consistent extension of its trusted anchor');
  ok(wAnch.cosign(forkBig, logKey.publicKey, []).fork === true, 'anchored witness refuses a fork inconsistent with its anchor');

  console.log('pqkt self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqkt\.mjs$/.test(process.argv[1] || '')) selfTest();
