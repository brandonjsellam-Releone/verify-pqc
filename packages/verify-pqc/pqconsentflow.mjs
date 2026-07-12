/*!
 * pqconsentflow — VaultHealth consent-LIFECYCLE engine (reference, DRAFT). The thing a data controller needs on top
 * of a single pqconsent receipt: a tamper-evident, CONTROLLER-signed log of the consent lifecycle — grant → access
 * events → withdrawal — that a data subject (or a regulator) can verify, and that cryptographically EVIDENCES a
 * GDPR violation (the controller accessing the data AFTER the subject withdrew, or outside the granted scope).
 *
 * Two signers, never conflated: the SUBJECT signs consent (the embedded pqconsent grant + revocation, verified under
 * the pinned subject); the CONTROLLER signs each LOG ENTRY (a non-repudiable attestation of what it did and when).
 * The hash chain binds order; withdrawal is final. verifyConsentFlow RECOMPUTES the permitted state from the signed
 * entries and surfaces VIOLATIONS — it returns `verified` (the chain is authentic + well-formed) separately from
 * `compliant` (no violation evidenced), so a violating-but-authentic log is exactly the evidence the subject wants.
 *
 * HONEST SCOPE: this is verifiable EVIDENCE of consent + access + withdrawal — not access ENFORCEMENT (the controller's
 * systems must actually honor a withdrawal; this proves whether they did). A "consent receipt" is evidence, NOT a legal
 * determination of valid consent. RESIDUAL (self-attested log, DeepSeek-reviewed): the access log is the CONTROLLER's —
 * it is non-repudiable (once signed it cannot be denied) and the subject's grant/revocation are bound, but a fully
 * malicious controller can still under-report by back-dating an access to BEFORE the subject's revoked_at, or by omitting
 * the withdrawal entirely. Detection binds to the SUBJECT-signed revoked_at (not chain position), and `opts.knownRevokedAt`
 * lets a subject/regulator who holds their own revocation flag a back-dated/withheld withdrawal — but completeness of a
 * self-maintained log ultimately needs the subject's independent copy (the documented deny-list-propagation residual).
 * Unaudited reference. Self-test: node pqconsentflow.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { verifyConsent, verifyConsentRevocation, makeSubjectId } from './pqconsent.mjs';

const CF_CTX = utf8ToBytes('trelyan-consent-flow-v1');         // controller-signing domain (Ed25519 + ML-DSA legs)
const CF_SLH_CTX = utf8ToBytes('trelyan-consent-flow-slh-v1'); // distinct domain for the optional SLH leg

function canon(v) {
  if (v === undefined) return 'null';
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
const h = (s) => bytesToHex(sha256(utf8ToBytes(s)));

export function makeControllerId(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('controller keys must be { ed, mldsa[, slh] }');
  return 'controller:trelyan:' + bytesToHex(sha256(concatBytes(utf8ToBytes('controller:trelyan:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}

const entryCore = (e) => ({ v: '1', seq: e.seq, prev_hash: e.prev_hash, type: e.type, receipt_id: e.receipt_id, purpose: e.purpose ?? null, category: e.category ?? null, nonce: e.nonce, embed_sha256: e.embed_sha256 ?? null, controller: e.controller, at: e.at ?? null });

function signEntry(core, controllerKeys) {
  const coreBytes = utf8ToBytes(canon(core));
  const sig = { controller_pub: { ed: bytesToHex(_pub(controllerKeys.ed)), mldsa: bytesToHex(_pub(controllerKeys.mldsa)) }, slh_signer_pub_hex: controllerKeys.slh ? bytesToHex(_pub(controllerKeys.slh)) : null,
    ed_sig: bytesToHex(ed25519.sign(concatBytes(CF_CTX, coreBytes), controllerKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, controllerKeys.mldsa.secretKey, { context: CF_CTX })) };
  if (controllerKeys.slh) { sig.controller_pub.slh = bytesToHex(_pub(controllerKeys.slh)); sig.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, controllerKeys.slh.secretKey, { context: CF_SLH_CTX })); }
  return { ...core, ...sig, entry_hash: h(canon(core)) };
}
function verifyEntrySig(entry, controllerPub) {
  const coreBytes = utf8ToBytes(canon(entryCore(entry)));
  let edOk = false, pqOk = false, slhOk = true;
  try { edOk = ed25519.verify(hexToBytes(entry.ed_sig), concatBytes(CF_CTX, coreBytes), controllerPub.ed); } catch { edOk = false; }
  try { pqOk = ml_dsa87.verify(hexToBytes(entry.mldsa_sig), coreBytes, controllerPub.mldsa, { context: CF_CTX }); } catch { pqOk = false; }
  if (controllerPub.slh) { try { slhOk = !!(entry.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(entry.slh_sig), coreBytes, controllerPub.slh, { context: CF_SLH_CTX })); } catch { slhOk = false; } }
  return edOk && pqOk && slhOk;
}

// open a lifecycle log on a VERIFIED pqconsent receipt. subjectPub pins the data subject. The CONTROLLER maintains the log.
export function openConsentFlow({ receipt, subjectPub, controllerKeys, at = null }) {
  if (!controllerKeys || !controllerKeys.ed || !controllerKeys.mldsa) throw new Error('controllerKeys must be { ed, mldsa[, slh] }');
  if (!receipt || receipt.subject !== makeSubjectId(subjectPub)) throw new Error('receipt subject != pinned subject');
  if (!verifyConsent(receipt, { now: at }).verified) throw new Error('cannot open a flow on an UNVERIFIED consent receipt (fail-dangerous)');
  const controller = makeControllerId(controllerKeys);
  const core = entryCore({ seq: 0, prev_hash: null, type: 'grant', receipt_id: receipt.receipt_id, nonce: receipt.nonce, embed_sha256: h(canon(receipt)), controller, at });
  const genesis = { ...signEntry(core, controllerKeys), receipt };
  return { v: '1', receipt_id: receipt.receipt_id, controller, subject: receipt.subject, entries: [genesis] };
}

function foldState(entries, opts = {}) {
  if (!Array.isArray(entries) || entries.length === 0 || entries[0].type !== 'grant') return { valid: false, error: 'genesis not a grant' };
  // The authoritative "after withdrawal" time is the SUBJECT-signed revoked_at (from the embedded revocation), NOT the
  // controller-chosen chain position or entry `at` — both of which the controller could reorder/back-date. We also fold
  // in any out-of-band known revocation time the verifier supplies (opts.knownRevokedAt), which lets a subject/regulator
  // who holds their own revocation detect a controller that reordered, back-dated, or WITHHELD the withdrawal.
  // FINITE-TIME INVARIANT (fix-verif 1 Jul). Two axes must carry a FINITE timestamp, enforced at the honest API
  // (logAccess/withdraw) and re-checked in verifyConsentFlow for hand-crafted entries:
  //   • every access `at`  — an untimestamped access is unauditable and is exactly how a controller dodges the revoked-at
  //     compare (slip a post-revocation access with at:null before the withdraw entry). It is now ALWAYS a hard violation,
  //     which removes the earlier null-`at`-vs-honest ambiguity (no false-positive on honest logs, since honest logs are
  //     always timestamped; no evasion, since a null `at` is flagged regardless of ordering).
  //   • the subject-signed `revoked_at` — a null/NaN revoked_at previously left effectiveRevokedAt null/NaN and SILENTLY
  //     disabled the whole revoked-at compare (a post-revocation access before the withdraw entry then passed). Non-finite
  //     revoked_at is rejected upstream, and Number.isFinite guards here so a coerced NaN can never disable the guard.
  let subjectRevokedAt = null, hasWithdraw = false;
  for (const e of entries) if (e && e.type === 'withdraw') { hasWithdraw = true; const rt = e.revocation && e.revocation.revoked_at; if (Number.isFinite(rt) && (subjectRevokedAt == null || rt < subjectRevokedAt)) subjectRevokedAt = rt; }
  const known = Number.isFinite(opts.knownRevokedAt) ? opts.knownRevokedAt : null;
  const effectiveRevokedAt = [subjectRevokedAt, known].filter((x) => Number.isFinite(x)).reduce((a, b) => (a == null ? b : Math.min(a, b)), null);
  let status = 'open', withdrawn_at = null; const accesses = []; const violations = [];
  for (let i = 1; i < entries.length; i++) {
    const e = entries[i];
    if (e.type === 'access') {
      accesses.push({ purpose: e.purpose, category: e.category, at: e.at });
      if (!Number.isFinite(e.at)) violations.push({ kind: 'access-missing-timestamp', basis: 'untimestamped', at: e.at ?? null, purpose: e.purpose, category: e.category });
      else if (status === 'withdrawn') violations.push({ kind: 'access-after-withdrawal', basis: 'chain-position', at: e.at, purpose: e.purpose, category: e.category });
      else if (effectiveRevokedAt != null && e.at >= effectiveRevokedAt) violations.push({ kind: 'access-after-withdrawal', basis: 'revoked-at', at: e.at, purpose: e.purpose, category: e.category });
    } else if (e.type === 'withdraw') {
      if (status === 'withdrawn') return { valid: false, error: 'double withdrawal' };
      status = 'withdrawn'; withdrawn_at = e.at;
    } else return { valid: false, error: 'unknown entry type: ' + e.type };
  }
  // Completeness: a verifier that KNOWS the subject revoked (out-of-band) but sees NO withdraw entry = the controller is
  // withholding the withdrawal (the deny-list-propagation residual — now DETECTED when the known revocation is supplied).
  if (known != null && !hasWithdraw) violations.push({ kind: 'withheld-withdrawal', knownRevokedAt: known });
  return { valid: true, status, withdrawn_at, subject_revoked_at: subjectRevokedAt, accesses, violations };
}

function append(flow, core, controllerKeys, extra = {}) {
  const prev = flow.entries[flow.entries.length - 1];
  const full = { ...core, seq: flow.entries.length, prev_hash: prev.entry_hash, controller: makeControllerId(controllerKeys) };
  flow.entries.push({ ...signEntry(entryCore(full), controllerKeys), ...extra });
  return flow;
}

// the controller logs an access. FAIL-DANGEROUS: refuses an out-of-scope access (purpose/category not granted) and an
// access after withdrawal — so an HONEST controller's log never contains a violation; a malicious one's is caught at verify.
export function logAccess(flow, { purpose, category, controllerKeys, nonce, at = null }) {
  const st = foldState(flow.entries);
  if (!st.valid) throw new Error('flow invalid: ' + st.error);
  if (st.status === 'withdrawn') throw new Error('consent withdrawn — no further access permitted');
  if (!Number.isFinite(at)) throw new Error('a finite access timestamp `at` is required — an untimestamped consent access is unauditable (fail-closed ordering)');
  const receipt = flow.entries[0].receipt;
  if (!verifyConsent(receipt, { purpose, category, now: at }).verified) throw new Error('access is OUTSIDE the granted scope (purpose/category not consented)');
  if (nonce == null) throw new Error('a fresh nonce is required');
  if (flow.entries.some((e) => e.type === 'access' && String(e.nonce) === String(nonce))) throw new Error('access nonce already used');
  return append(flow, { type: 'access', receipt_id: flow.receipt_id, purpose: String(purpose), category: String(category), nonce: String(nonce), at }, controllerKeys);
}

// the subject withdraws (a pqconsent revocation, verified under the pinned subject). After this, no access is permitted.
export function withdraw(flow, { revocation, subjectPub, controllerKeys, nonce, at = null }) {
  if (!revocation || revocation.subject !== makeSubjectId(subjectPub)) throw new Error('revocation subject != pinned subject');
  if (revocation.receipt_id !== flow.receipt_id) throw new Error('revocation does not match this consent (receipt_id)');
  if (!verifyConsentRevocation(revocation, flow.subject).verified) throw new Error('cannot record an UNVERIFIED withdrawal (fail-dangerous)');
  if (!Number.isFinite(revocation.revoked_at)) throw new Error('revocation must carry a finite subject-signed revoked_at — a consent-flow withdrawal without a timestamp cannot anchor access-after-withdrawal (fail-closed)');
  return append(flow, { type: 'withdraw', receipt_id: flow.receipt_id, nonce: String(nonce ?? ('w-' + flow.entries.length)), embed_sha256: h(canon(revocation)), at }, controllerKeys, { revocation });
}

// TOTAL / fail-closed. Verifies the chain + every entry's controller signature + the embedded subject artifacts (grant
// receipt + withdrawal revocation, under the pinned subject), then RECOMPUTES the permitted state and the violations.
// Returns { verified (chain authentic + well-formed), compliant (no violation), violations, state }.
export function verifyConsentFlow(flow, subjectPub, controllerPub, opts = {}) {
  try {
    if (!flow || typeof flow !== 'object' || !Array.isArray(flow.entries) || !flow.entries.length) return { verified: false };
    if (!subjectPub || !subjectPub.ed || !subjectPub.mldsa || !controllerPub || !controllerPub.ed || !controllerPub.mldsa) return { verified: false };
    const controllerId = makeControllerId(controllerPub);
    // bind the top-level header convenience copies to the pinned parties (no unsigned trust surface above the entries)
    if (flow.v !== '1' || typeof flow.receipt_id !== 'string' || flow.controller !== controllerId || flow.subject !== makeSubjectId(subjectPub)) return { verified: false, reason: 'flow header does not match the pinned parties' };
    let prevHash = null; const nonces = new Set();
    for (let i = 0; i < flow.entries.length; i++) {
      const e = flow.entries[i];
      if (e.seq !== i || e.prev_hash !== prevHash) return { verified: false, reason: 'chain broken at ' + i };
      if (e.entry_hash !== h(canon(entryCore(e)))) return { verified: false, reason: 'entry_hash mismatch at ' + i };
      if (e.controller !== controllerId) return { verified: false, reason: 'entry not by the pinned controller at ' + i };
      if (!verifyEntrySig(e, controllerPub)) return { verified: false, reason: 'controller signature invalid at ' + i };
      if (e.receipt_id !== flow.receipt_id) return { verified: false, reason: 'receipt_id mismatch at ' + i };
      if (e.type === 'access') { if (nonces.has(String(e.nonce))) return { verified: false, reason: 'duplicate access nonce at ' + i }; nonces.add(String(e.nonce)); }
      prevHash = e.entry_hash;
    }
    // genesis: a real pqconsent grant by the pinned subject, bound into the chain
    const g = flow.entries[0];
    if (g.type !== 'grant' || !g.receipt) return { verified: false, reason: 'genesis is not a grant with an embedded receipt' };
    if (g.embed_sha256 !== h(canon(g.receipt))) return { verified: false, reason: 'embedded receipt hash != bound embed_sha256' };
    if (g.receipt.subject !== makeSubjectId(subjectPub)) return { verified: false, reason: 'grant subject != pinned subject' };
    // the grant's signature + scope are checked here; temporal validity is enforced PER-ACCESS (now: e.at below), so a
    // historical log with no single "now" verifies the genesis without a clock (the leaf's strict-clock guard is waived here).
    if (!verifyConsent(g.receipt, { now: opts.now, allowNoExpiryClock: true }).verified || g.receipt.receipt_id !== flow.receipt_id) return { verified: false, reason: 'embedded consent receipt invalid' };
    // each access must be in the granted scope; each withdraw must carry a valid revocation by the pinned subject
    for (let i = 1; i < flow.entries.length; i++) {
      const e = flow.entries[i];
      if (e.type === 'access') {
        // bind the access TIME into the scope check — an access after the grant's expiry is out-of-scope, not silently ok
        if (!verifyConsent(g.receipt, { purpose: e.purpose, category: e.category, now: e.at == null ? undefined : e.at }).verified) return { verified: false, reason: 'access ' + i + ' is outside the granted scope (purpose/category/validity)' };
      } else if (e.type === 'withdraw') {
        if (!e.revocation || e.embed_sha256 !== h(canon(e.revocation))) return { verified: false, reason: 'withdraw ' + i + ' embedded revocation hash mismatch' };
        if (e.revocation.subject !== makeSubjectId(subjectPub) || e.revocation.receipt_id !== flow.receipt_id) return { verified: false, reason: 'withdraw ' + i + ' revocation not by the pinned subject for this receipt' };
        if (!verifyConsentRevocation(e.revocation, flow.subject).verified) return { verified: false, reason: 'withdraw ' + i + ' revocation invalid' };
        if (!Number.isFinite(e.revocation.revoked_at)) return { verified: false, reason: 'withdraw ' + i + ' revocation has no finite revoked_at — cannot anchor the lifecycle (fail-closed)' };
      }
    }
    const st = foldState(flow.entries, opts);
    if (!st.valid) return { verified: false, reason: 'lifecycle invalid: ' + st.error };
    return { verified: true, compliant: st.violations.length === 0, violations: st.violations,
      state: { receipt_id: flow.receipt_id, controller: flow.controller, subject: flow.subject, status: st.status, withdrawn_at: st.withdrawn_at, subject_revoked_at: st.subject_revoked_at, access_count: st.accesses.length } };
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqconsentflow.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { grantConsent, revokeConsent } = await import('./pqconsent.mjs');
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const ks = (a, b) => ({ ed: ed(a), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(b)) });
  const pub = (k) => ({ ed: k.ed.publicKey, mldsa: k.mldsa.publicKey });
  const subject = ks(1, 2), ctrl = ks(3, 4), attacker = ks(9, 10);
  const receipt = grantConsent({ subjectKeys: subject, controller: 'vaulthealth', purposes: ['ai_coaching', 'doctor_share'], categories: ['HEART_RATE', 'SLEEP'], legalBasis: 'GDPR-Art-9-2-a', nonce: 'c1' });

  // open + in-scope accesses → compliant
  const flow = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl, at: 100 });
  ok(flow.entries.length === 1 && verifyConsentFlow(flow, pub(subject), pub(ctrl)).verified === true, 'open on a verified receipt → valid 1-entry flow');
  logAccess(flow, { purpose: 'ai_coaching', category: 'HEART_RATE', controllerKeys: ctrl, nonce: 'a1', at: 110 });
  logAccess(flow, { purpose: 'doctor_share', category: 'SLEEP', controllerKeys: ctrl, nonce: 'a2', at: 120 });
  const v1 = verifyConsentFlow(flow, pub(subject), pub(ctrl));
  ok(v1.verified && v1.compliant && v1.state.access_count === 2 && v1.state.status === 'open', 'two in-scope accesses → verified + compliant, status open');

  // out-of-scope access refused
  let oos = false; try { logAccess(flow, { purpose: 'marketing', category: 'HEART_RATE', controllerKeys: ctrl, nonce: 'a3', at: 130 }); } catch { oos = true; }
  ok(oos, 'out-of-scope purpose (marketing) → refused at logAccess (fail-dangerous)');

  // withdraw → status withdrawn; further access refused
  const rev = revokeConsent({ subjectKeys: subject, receiptId: receipt.receipt_id, reason: 'user-withdrew', revokedAt: 200 });
  withdraw(flow, { revocation: rev, subjectPub: pub(subject), controllerKeys: ctrl, at: 200 });
  const v2 = verifyConsentFlow(flow, pub(subject), pub(ctrl));
  ok(v2.verified && v2.compliant && v2.state.status === 'withdrawn' && v2.state.withdrawn_at === 200, 'withdrawal recorded → withdrawn, still compliant');
  let after = false; try { logAccess(flow, { purpose: 'ai_coaching', category: 'HEART_RATE', controllerKeys: ctrl, nonce: 'a9', at: 210 }); } catch { after = true; }
  ok(after, 'access after withdrawal → refused at logAccess (honest controller)');

  // VIOLATION DETECTION: a malicious controller hand-crafts a post-withdrawal access (bypassing logAccess) — still
  // cryptographically valid (controller-signed), but verifyConsentFlow DETECTS + reports the violation.
  const evil = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl, at: 100 });
  withdraw(evil, { revocation: rev, subjectPub: pub(subject), controllerKeys: ctrl, at: 200 });
  // craft a post-withdrawal access entry directly + chain it
  const prev = evil.entries[evil.entries.length - 1];
  const badCore = entryCore({ seq: evil.entries.length, prev_hash: prev.entry_hash, type: 'access', receipt_id: evil.receipt_id, purpose: 'ai_coaching', category: 'HEART_RATE', nonce: 'evil', controller: makeControllerId(ctrl), at: 250 });
  evil.entries.push(signEntry(badCore, ctrl));
  const ev = verifyConsentFlow(evil, pub(subject), pub(ctrl));
  ok(ev.verified === true && ev.compliant === false && ev.violations.length === 1 && ev.violations[0].kind === 'access-after-withdrawal', 'malicious post-withdrawal access → chain VERIFIED but NOT compliant; violation evidenced');

  // SUBJECT-TIME detection (DeepSeek red-team #1): the controller logs an access whose `at` is at/after the subject's
  // signed revoked_at, but places it BEFORE the withdraw entry in the chain (so chain-position alone wouldn't flag it).
  // Caught because foldState compares against the SUBJECT-signed revoked_at, not the controller-chosen order.
  const bd = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl, at: 100 });
  logAccess(bd, { purpose: 'ai_coaching', category: 'HEART_RATE', controllerKeys: ctrl, nonce: 'bd1', at: 250 });
  withdraw(bd, { revocation: revokeConsent({ subjectKeys: subject, receiptId: receipt.receipt_id, revokedAt: 200 }), subjectPub: pub(subject), controllerKeys: ctrl, at: 260 });
  const vbd = verifyConsentFlow(bd, pub(subject), pub(ctrl));
  ok(vbd.verified && !vbd.compliant && vbd.violations.some((x) => x.basis === 'revoked-at'), 'access at/after the SUBJECT revoked_at (logged before the withdraw entry) → violation detected via revoked-at, not chain position');

  // TIMESTAMP INVARIANT (fix-verif 1 Jul). Every access MUST be finite-timestamped. The honest API refuses an untimestamped
  // access; a HAND-CRAFTED at:null access entry still VERIFIES (signed+chained) but is NON-compliant. This closes the
  // null-`at` evasion (an untimestamped access could dodge BOTH chain-position and the revoked-at compare) WITHOUT a
  // false-positive on honest logs — honest logs are always timestamped, so the earlier ambiguity is gone.
  let noTs = false;
  try { const t = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl, at: 100 }); logAccess(t, { purpose: 'ai_coaching', category: 'HEART_RATE', controllerKeys: ctrl, nonce: 'ut0', at: null }); } catch { noTs = true; }
  ok(noTs, 'untimestamped access (at:null) → refused at logAccess (honest path)');
  const ut = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl, at: 100 });
  const utPrev = ut.entries[ut.entries.length - 1];
  ut.entries.push(signEntry(entryCore({ seq: ut.entries.length, prev_hash: utPrev.entry_hash, type: 'access', receipt_id: ut.receipt_id, purpose: 'ai_coaching', category: 'HEART_RATE', nonce: 'ut1', controller: makeControllerId(ctrl), at: null }), ctrl));
  withdraw(ut, { revocation: revokeConsent({ subjectKeys: subject, receiptId: receipt.receipt_id, revokedAt: 200 }), subjectPub: pub(subject), controllerKeys: ctrl, at: 260 });
  const vut = verifyConsentFlow(ut, pub(subject), pub(ctrl));
  ok(vut.verified && !vut.compliant && vut.violations.some((x) => x.kind === 'access-missing-timestamp'), 'hand-crafted untimestamped access → chain VERIFIED but NON-compliant (access-missing-timestamp)');

  // NULL/NaN `revoked_at` FAIL-CLOSED (fix-verif 1 Jul): a withdrawal whose subject-signed revocation carries no finite
  // revoked_at cannot anchor the lifecycle — it previously left effectiveRevokedAt null and SILENTLY disabled the
  // revoked-at compare (a post-revocation access before the withdraw entry then passed). Refused at the API + at verify.
  let nrThrow = false;
  try { const n = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl, at: 100 }); withdraw(n, { revocation: revokeConsent({ subjectKeys: subject, receiptId: receipt.receipt_id, reason: 'no-time' }), subjectPub: pub(subject), controllerKeys: ctrl, at: 260 }); } catch { nrThrow = true; }
  ok(nrThrow, 'withdraw with a revocation lacking a finite revoked_at → refused at the honest API (fail-closed anchor)');
  const nr = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl, at: 100 });
  const revNoTime = revokeConsent({ subjectKeys: subject, receiptId: receipt.receipt_id, reason: 'no-time' });
  const nrPrev = nr.entries[nr.entries.length - 1];
  nr.entries.push({ ...signEntry(entryCore({ seq: nr.entries.length, prev_hash: nrPrev.entry_hash, type: 'withdraw', receipt_id: nr.receipt_id, nonce: 'w-x', embed_sha256: h(canon(revNoTime)), controller: makeControllerId(ctrl), at: 260 }), ctrl), revocation: revNoTime });
  ok(verifyConsentFlow(nr, pub(subject), pub(ctrl)).verified === false, 'hand-crafted withdraw embedding a revocation with no finite revoked_at → verified:false (fail-closed)');

  // WITHHELD-WITHDRAWAL detection (DeepSeek #2): the controller never logs the withdrawal. With the subject's known
  // revocation supplied out-of-band, BOTH the withheld withdrawal and the post-revocation access are flagged.
  const wh = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl, at: 100 });
  logAccess(wh, { purpose: 'ai_coaching', category: 'HEART_RATE', controllerKeys: ctrl, nonce: 'wh1', at: 300 });
  const vwh = verifyConsentFlow(wh, pub(subject), pub(ctrl), { knownRevokedAt: 200 });
  ok(vwh.verified && !vwh.compliant && vwh.violations.some((x) => x.kind === 'withheld-withdrawal') && vwh.violations.some((x) => x.kind === 'access-after-withdrawal'), 'withheld withdrawal + known revocation supplied → withheld-withdrawal AND access-after-withdrawal flagged');
  ok(verifyConsentFlow(wh, pub(subject), pub(ctrl)).compliant === true, 'same withheld log WITHOUT the out-of-band revocation looks compliant — documented self-attested-completeness residual');

  // TEMPORAL SCOPE (DeepSeek #3): an access after the grant EXPIRY is out-of-scope (not silently ok).
  const expRcpt = grantConsent({ subjectKeys: subject, controller: 'vaulthealth', purposes: ['ai_coaching'], categories: ['HEART_RATE'], legalBasis: 'GDPR-Art-9-2-a', nonce: 'exp', expiresAt: 500 });
  const ef = openConsentFlow({ receipt: expRcpt, subjectPub: pub(subject), controllerKeys: ctrl, at: 100 });
  logAccess(ef, { purpose: 'ai_coaching', category: 'HEART_RATE', controllerKeys: ctrl, nonce: 'e1', at: 400 });
  ok(verifyConsentFlow(ef, pub(subject), pub(ctrl)).verified, 'access before grant expiry → verifies');
  const prevE = ef.entries[ef.entries.length - 1];
  ef.entries.push(signEntry(entryCore({ seq: ef.entries.length, prev_hash: prevE.entry_hash, type: 'access', receipt_id: ef.receipt_id, purpose: 'ai_coaching', category: 'HEART_RATE', nonce: 'e2', controller: makeControllerId(ctrl), at: 600 }), ctrl));
  ok(verifyConsentFlow(ef, pub(subject), pub(ctrl)).verified === false, 'hand-crafted access AFTER grant expiry (at=600 > expires_at=500) → scope check FAILS (verified:false)');

  // wrong pins / fail-dangerous opens
  ok(verifyConsentFlow(flow, pub(attacker), pub(ctrl)).verified === false, 'wrong pinned subject → FAILS');
  ok(verifyConsentFlow(flow, pub(subject), pub(attacker)).verified === false, 'wrong pinned controller → FAILS');
  let badOpen = false; try { openConsentFlow({ receipt, subjectPub: pub(attacker), controllerKeys: ctrl }); } catch { badOpen = true; }
  ok(badOpen, 'fail-dangerous: open with a receipt whose subject != pinned subject → refused');

  // tamper-evident: alter a logged access purpose → chain breaks
  const tam = JSON.parse(JSON.stringify(flow)); tam.entries[1].purpose = 'marketing';
  ok(verifyConsentFlow(tam, pub(subject), pub(ctrl)).verified === false, 'altered access entry → entry_hash/sig FAILS (tamper-evident)');
  // forged withdrawal by the attacker (not the subject) → rejected
  const revFake = revokeConsent({ subjectKeys: attacker, receiptId: receipt.receipt_id, revokedAt: 300 });
  let badWd = false; try { const f2 = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl }); withdraw(f2, { revocation: revFake, subjectPub: pub(subject), controllerKeys: ctrl, at: 300 }); } catch { badWd = true; }
  ok(badWd, 'withdrawal revocation signed by a NON-subject → refused');

  // 3-leg hybrid controller
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5));
  const ctrl3 = { ed: ctrl.ed, mldsa: ctrl.mldsa, slh };
  const tCtrl3 = { ed: ctrl.ed.publicKey, mldsa: ctrl.mldsa.publicKey, slh: slh.publicKey };
  const f3 = openConsentFlow({ receipt, subjectPub: pub(subject), controllerKeys: ctrl3, at: 100 });
  logAccess(f3, { purpose: 'ai_coaching', category: 'SLEEP', controllerKeys: ctrl3, nonce: 'a1', at: 110 });
  ok(typeof f3.entries[1].slh_sig === 'string' && verifyConsentFlow(f3, pub(subject), tCtrl3).verified === true, '3-leg (Ed25519∧ML-DSA∧SLH) consent flow verifies');
  const f3s = JSON.parse(JSON.stringify(f3)); f3s.entries[1].slh_sig = '00';
  ok(verifyConsentFlow(f3s, pub(subject), tCtrl3).verified === false, 'stripped SLH leg fails when controller.slh pinned (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { entries: 'x' }, { entries: [{ seq: 3 }] }]) { try { if (verifyConsentFlow(bad, pub(subject), pub(ctrl)).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed flows → verified:false, never throws');

  console.log('pqconsentflow self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqconsentflow\.mjs$/.test(process.argv[1] || '')) selfTest();
