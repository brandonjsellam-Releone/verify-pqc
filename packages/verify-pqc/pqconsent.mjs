/*!
 * pqconsent — verifiable, self-sovereign consent receipt (post-quantum). Reference, DRAFT.
 *
 * The DATA SUBJECT (e.g. a VaultHealth / VaultMe user, signing with their device key) issues a hybrid-signed receipt
 * granting a named CONTROLLER specific PURPOSES over specific DATA CATEGORIES, under a stated legal basis, with an
 * expiry — and can REVOKE it. A controller / auditor / regulator verifies: the subject (whose id binds their keys)
 * granted THIS exact scope; it is unexpired; it is not revoked; and a given (purpose, category) is actually covered
 * (deny-by-default). The subject — not the controller — is the signer and the sole revoker (self-sovereign consent).
 *
 * FALSIFIABLE PROPERTIES (given the receipt + the subject's keys): the subject consented to EXACTLY these purposes ×
 * categories at this time (forging needs a classical AND a lattice [AND hash-based] break); a purpose/category not in
 * the receipt is refused (so bundled / pre-ticked / scope-creep consent cannot verify); revocation is provable.
 * Ed25519 ∧ ML-DSA-87 ∧ optional SLH-DSA-256f (anti-downgrade), dual-anchor-ready (an immutable consent-event trail).
 *
 * HONEST: this is cryptographic EVIDENCE of a consent event under the stated model — it is tamper-evident proof of
 * WHAT was consented, WHEN, and revocation status. It is NOT a legal determination that the consent is valid/lawful
 * (that needs a lawful basis, proper UX, and counsel) and NOT legal advice. Unaudited reference implementation.
 *
 * Self-test: node pqconsent.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';

const CONSENT_CTX = utf8ToBytes('trelyan-consent-receipt-v1');       // signing domain (Ed25519 + ML-DSA legs)
const CONSENT_SLH_CTX = utf8ToBytes('trelyan-consent-receipt-slh-v1'); // distinct domain for the optional SLH leg
const REV_CTX = utf8ToBytes('trelyan-consent-revocation-v1');       // distinct domain for revocation records
const REV_SLH_CTX = utf8ToBytes('trelyan-consent-revocation-slh-v1');

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
export function makeSubjectId(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('subject keys must be { ed, mldsa[, slh] }');
  return 'consent:trelyan:subject:v1:' + bytesToHex(sha256(concatBytes(utf8ToBytes('consent:trelyan:subject:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}
// purpose/category tokens are normalized MACHINE CODES: NFKC + casefold + trim, restricted to a safe ASCII charset
// [a-z0-9_.:-]. This guarantees case / whitespace / unicode-homoglyph / bidi-control variants can NEVER diverge
// between the signer and the verifier, and a deceptive token can't be silently signed (apex-team fix). null = invalid.
function normToken(s) {
  const t = String(s == null ? '' : s).normalize('NFKC').trim().toLowerCase();
  return /^[a-z0-9_.:-]+$/.test(t) ? t : null;
}
const normList = (a) => {
  const out = [];
  for (const x of (Array.isArray(a) ? a : [])) { const t = normToken(x); if (t === null) throw new Error('invalid purpose/category token ' + JSON.stringify(x) + ' — use ASCII codes [a-z0-9_.:-] (no spaces / unicode / control chars)'); out.push(t); }
  return [...new Set(out)].sort();
};
// receipt_id is a deterministic function of the signed scope (used as the revocation key).
function receiptId(m) { return bytesToHex(sha256(utf8ToBytes(canon({ subject: m.subject, controller: m.controller, purposes: m.purposes, categories: m.categories, nonce: m.nonce })))); }
function consentCore(m) {
  return { v: '1', subject: m.subject, controller: m.controller, purposes: m.purposes, categories: m.categories,
    legal_basis: m.legal_basis, jurisdiction: m.jurisdiction ?? null, policy_ref: m.policy_ref ?? null,
    nonce: m.nonce, granted_at: m.granted_at ?? null, expires_at: m.expires_at ?? null, receipt_id: m.receipt_id, anchor_commitment: m.anchor_commitment ?? null };
}

// subjectKeys = the data subject's device keys { ed, mldsa[, slh] }. purposes/categories = non-empty string lists.
export function grantConsent({ subjectKeys, controller, purposes, categories, legalBasis, jurisdiction, policyRef, nonce, grantedAt, expiresAt }) {
  if (!subjectKeys || !subjectKeys.ed || !subjectKeys.mldsa) throw new Error('subjectKeys must be { ed, mldsa[, slh] }');
  if (!controller) throw new Error('controller is required');
  const purp = normList(purposes), cats = normList(categories);
  if (!purp.length || !cats.length) throw new Error('at least one purpose AND one category are required (no empty/blanket consent)');
  if (!legalBasis || typeof legalBasis !== 'string') throw new Error('legalBasis (string) is required, e.g. GDPR-Art-9-2-a-explicit');
  const subject = makeSubjectId(subjectKeys);
  const idF = { subject, controller: String(controller), purposes: purp, categories: cats, nonce: String(nonce ?? bytesToHex(randomBytes(16))) };
  const receipt_id = receiptId(idF);
  const anchor_commitment = bytesToHex(sha256(utf8ToBytes('trelyan-consent-anchor-v1' + canon({ ...idF, receipt_id }))));
  const core = consentCore({ ...idF, legal_basis: String(legalBasis), jurisdiction: jurisdiction ?? null, policy_ref: policyRef ?? null, granted_at: grantedAt ?? null, expires_at: expiresAt ?? null, receipt_id, anchor_commitment });
  const coreBytes = utf8ToBytes(canon(core));
  const receipt = { ...core,
    subject_pub: { ed: bytesToHex(_pub(subjectKeys.ed)), mldsa: bytesToHex(_pub(subjectKeys.mldsa)) },
    ed_sig: bytesToHex(ed25519.sign(concatBytes(CONSENT_CTX, coreBytes), subjectKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, subjectKeys.mldsa.secretKey, { context: CONSENT_CTX })) };
  if (subjectKeys.slh) { receipt.subject_pub.slh = bytesToHex(_pub(subjectKeys.slh)); receipt.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, subjectKeys.slh.secretKey, { context: CONSENT_SLH_CTX })); }
  return receipt;
}

// the subject (and ONLY the subject) revokes. A controller/auditor collects verified revocations into a deny-set.
export function revokeConsent({ subjectKeys, receiptId: rid, reason, revokedAt }) {
  if (!subjectKeys || !subjectKeys.ed || !subjectKeys.mldsa) throw new Error('subjectKeys must be { ed, mldsa[, slh] }');
  if (!rid) throw new Error('receiptId is required');
  const core = { v: '1', subject: makeSubjectId(subjectKeys), receipt_id: String(rid), reason: reason ?? null, revoked_at: revokedAt ?? null };
  const coreBytes = utf8ToBytes(canon(core));
  const rec = { ...core, subject_pub: { ed: bytesToHex(_pub(subjectKeys.ed)), mldsa: bytesToHex(_pub(subjectKeys.mldsa)) },
    ed_sig: bytesToHex(ed25519.sign(concatBytes(REV_CTX, coreBytes), subjectKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, subjectKeys.mldsa.secretKey, { context: REV_CTX })) };
  if (subjectKeys.slh) { rec.subject_pub.slh = bytesToHex(_pub(subjectKeys.slh)); rec.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, subjectKeys.slh.secretKey, { context: REV_SLH_CTX })); }
  return rec;
}
// verify a revocation was signed by the SAME subject that the receipt binds (no one else can revoke — nor forge one).
export function verifyConsentRevocation(rec, receiptOrSubjectId) {
  try {
    if (!rec || typeof rec !== 'object' || !rec.subject_pub) return { verified: false };
    let subPub; try { subPub = { ed: hexToBytes(rec.subject_pub.ed), mldsa: hexToBytes(rec.subject_pub.mldsa), ...(rec.subject_pub.slh ? { slh: hexToBytes(rec.subject_pub.slh) } : {}) }; } catch { return { verified: false }; }
    if (makeSubjectId(subPub) !== rec.subject) return { verified: false, reason: 'subject_pub != subject id' };
    const wantSubject = typeof receiptOrSubjectId === 'string' ? receiptOrSubjectId : (receiptOrSubjectId && receiptOrSubjectId.subject);
    if (wantSubject != null && rec.subject !== wantSubject) return { verified: false, reason: 'revocation subject != receipt subject (only the subject may revoke)' };
    const coreBytes = utf8ToBytes(canon({ v: rec.v, subject: rec.subject, receipt_id: rec.receipt_id, reason: rec.reason ?? null, revoked_at: rec.revoked_at ?? null }));
    let edOk = false, pqOk = false;
    try { edOk = ed25519.verify(hexToBytes(rec.ed_sig), concatBytes(REV_CTX, coreBytes), subPub.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(rec.mldsa_sig), coreBytes, subPub.mldsa, { context: REV_CTX }); } catch { pqOk = false; }
    return { verified: edOk && pqOk, receipt_id: rec.receipt_id, reason: rec.reason ?? null };
  } catch { return { verified: false }; }
}

// TOTAL / fail-closed. opts: now (expiry), controller (must match if given), purpose + category (deny-by-default scope
// check — both must be in the granted lists; normalized identically to grant), revoked ({has(receipt_id)->bool}
// deny-set), requireSlh, expectedAnchor.
// REVOCATION CAVEAT (apex-team / council): the deny-set only stops processing if the controller HAS the subject's
// revocation — a controller that suppresses/ignores it can keep processing (inherent deny-list limit). Mitigate with
// SHORT expires_at + an anchored/transparency-log revocation registry; the subject's signed revocation is the proof.
export function verifyConsent(receipt, opts = {}) {
  try {
    if (!receipt || typeof receipt !== 'object' || !receipt.subject_pub) return { verified: false };
    let subPub; try { subPub = { ed: hexToBytes(receipt.subject_pub.ed), mldsa: hexToBytes(receipt.subject_pub.mldsa), ...(receipt.subject_pub.slh ? { slh: hexToBytes(receipt.subject_pub.slh) } : {}) }; } catch { return { verified: false, reason: 'bad subject_pub' }; }
    if (makeSubjectId(subPub) !== receipt.subject) return { verified: false, reason: 'subject_pub does not match subject id' };
    if (receipt.receipt_id !== receiptId(receipt)) return { verified: false, reason: 'receipt_id does not bind the scope' };
    if (!Array.isArray(receipt.purposes) || !Array.isArray(receipt.categories) || !receipt.purposes.length || !receipt.categories.length) return { verified: false, reason: 'empty scope' };
    const coreBytes = utf8ToBytes(canon(consentCore(receipt)));
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(receipt.ed_sig), concatBytes(CONSENT_CTX, coreBytes), subPub.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(receipt.mldsa_sig), coreBytes, subPub.mldsa, { context: CONSENT_CTX }); } catch { pqOk = false; }
    if (opts.requireSlh) { try { slhOk = !!(subPub.slh && receipt.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(receipt.slh_sig), coreBytes, subPub.slh, { context: CONSENT_SLH_CTX })); } catch { slhOk = false; } }
    if (!edOk || !pqOk || !slhOk) return { verified: false, reason: 'subject hybrid signature invalid (or required leg missing)' };
    if (opts.controller != null && receipt.controller !== opts.controller) return { verified: false, reason: 'controller mismatch' };
    if (receipt.expires_at != null && opts.now != null && Number(opts.now) >= Number(receipt.expires_at)) return { verified: false, reason: 'expired' };
    // scope: deny-by-default — a purpose/category not explicitly granted is NOT consented
    if (opts.purpose != null) { const p = normToken(opts.purpose); if (p === null || !receipt.purposes.includes(p)) return { verified: false, reason: 'purpose not consented' }; }
    if (opts.category != null) { const cat = normToken(opts.category); if (cat === null || !receipt.categories.includes(cat)) return { verified: false, reason: 'category not consented' }; }
    if (opts.revoked && typeof opts.revoked.has === 'function' && opts.revoked.has(receipt.receipt_id)) return { verified: false, reason: 'revoked' };
    if (opts.expectedAnchor != null && receipt.anchor_commitment !== opts.expectedAnchor) return { verified: false, reason: 'anchor commitment mismatch' };
    return { verified: true, subject: receipt.subject, controller: receipt.controller, purposes: receipt.purposes, categories: receipt.categories, receipt_id: receipt.receipt_id };
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqconsent.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const subject = { ed: ed(1), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)) };
  const attacker = { ed: ed(9), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)) };

  const r = grantConsent({ subjectKeys: subject, controller: 'vaulthealth', purposes: ['ai_coaching', 'doctor_share'],
    categories: ['HEART_RATE', 'SLEEP'], legalBasis: 'GDPR-Art-9-2-a-explicit', jurisdiction: 'EU', expiresAt: 1000, nonce: 'c-1' });
  ok(r.subject === makeSubjectId(subject) && typeof r.receipt_id === 'string', 'receipt binds subject id + receipt_id');
  ok(verifyConsent(r, { now: 1, controller: 'vaulthealth', purpose: 'ai_coaching', category: 'HEART_RATE' }).verified === true, 'granted purpose+category verifies');
  // DENY-BY-DEFAULT scope (GDPR Art.9 explicit)
  ok(verifyConsent(r, { now: 1, purpose: 'ad_targeting' }).verified === false, 'an UNGRANTED purpose (ad_targeting) -> NOT consented -> FAILS');
  ok(verifyConsent(r, { now: 1, category: 'MENTAL_HEALTH' }).verified === false, 'an UNGRANTED category (MENTAL_HEALTH) -> NOT consented -> FAILS');
  // APEX-TEAM FIX: strict token canonicalization — case/whitespace/unicode-homoglyph cannot diverge signer vs verifier
  const rc = grantConsent({ subjectKeys: subject, controller: 'vaulthealth', purposes: ['AI_Coaching'], categories: ['Heart_Rate'], legalBasis: 'GDPR-Art-9-2-a-explicit', nonce: 'cc-1' });
  ok(verifyConsent(rc, { purpose: 'ai_coaching', category: 'HEART_RATE' }).verified === true, 'token canon: case-insensitive membership (AI_Coaching grant matches ai_coaching check)');
  ok(verifyConsent(r, { now: 1, purpose: 'ai coaching' }).verified === false, 'a malformed query token (embedded whitespace) -> deny');
  let homo = false; try { grantConsent({ subjectKeys: subject, controller: 'x', purposes: ['mаrketing'], categories: ['a'], legalBasis: 'b' }); } catch { homo = true; }
  ok(homo, 'a unicode-homoglyph / non-ASCII purpose token is REJECTED at grant (no deceptive token gets signed)');
  // controller + expiry
  ok(verifyConsent(r, { now: 1, controller: 'other-co' }).verified === false, 'controller mismatch -> FAILS');
  ok(verifyConsent(r, { now: 1000 }).verified === false, 'expired consent -> FAILS');
  // subject_pub substitution / forgery
  const f = JSON.parse(JSON.stringify(r)); f.subject_pub.ed = bytesToHex(attacker.ed.publicKey); f.subject_pub.mldsa = bytesToHex(attacker.mldsa.publicKey);
  ok(verifyConsent(f, { now: 1 }).verified === false, 'subject_pub substitution -> subject id mismatch -> FAILS');
  // tamper: add a purpose without re-sign (scope-creep)
  const t = JSON.parse(JSON.stringify(r)); t.purposes = [...t.purposes, 'ad_targeting'].sort();
  ok(verifyConsent(t, { now: 1 }).verified === false, 'scope-creep (added purpose, re-sign-free) -> receipt_id/sig FAILS');
  // no blanket consent
  let blank = false; try { grantConsent({ subjectKeys: subject, controller: 'x', purposes: [], categories: ['A'], legalBasis: 'b' }); } catch { blank = true; }
  ok(blank, 'empty purpose list rejected at grant (no blanket/empty consent)');

  // revocation — only the subject can revoke; it is provable; a forged one fails
  const rev = revokeConsent({ subjectKeys: subject, receiptId: r.receipt_id, reason: 'withdrew', revokedAt: 5 });
  ok(verifyConsentRevocation(rev, r).verified === true && verifyConsentRevocation(rev, r).receipt_id === r.receipt_id, 'subject revocation verifies against the receipt');
  const forgedRev = revokeConsent({ subjectKeys: attacker, receiptId: r.receipt_id });
  ok(verifyConsentRevocation(forgedRev, r).verified === false, 'a revocation by someone OTHER than the subject -> FAILS (only the subject may revoke)');
  const denySet = new Set([verifyConsentRevocation(rev, r).receipt_id]);
  ok(verifyConsent(r, { now: 1, revoked: denySet, purpose: 'ai_coaching', category: 'HEART_RATE' }).verified === false, 'revoked receipt in the deny-set -> FAILS');

  // anchor pin
  ok(verifyConsent(r, { now: 1, expectedAnchor: r.anchor_commitment }).verified === true && verifyConsent(r, { now: 1, expectedAnchor: 'beef' }).verified === false, 'expectedAnchor pin enforced');

  // 3-leg hash-based hardening
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5));
  const subject3 = { ed: subject.ed, mldsa: subject.mldsa, slh };
  const r3 = grantConsent({ subjectKeys: subject3, controller: 'vaulthealth', purposes: ['ai_coaching'], categories: ['HEART_RATE'], legalBasis: 'GDPR-Art-9-2-a-explicit', nonce: 'c-3' });
  ok(typeof r3.slh_sig === 'string' && verifyConsent(r3, { requireSlh: true }).verified === true, '3-leg receipt verifies with requireSlh');
  const r3s = JSON.parse(JSON.stringify(r3)); r3s.slh_sig = '00';
  ok(verifyConsent(r3s, { requireSlh: true }).verified === false, 'stripped SLH leg fails when requireSlh (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { purposes: [] }, { ...r, ed_sig: 'zz' }]) { try { if (verifyConsent(bad, { now: 1 }).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed receipts -> verified:false, never throws');

  console.log('pqconsent self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqconsent\.mjs$/.test(process.argv[1] || '')) selfTest();
