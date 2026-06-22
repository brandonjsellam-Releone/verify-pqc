/*!
 * @trelyan/verify-pqc/mldsa — in-browser ML-DSA-87 verification of THRONDAR's
 * transparency-log Signed Tree Head. **Layer 1** of the two-layer anchor.
 *
 * ROOT OF TRUST (hardened per Apex-council review): the signature is verified against a
 * PINNED full public key (packages/verify-pqc/throndar-sth-key.js, the whole 2592-byte
 * ML-DSA-87 key), NOT the key the server sends and NOT a truncated thumbprint. So a
 * malicious/MITM'd server (or a key_id-grinding attacker) cannot get a false "verified".
 *
 * Peer dependency: @noble/post-quantum + @noble/hashes (audited, pure-JS FIPS-204).
 * The construction is reverse-derived from THRONDAR's signer (lib/provenance-canonical.ts):
 * ML-DSA over the canonical core {"v","model","answer_sha256","governance_flag","ts"}
 * (FIXED key order) under context "throndar-sth-v1", with answer_sha256 == sha256(signed).
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { THRONDAR_STH_PUBKEY_HEX, THRONDAR_STH_KEY_ID, THRONDAR_STH_PINS } from './throndar-sth-key.mjs';

const enc = (s) => new TextEncoder().encode(s);
const STH_CONTEXT = 'throndar-sth-v1';
const SIG_HEXLEN = 4627 * 2, PK_HEXLEN = 2592 * 2;

function hexToBytesStrict(hex, expectHexLen) {
  if (typeof hex !== 'string' || hex.length !== expectHexLen || !/^[0-9a-fA-F]+$/.test(hex)) return null;
  const u = new Uint8Array(hex.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(hex.substr(i * 2, 2), 16);
  return u;
}

/** EXACT signed bytes: canonical core, fixed key order, ts coerced to integer. */
function canonicalCore(r) {
  return enc(JSON.stringify({
    v: r.v, model: r.model, answer_sha256: r.answer_sha256,
    governance_flag: r.governance_flag, ts: Number(r.ts),
  }));
}

/**
 * Verify a THRONDAR `signed_tree_head` (from GET /api/transparency/ledger) against the
 * PINNED key. Returns { verified, sigValid, digestChain, ctxOk, keyIdMatches, reason }.
 * Pass opts.pubkeyHex only to test against a rotated key.
 */
export function verifyThrondarSth(sth, opts = {}) {
  try {
    const r = sth && sth.receipt, signed = sth && sth.signed;
    if (!r || typeof signed !== 'string') return { verified: false, reason: 'missing receipt/signed' };
    // Pin SELECTION (rotation-ready): choose the pinned FULL pubkey whose key_id matches this
    // receipt. opts.pubkeyHex still overrides (tests against a rotated key); opts.pins overrides the
    // recognized set. Day-one THRONDAR_STH_PINS = [{current}] ⇒ identical behaviour to a scalar pin.
    const pins = opts.pins || THRONDAR_STH_PINS || [{ key_id: THRONDAR_STH_KEY_ID, pubkey_hex: THRONDAR_STH_PUBKEY_HEX, role: 'current' }];
    const matched = opts.pubkeyHex ? { key_id: r.key_id, pubkey_hex: opts.pubkeyHex, role: 'override' }
                                   : pins.find((p) => p && p.key_id === r.key_id);
    const keyIdMatches = !!matched; // recognized iff the id is in the pinned SET; real binding is the pinned pk
    const pk = matched ? hexToBytesStrict(matched.pubkey_hex, PK_HEXLEN) : null;
    const sig = hexToBytesStrict(r.sig, SIG_HEXLEN);
    if (!keyIdMatches) return { verified: false, sigValid: false, digestChain: false, ctxOk: false, keyIdMatches: false, reason: 'receipt key_id is not in the recognized pin set {current, previous}' };
    if (!pk) return { verified: false, reason: 'pinned pubkey malformed' };
    if (!sig) return { verified: false, reason: 'signature is not 4627 bytes of hex' };
    const digestChain = bytesToHex(sha256(enc(signed))) === r.answer_sha256;
    const ctxOk = r.context === STH_CONTEXT;
    let sigValid = false;
    try { sigValid = ml_dsa87.verify(sig, canonicalCore(r), pk, { context: enc(STH_CONTEXT) }); } catch { sigValid = false; }
    const verified = sigValid && digestChain && ctxOk && keyIdMatches;
    return {
      verified, sigValid, digestChain, ctxOk, keyIdMatches,
      matchedKeyId: matched ? matched.key_id : null, matchedRole: matched ? matched.role : null,
      reason: verified ? 'ok'
        : !sigValid ? 'ML-DSA-87 signature invalid under the PINNED THRONDAR key'
        : !digestChain ? 'answer_sha256 != sha256(signed) — receipt does not bind this STH'
        : !ctxOk ? 'context is not throndar-sth-v1'
        : 'receipt key_id is not in the recognized pin set',
    };
  } catch (e) { return { verified: false, reason: 'error: ' + (e && e.message || e) }; }
}

/**
 * ADDITIVE: ML-DSA-87 verdict (authoritative) PLUS the optional SLH-DSA diversity leg.
 * `verified` is IDENTICAL to verifyThrondarSth(...).verified — ML-DSA-87 is the SOLE gate. SLH is
 * advisory defence-in-depth (handbook §4.2/§6.2.3); it NEVER flips `verified` in either direction.
 * Dynamically imports slhdsa.mjs so this module has no hard dependency on the SLH pin/leg.
 */
export async function verifyThrondarStrong(sth, opts = {}) {
  const ml = verifyThrondarSth(sth, opts);
  let slh = { slhPresent: false, slhValid: false, reason: 'SLH leg not loaded' };
  try { const m = await import('./slhdsa.mjs'); slh = m.verifyThrondarSlh(sth, opts); }
  catch (e) { slh = { slhPresent: false, slhValid: false, reason: 'SLH leg unavailable: ' + (e && e.message || e) }; }
  return {
    verified: ml.verified,            // authoritative: ML-DSA-87 ONLY
    mldsa: ml, slhdsa: slh,
    diversity: ml.verified && slh.slhValid ? 'ml-dsa + slh-dsa (dual PQC family)'
      : ml.verified ? 'ml-dsa (slh-dsa diversity ' + (slh.slhPresent ? 'failed' : 'absent') + ')'
      : 'verification failed',
  };
}

export { THRONDAR_STH_KEY_ID, THRONDAR_STH_PUBKEY_HEX, THRONDAR_STH_PINS };
