/*!
 * @trelyan/verify-pqc/mldsa — in-browser ML-DSA-87 verification of THRONDAR's
 * transparency-log Signed Tree Head. This is **Layer 1** of the two-layer anchor:
 * proving the STH is genuinely signed by THRONDAR's post-quantum answer-signer,
 * not merely asserted. PROVEN against the live /api/transparency/ledger STH.
 *
 * Peer dependency: @noble/post-quantum (audited, pure-JS ML-DSA / FIPS-204) + @noble/hashes.
 * Isomorphic: works in Node and the browser. MIT.
 *
 * The exact construction is reverse-derived from THRONDAR's signer
 * (lib/provenance-canonical.ts): the signature covers the canonical core
 *   {"v","model","answer_sha256","governance_flag","ts"}   (FIXED key order, not sorted)
 * under ML-DSA context "throndar-sth-v1", and answer_sha256 == sha256(signed).
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const enc = (s) => new TextEncoder().encode(s);
function hexToBytes(h) { const u = new Uint8Array(h.length / 2); for (let i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16); return u; }

/** Published THRONDAR STH-signer key thumbprint. Pinning this rejects an
 *  attacker-substituted key+signature (they can't forge this published id). */
export const THRONDAR_STH_KEY_ID = '0986d89fa3c74566';
export const STH_CONTEXT = 'throndar-sth-v1';

/** The exact bytes ML-DSA covers: canonical receipt core, FIXED key order. */
function canonicalCore(r) {
  return enc(JSON.stringify({
    v: r.v, model: r.model, answer_sha256: r.answer_sha256,
    governance_flag: r.governance_flag, ts: r.ts,
  }));
}

/**
 * Verify a THRONDAR `signed_tree_head` object (from GET /api/transparency/ledger).
 * Returns { verified, keyRecognized, digestChain, sigValid, reason }.
 *
 *   verified === true  ⇒  this STH is genuinely signed by the PINNED THRONDAR
 *   ML-DSA-87 key, over a receipt whose digest binds the exact STH content.
 */
export function verifyThrondarSth(sth, opts = {}) {
  const pinnedKeyId = opts.pinnedKeyId || THRONDAR_STH_KEY_ID;
  try {
    const r = sth.receipt, signed = sth.signed, key = sth.key;
    if (!r || !signed || !key) return { verified: false, reason: 'missing receipt/signed/key' };
    const pk = hexToBytes(key.public_key_hex);
    const sig = hexToBytes(r.sig);
    // 1) digest chain — answer_sha256 must equal sha256(signed); binds the receipt to the STH content
    const digestChain = bytesToHex(sha256(enc(signed))) === r.answer_sha256;
    // 2) key pinning — both key ids must be the published THRONDAR STH signer
    const keyRecognized = r.key_id === pinnedKeyId && key.key_id === pinnedKeyId;
    // 3) ML-DSA-87 signature over the canonical core, context-bound
    const sigValid = ml_dsa87.verify(sig, canonicalCore(r), pk, { context: enc(r.context || STH_CONTEXT) });
    const ctxOk = (r.context || STH_CONTEXT) === STH_CONTEXT;
    const verified = digestChain && keyRecognized && sigValid && ctxOk;
    return {
      verified, keyRecognized, digestChain, sigValid,
      reason: verified ? 'ok'
        : !keyRecognized ? `key_id ${r.key_id} is not the pinned THRONDAR STH signer ${pinnedKeyId}`
        : !digestChain ? 'answer_sha256 != sha256(signed) — receipt does not bind this STH'
        : !sigValid ? 'ML-DSA-87 signature is invalid'
        : 'STH context mismatch',
    };
  } catch (e) { return { verified: false, reason: 'error: ' + (e && e.message || e) }; }
}
