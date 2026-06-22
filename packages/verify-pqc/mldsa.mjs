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
import { THRONDAR_STH_PUBKEY_HEX, THRONDAR_STH_KEY_ID } from './throndar-sth-key.mjs';

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
    const pk = hexToBytesStrict(opts.pubkeyHex || THRONDAR_STH_PUBKEY_HEX, PK_HEXLEN);
    const sig = hexToBytesStrict(r.sig, SIG_HEXLEN);
    if (!pk) return { verified: false, reason: 'pinned pubkey malformed' };
    if (!sig) return { verified: false, reason: 'signature is not 4627 bytes of hex' };
    const digestChain = bytesToHex(sha256(enc(signed))) === r.answer_sha256;
    const ctxOk = r.context === STH_CONTEXT;
    const keyIdMatches = r.key_id === THRONDAR_STH_KEY_ID; // label sanity-check; real binding is the pinned pk
    let sigValid = false;
    try { sigValid = ml_dsa87.verify(sig, canonicalCore(r), pk, { context: enc(STH_CONTEXT) }); } catch { sigValid = false; }
    const verified = sigValid && digestChain && ctxOk && keyIdMatches;
    return {
      verified, sigValid, digestChain, ctxOk, keyIdMatches,
      reason: verified ? 'ok'
        : !sigValid ? 'ML-DSA-87 signature invalid under the PINNED THRONDAR key'
        : !digestChain ? 'answer_sha256 != sha256(signed) — receipt does not bind this STH'
        : !ctxOk ? 'context is not throndar-sth-v1'
        : 'receipt key_id does not match the pinned key',
    };
  } catch (e) { return { verified: false, reason: 'error: ' + (e && e.message || e) }; }
}

export { THRONDAR_STH_KEY_ID, THRONDAR_STH_PUBKEY_HEX };
