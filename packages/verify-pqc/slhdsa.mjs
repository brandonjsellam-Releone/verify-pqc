/*!
 * @trelyan/verify-pqc/slhdsa — in-browser SLH-DSA-256f (FIPS-205) verification of THRONDAR's
 * transparency-log STH, as an ADDITIVE post-quantum DIVERSITY leg alongside ML-DSA-87.
 *
 * WHY (TNO/AIVD/CWI PQC Migration Handbook §4.2/§6.2.3): PREFER ML-DSA + SLH-DSA over FN-DSA/Falcon
 * — Falcon's floating-point Gaussian sampler is hard to side-channel-protect (§5.3.2; DFA [BD23] §6.5).
 * ML-DSA-87 and Falcon are BOTH lattice schemes; SLH-DSA is hash-based, so it adds true
 * ALGORITHM-FAMILY diversity: a lattice break leaves this leg standing.
 *
 * NON-AUTHORITATIVE BY DESIGN: this never produces an authoritative "verified". The sole gate stays
 * ML-DSA-87 (mldsa.mjs). It returns { slhPresent, slhValid, reason } as a defence-in-depth signal.
 * If THRONDAR has not published an SLH co-signature yet, slhPresent=false (NOT a failure).
 *
 * INTEROP (proven 22 Jun 2026): the bridge signs with pure-Python FIPS-205 `slhdsa`
 * (KeyPair.sign_pure(canonicalCore, ctx="throndar-sth-v1")); that verifies under this @noble
 * `slh_dsa_sha2_256f.verify(sig, canonicalCore, pk, {context})`. Params: pk=64 B, sig=49856 B.
 *
 * Root of trust mirrors mldsa.mjs: verify against the PINNED full 64-byte SLH-DSA public key
 * (throndar-slh-key.mjs), NOT the key the server sends.
 */
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { THRONDAR_SLH_PUBKEY_HEX, THRONDAR_SLH_KEY_ID } from './throndar-slh-key.mjs';

const enc = (s) => new TextEncoder().encode(s);
const STH_CONTEXT = 'throndar-sth-v1';
const SIG_HEXLEN = 49856 * 2, PK_HEXLEN = 64 * 2;

function hexToBytesStrict(hex, expectHexLen) {
  if (typeof hex !== 'string' || hex.length !== expectHexLen || !/^[0-9a-fA-F]+$/.test(hex)) return null;
  const u = new Uint8Array(hex.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(hex.substr(i * 2, 2), 16);
  return u;
}

/** EXACT signed bytes: same canonical core + fixed key order as the ML-DSA leg (mldsa.mjs). */
function canonicalCore(r) {
  return enc(JSON.stringify({
    v: r.v, model: r.model, answer_sha256: r.answer_sha256,
    governance_flag: r.governance_flag, ts: Number(r.ts),
  }));
}

/**
 * Verify THRONDAR's OPTIONAL SLH-DSA co-signature over the SAME canonical core as the ML-DSA STH.
 * Read from sth.receipt.slh_sig (or opts.slhSigHex). DIVERSITY check, never authoritative:
 * - slhPresent=false when no pin OR no co-sig is published → harmless, NOT a failure.
 * - slhValid=true only when the SLH-DSA-256f signature verifies under the PINNED 64-byte key.
 * Callers MUST keep ML-DSA-87 (mldsa.mjs) as the verdict.
 */
export function verifyThrondarSlh(sth, opts = {}) {
  try {
    const r = sth && sth.receipt;
    const slhSigHex = opts.slhSigHex || (r && r.slh_sig);
    const pinHex = opts.pubkeyHex || THRONDAR_SLH_PUBKEY_HEX;
    if (!pinHex) return { slhPresent: false, slhValid: false, reason: 'no SLH-DSA pin published (diversity leg inactive)' };
    if (!r || !slhSigHex) return { slhPresent: false, slhValid: false, reason: 'STH carries no SLH-DSA co-signature' };
    const pk = hexToBytesStrict(pinHex, PK_HEXLEN);
    const sig = hexToBytesStrict(slhSigHex, SIG_HEXLEN);
    if (!pk) return { slhPresent: true, slhValid: false, reason: 'pinned SLH pubkey malformed (expect 64 B hex)' };
    if (!sig) return { slhPresent: true, slhValid: false, reason: 'SLH signature is not 49856 bytes of hex' };
    const keyIdMatches = !THRONDAR_SLH_KEY_ID || r.slh_key_id === THRONDAR_SLH_KEY_ID;
    const context = opts.context || STH_CONTEXT;
    let slhValid = false;
    try { slhValid = slh_dsa_sha2_256f.verify(sig, canonicalCore(r), pk, { context: enc(context) }); } catch { slhValid = false; }
    return {
      slhPresent: true, slhValid: slhValid && keyIdMatches,
      reason: (slhValid && keyIdMatches) ? 'ok'
        : !slhValid ? 'SLH-DSA-256f signature invalid under the pinned THRONDAR SLH key'
        : 'SLH receipt key_id does not match the pinned SLH key',
    };
  } catch (e) { return { slhPresent: false, slhValid: false, reason: 'error: ' + (e && e.message || e) }; }
}

/** Self-test: proves the @noble FIPS-205 path round-trips and a tampered/foreign sig fails.
 *  Pure-JS, no network. @noble API: sign(msg, sk, {context}) / verify(sig, msg, pk, {context}). */
export function selfTest() {
  const ctx = { context: enc(STH_CONTEXT) };
  const msg = canonicalCore({ v: 1, model: 'x', answer_sha256: 'ab', governance_flag: false, ts: 1782083680 });
  const kp = slh_dsa_sha2_256f.keygen();
  const sig = slh_dsa_sha2_256f.sign(msg, kp.secretKey, ctx);
  const good = slh_dsa_sha2_256f.verify(sig, msg, kp.publicKey, ctx) === true;
  const bad = sig.slice(); bad[100] ^= 0xff;
  const tamperRejected = slh_dsa_sha2_256f.verify(bad, msg, kp.publicKey, ctx) === false;
  const noCtxRejected = slh_dsa_sha2_256f.verify(sig, msg, kp.publicKey) === false; // context genuinely bound
  const sizesOk = kp.publicKey.length === 64 && sig.length === 49856;
  const ok = good && tamperRejected && noCtxRejected && sizesOk;
  return { ok, results: { good, tamperRejected, noCtxRejected, sizesOk } };
}

export { THRONDAR_SLH_KEY_ID, THRONDAR_SLH_PUBKEY_HEX };
