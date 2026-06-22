/*!
 * @trelyan/verify-pqc/verify — unified post-quantum verification entry.
 *
 * One import for the full DUAL-PQC stack of THRONDAR's transparency-log Signed Tree Head:
 *   • ML-DSA-87 (FIPS-204) — the LOAD-BEARING gate (mldsa.mjs)
 *   • SLH-DSA-256f (FIPS-205) — the additive, NON-AUTHORITATIVE hash-based diversity leg (slhdsa.mjs)
 *
 * ML-DSA and Falcon are both lattice schemes; SLH-DSA is hash-based, so it gives true
 * algorithm-family diversity (handbook §4.2: prefer ML-DSA + SLH-DSA over FN-DSA). The SLH leg
 * can NEVER flip the verdict — `verifyThrondarStrong().verified` is exactly the ML-DSA result.
 */
export {
  verifyThrondarSth,
  verifyThrondarStrong,
  THRONDAR_STH_KEY_ID,
  THRONDAR_STH_PUBKEY_HEX,
  THRONDAR_STH_PINS,
} from './mldsa.mjs';

export {
  verifyThrondarSlh,
  selfTest as slhSelfTest,
  THRONDAR_SLH_KEY_ID,
  THRONDAR_SLH_PUBKEY_HEX,
} from './slhdsa.mjs';
