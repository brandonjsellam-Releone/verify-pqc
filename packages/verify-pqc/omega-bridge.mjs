/*!
 * omega-bridge — TRELYAN OMEGA Layer 4 (Bridge) hybrid-key + entropy core (reference, DRAFT). The HONEST, hardware-free
 * slice of the blueprint's "QKD + Hybrid Cryptography" layer:
 *   1. A real SP 800-90B §6.3.1 Most-Common-Value (MCV) MIN-ENTROPY ESTIMATOR over supplied bytes (a lower-bound estimate,
 *      not a certification), + an accept/reject gate.
 *   2. A hybrid-key KDF COMBINER: fold multiple keying-material sources (a QKD-key slot ∥ a PQ-KEM shared secret ∥ a
 *      classical secret) into one session key via HKDF-SHA256 with per-slot domain separation. Security is the standard
 *      hybrid argument: the output is secret if HKDF is secure AND at least one *required* input is secret.
 *   3. A PQ-signed KEY-DERIVATION ATTESTATION (via pqseal: ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519) recording which sources
 *      contributed + the entropy estimate — verifiable offline, fail-closed.
 *
 * WHAT IS MOCK / GATED (claim hygiene — Dorit Dor will grill this):
 *   • There is NO QKD hardware here. `qkdSessionMock()` is a CLEARLY-LABELLED interface mock (OS CSPRNG bytes + a fake
 *     QBER field) so the shape exists for a future certified integration — it NEVER produces or claims real quantum keys.
 *   • `getEntropyMock()` returns OS CSPRNG bytes (crypto.getRandomValues via @noble randomBytes), labelled MOCK_CSPRNG —
 *     NEVER "quantum randomness". True QRNG needs certified hardware (owner-gated).
 *   • The MCV estimator is a single SP 800-90B IID estimator — NOT the full 90B validation battery (non-IID track,
 *     restart tests, lab process). It is a sanity lower-bound, reported as such.
 *   • True m-of-n threshold secret-sharing / MPC (BLS) is NOT implemented — `thresholdSecretShare()` is GATED (throws).
 *     The combiner here is a hybrid KDF (OR-security of inputs), not Shamir/MPC.
 *   • This is the (unaudited) composition layer over @noble/{hashes,curves,post-quantum}. Self-test: node omega-bridge.mjs
 */
import { seal, openSeal } from './pqseal.mjs';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';

const COMBINE_INFO_TAG = 'trelyan-omega-bridge-combine-v1';
const ATTEST_TAG = utf8ToBytes('trelyan-omega-bridge-attest-v1');
const SLOTS = ['qkd', 'kem', 'classical'];   // canonical slot order (domain separation labels)

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const toBytes = (x) => (x instanceof Uint8Array ? x : utf8ToBytes(String(x)));

/* ============================ 1. Entropy estimation (SP 800-90B §6.3.1 MCV) ============================ */

/**
 * minEntropyMCV(bytes) — SP 800-90B §6.3.1 Most-Common-Value min-entropy estimate over 8-bit symbols.
 * Returns min-entropy PER BYTE (0..8). This is a statistical LOWER-BOUND ESTIMATE assuming IID samples — NOT a guarantee
 * and NOT the full 90B battery. For a meaningful estimate SP 800-90B expects a large sample (≥ ~1e6); small n is flagged.
 *   p̂ = maxCount/n ; p_u = min(1, p̂ + 2.576·sqrt(p̂(1−p̂)/(n−1))) ; H_min = −log2(p_u)   (per 8-bit symbol)
 */
export function minEntropyMCV(bytes) {
  const b = toBytes(bytes); const n = b.length;
  if (n < 2) return { perByte: 0, perBit: 0, n, reliable: false, note: 'need >= 2 samples' };
  const counts = new Uint32Array(256);
  for (let i = 0; i < n; i++) counts[b[i]]++;
  let maxCount = 0, distinct = 0;
  for (let s = 0; s < 256; s++) { if (counts[s]) distinct++; if (counts[s] > maxCount) maxCount = counts[s]; }
  const pHat = maxCount / n;
  const pu = Math.min(1, pHat + 2.576 * Math.sqrt((pHat * (1 - pHat)) / (n - 1)));
  const perByte = -Math.log2(pu);
  return {
    perByte, perBit: perByte / 8, n, distinct, maxCount, pHat, pUpper: pu,
    reliable: n >= 1_000_000,
    note: n >= 1_000_000 ? 'ok' : `estimate weak for n=${n} (SP 800-90B expects ~1e6 samples); treat as a coarse sanity lower bound`,
  };
}

/** entropyReport(bytes) — human/machine report combining the MCV estimate with a distinct-symbol sanity flag. */
export function entropyReport(bytes) {
  const mcv = minEntropyMCV(bytes);
  const warnings = [];
  if (!mcv.reliable) warnings.push(mcv.note);
  if (mcv.distinct != null && mcv.distinct < 32 && mcv.n >= 256) warnings.push(`only ${mcv.distinct} distinct byte values in ${mcv.n} samples — possible low-entropy source`);
  return { estimator: 'SP800-90B-6.3.1-MCV', min_entropy_per_byte: mcv.perByte, min_entropy_per_bit: mcv.perBit, samples: mcv.n, distinct: mcv.distinct, reliable: mcv.reliable, warnings };
}

/**
 * acceptEntropy(bytes, { minBitsPerByte = 7.0, requireReliable = false }) — a gate: accept only if the MCV lower-bound ≥
 * threshold. Fail-closed. NOTE the estimator is CONSERVATIVE for small n (the confidence bound is loose, so it UNDER-states
 * entropy for n < ~1e6). That means the default gate may reject strong-but-small samples — which is safe. The unsafe
 * direction is trusting a small-sample estimate for a security-critical key: set `requireReliable: true` to REJECT any
 * sample the estimator flags `reliable:false` (n < 1e6), rather than accept on a statistically weak estimate.
 */
export function acceptEntropy(bytes, { minBitsPerByte = 7.0, requireReliable = false } = {}) {
  const r = entropyReport(bytes);
  if (requireReliable && !r.reliable) return { accepted: false, min_entropy_per_byte: r.min_entropy_per_byte, threshold: minBitsPerByte, report: r, reason: 'reliable estimate required but sample too small (n < 1e6)' };
  return { accepted: r.min_entropy_per_byte >= minBitsPerByte, min_entropy_per_byte: r.min_entropy_per_byte, threshold: minBitsPerByte, report: r };
}

/* ============================ 2. Hybrid-key KDF combiner ============================ */

/**
 * hybridCombine(inputs, opts) — fold available keying material into ONE session key via HKDF-SHA256.
 *   inputs: { qkd?: bytes, kem?: bytes, classical?: bytes }   (any subset; each is raw secret keying material)
 *   opts.requirePresent: string[]  slots that MUST be present (default ['kem','classical'] — always a PQ + a classical leg)
 *   opts.length: output key bytes (default 32) ; opts.info: extra context string ; opts.salt: optional HKDF salt bytes
 * Returns { key(hex), contributed: [...slots in canonical order], info } — the `info` string binds WHICH slots contributed
 * + their order + the context, so a verifier re-derives the exact key. Security (honest): the output key is
 * indistinguishable from random if HKDF-SHA256 is secure AND ≥1 contributing slot is secret — the standard hybrid-KDF
 * argument. This is NOT threshold secret-sharing (a missing required slot FAILS; it does not reconstruct).
 * Slot names are RESERVED to {qkd, kem, classical}: only those contribute (any other key in `inputs` is IGNORED, never
 * folded in), and the label‖len‖bytes framing is injective under those reserved names. requirePresent must name reserved
 * slots only (a non-slot name would otherwise pass a presence check yet never contribute — rejected here, fail-closed).
 */
export function hybridCombine(inputs, opts = {}) {
  if (!inputs || typeof inputs !== 'object') throw new Error('omega-bridge: inputs object required');
  // reject unknown slots (sweep R1): a typo'd source key (e.g. 'kdm' for 'kem') would otherwise be SILENTLY ignored,
  // yielding a weaker composition than the caller intended (2 legs where they meant 3). Fail-closed on any non-reserved key.
  for (const k of Object.keys(inputs)) if (!SLOTS.includes(k)) throw new Error(`omega-bridge: unknown input slot '${k}' (reserved: ${SLOTS.join(', ')}) — a typo would silently weaken the composition`);
  const require_ = opts.requirePresent ?? ['kem', 'classical'];
  for (const r of require_) {
    if (!SLOTS.includes(r)) throw new Error(`omega-bridge: requirePresent names a non-reserved slot '${r}' (reserved: ${SLOTS.join(', ')})`);
    if (!(r in inputs) || !inputs[r] || !toBytes(inputs[r]).length) throw new Error(`omega-bridge: required slot '${r}' missing/empty (fail-closed — no reconstruction)`);
  }
  const contributed = SLOTS.filter((s) => inputs[s] && toBytes(inputs[s]).length);
  if (!contributed.length) throw new Error('omega-bridge: no keying material');
  // domain-separated concatenation: label ‖ len ‖ bytes for each contributing slot, in canonical order (injective)
  const parts = [];
  for (const s of contributed) {
    const kb = toBytes(inputs[s]);
    const lab = utf8ToBytes(s + ':');
    const len = new Uint8Array(4); new DataView(len.buffer).setUint32(0, kb.length, false);
    parts.push(concatBytes(lab, len, kb));
  }
  const ikm = concatBytes(...parts);
  const info = utf8ToBytes(`${COMBINE_INFO_TAG}|slots=${contributed.join('+')}|${opts.info ?? ''}`);
  const salt = opts.salt ? toBytes(opts.salt) : new Uint8Array(0);
  const length = opts.length ?? 32;
  const key = hkdf(sha256, ikm, salt, info, length);
  return { key: bytesToHex(key), contributed, info: `slots=${contributed.join('+')}|${opts.info ?? ''}`, length };
}

/* ============================ 3. PQ-signed key-derivation attestation ============================ */

// signable core of an attestation: binds session id, contributing slots, entropy estimate, combiner info + a NON-secret
// key COMMITMENT (SHA-256 of the derived key — never the key itself) so the record can be published/verified safely.
function attestCore(a) {
  return { v: 'omega-bridge-attest-1', session_id: a.session_id, contributed: a.contributed, combine_info: a.combine_info, key_commitment: a.key_commitment, entropy: a.entropy, ts: a.ts ?? null };
}

/**
 * attestKeyDerivation({ sessionId, combined, entropy, ts }, signers) — PQ-sign a record that a session key was derived
 * from `combined.contributed` sources with the given entropy estimate. `combined` is the hybridCombine() result. Signs a
 * key COMMITMENT (hash), never the key. signers = pqseal signer set (recommend ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519).
 */
export function attestKeyDerivation({ sessionId, combined, entropy, ts }, signers) {
  if (!combined || !combined.key) throw new Error('omega-bridge: combined (hybridCombine result) required');
  const core = attestCore({
    session_id: sessionId, contributed: combined.contributed, combine_info: combined.info,
    key_commitment: bytesToHex(sha256(concatBytes(ATTEST_TAG, hexToBytes(combined.key)))),
    entropy: entropy ? { estimator: entropy.estimator, min_entropy_per_byte: entropy.min_entropy_per_byte, reliable: entropy.reliable } : null,
    ts: ts ?? null,
  });
  const coreBytes = utf8ToBytes(canon(core));
  return { core, seal: seal(coreBytes, signers) };
}

/** verifyKeyAttestation(att, opts) — TOTAL / fail-closed. opts.trusted + opts.requireKinds pin the signer. If opts.key
 *  (the actual derived key hex) is supplied, also checks the key commitment matches. */
export function verifyKeyAttestation(att, opts = {}) {
  const fail = (reason) => ({ verified: false, sealOk: false, commitmentOk: null, reason });
  try {
    if (!att || !att.core || !att.seal) return fail('shape');
    const coreBytes = utf8ToBytes(canon(attestCore(att.core)));
    const sv = openSeal(coreBytes, att.seal, { trusted: opts.trusted, requireKinds: opts.requireKinds, requireDistinctLegs: true });
    let commitmentOk = null;
    if (opts.key) commitmentOk = att.core.key_commitment === bytesToHex(sha256(concatBytes(ATTEST_TAG, hexToBytes(opts.key))));
    const verified = sv.verified && (opts.key ? commitmentOk : true);
    return { verified, sealOk: sv.verified, commitmentOk, kinds: sv.kinds, reason: verified ? 'ok' : (!sv.verified ? 'seal invalid' : 'key commitment mismatch') };
  } catch { return fail('exception'); }
}

/* ============================ 4. MOCK sources (clearly labelled — NOT hardware) ============================ */

/** getEntropyMock(nBytes) — OS CSPRNG bytes, LABELLED MOCK. This is NOT quantum randomness. A production Layer 5/QRNG or
 *  Layer 4/QKD source would replace this via the same shape after a certified-hardware integration (owner-gated). */
export function getEntropyMock(nBytes = 32) {
  return { bytes: randomBytes(nBytes), source: 'MOCK_CSPRNG', warning: 'OS CSPRNG (crypto.getRandomValues) — NOT quantum. Do not label as quantum randomness.' };
}

/** qkdSessionMock(nBytes) — a clearly-labelled MOCK of a QKD key-delivery session. NO QKD hardware is involved; the key
 *  material is OS CSPRNG and the QBER is a placeholder. Exists only to define the interface shape for a future certified
 *  ETSI-QKD-014/15/16 integration (owner-gated). NEVER claim this delivered a quantum key. */
export function qkdSessionMock(nBytes = 32) {
  return {
    key: randomBytes(nBytes), source: 'MOCK_QKD_INTERFACE', qber: null, device_id: 'MOCK', protocol: 'MOCK (interface only)',
    warning: 'MOCK — no QKD hardware. Key is OS CSPRNG. Certified integration (ID Quantique/Toshiba/ETSI QKD) is owner-gated; never claim a real quantum key from this.',
  };
}

/* ============================ 5. Gated: true threshold secret-sharing / MPC ============================ */
/** thresholdSecretShare() — real m-of-n Shamir secret-sharing / BLS-MPC key escrow (blueprint Layer 4) is NOT implemented.
 *  The hybridCombine() above is a KDF combiner (OR-security), not secret-sharing. True threshold/MPC needs careful design
 *  + review; gate it rather than ship a fragile version. Machine-enforced: always throws. */
export function thresholdSecretShare() {
  throw new Error('OMEGA_MPC_THRESHOLD_GATED: true m-of-n secret-sharing / BLS-MPC key escrow is not implemented (needs dedicated design + audit). Use hybridCombine() for hybrid-KDF composition, which is OR-secure but NOT threshold reconstruction.');
}

/* ---------------------------------------- self-test: node omega-bridge.mjs ---------------------------------------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { slh_dsa_sha2_256f } = await import('@noble/post-quantum/slh-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const seed = (n, len = 32) => new Uint8Array(len).fill(n);

  // --- entropy estimator ---
  // MCV's confidence bound underestimates badly for small n, so a meaningful >=7 bits/byte estimate needs a large sample
  // (SP 800-90B expects ~1e6). We use a big sample for the accept gate and a small one to demonstrate the caveat.
  const bigChunks = []; for (let i = 0; i < 16; i++) bigChunks.push(randomBytes(65536));  // getRandomValues caps at 64KB/call
  const big = concatBytes(...bigChunks);   // ~1.05e6 samples
  const rBig = entropyReport(big);
  ok(rBig.min_entropy_per_byte > 7.0 && rBig.reliable, 'MCV: 1e6 CSPRNG bytes → >7 bits/byte, reliable');
  const small = randomBytes(4096);
  const rSmall = entropyReport(small);
  ok(rSmall.min_entropy_per_byte < rBig.min_entropy_per_byte, 'MCV: small sample underestimates (loose confidence bound)');
  ok(rSmall.warnings.some((w) => /1e6|coarse|weak/.test(w)), 'entropyReport: small-sample reliability warning present');
  const bad = new Uint8Array(4096).fill(7);              // constant → zero entropy
  ok(minEntropyMCV(bad).perByte === 0, 'MCV: constant stream → 0 min-entropy');
  ok(!acceptEntropy(bad).accepted && acceptEntropy(big).accepted, 'acceptEntropy: gate rejects constant, accepts large CSPRNG sample');
  // requireReliable: reject a small (unreliable) sample even if its point estimate would pass, but accept the big one
  ok(!acceptEntropy(small, { minBitsPerByte: 0, requireReliable: true }).accepted, 'acceptEntropy: requireReliable rejects small sample');
  ok(acceptEntropy(big, { requireReliable: true }).accepted, 'acceptEntropy: requireReliable accepts 1e6 sample');

  // --- hybrid combiner ---
  const kem = seed(1), cls = seed(2), qkd = seed(3);
  const c1 = hybridCombine({ kem, classical: cls });
  const c1b = hybridCombine({ kem, classical: cls });
  ok(c1.key === c1b.key && c1.key.length === 64, 'combine: deterministic, 32-byte key');
  ok(c1.contributed.join('+') === 'kem+classical', 'combine: contributed slots recorded in canonical order');
  const c2 = hybridCombine({ qkd, kem, classical: cls });
  ok(c2.key !== c1.key && c2.contributed[0] === 'qkd', 'combine: adding qkd slot changes key + is bound into info');
  // required slot missing → fail-closed
  let threw = false; try { hybridCombine({ kem }); } catch { threw = true; }
  ok(threw, 'combine: missing required classical slot rejected (no reconstruction)');
  // requirePresent naming a non-reserved slot → rejected (would otherwise pass presence but never contribute)
  let badSlot = false; try { hybridCombine({ kem, classical: cls, evil: seed(9) }, { requirePresent: ['evil'] }); } catch { badSlot = true; }
  ok(badSlot, 'combine: requirePresent with a non-reserved slot rejected');
  // a non-reserved key in inputs is now REJECTED (sweep R1: silent-ignore would weaken the composition on a typo)
  let unknownSlot = false; try { hybridCombine({ kem, classical: cls, evil: seed(9) }); } catch { unknownSlot = true; }
  ok(unknownSlot, 'combine: unknown input slot rejected (fail-closed — no silent weakening on a typo)');
  // domain separation: same bytes in different slots → different key
  const cA = hybridCombine({ kem: seed(9), classical: seed(2) });
  const cB = hybridCombine({ kem: seed(2), classical: seed(9) });
  ok(cA.key !== cB.key, 'combine: slot labels domain-separate identical material');

  // --- attestation ---
  const A = { alg: 'ML-DSA-87', ...ml_dsa87.keygen(seed(11)) };
  const B = { alg: 'SLH-DSA-256f', ...slh_dsa_sha2_256f.keygen(seed(22, 96)) };
  const C = (() => { const sk = seed(33); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })();
  const signers = [A, B, C];
  const trusted = { 'ML-DSA-87': A.publicKey, 'SLH-DSA-256f': B.publicKey, 'Ed25519': C.publicKey };
  const att = attestKeyDerivation({ sessionId: 's1', combined: c2, entropy: rBig, ts: 1 }, signers);
  const v = verifyKeyAttestation(att, { trusted, requireKinds: ['lattice', 'hash-based', 'classical'], key: c2.key });
  ok(v.verified && v.commitmentOk, 'attest: verifies (pinned 3-family) + key commitment matches');
  ok(!verifyKeyAttestation(att, { trusted, key: 'ff'.repeat(32) }).verified, 'attest: wrong key → commitment mismatch');
  const tampered = JSON.parse(JSON.stringify(att)); tampered.core.session_id = 's2';
  ok(!verifyKeyAttestation(tampered, { trusted }).verified, 'attest: tampered core rejected');
  ok(att.core.key_commitment && !JSON.stringify(att).includes(c2.key), 'attest: publishes key COMMITMENT, never the key');

  // --- mocks are labelled ---
  ok(getEntropyMock().source === 'MOCK_CSPRNG' && /NOT quantum/.test(getEntropyMock().warning), 'mock: entropy labelled MOCK, not quantum');
  ok(qkdSessionMock().source === 'MOCK_QKD_INTERFACE' && /no QKD hardware/.test(qkdSessionMock().warning), 'mock: qkd labelled interface-only');

  // --- threshold/MPC gate ---
  let gated = false; try { thresholdSecretShare(); } catch (e) { gated = /MPC_THRESHOLD_GATED/.test(e.message); }
  ok(gated, 'threshold secret-sharing / MPC is gated (throws)');

  console.log(`\nomega-bridge self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTest();
