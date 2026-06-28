/*!
 * pqclaimgate — verified-claims-only gate for ~ZERO UNFLAGGED hallucination (reference, DRAFT, standalone).
 *
 * The engine behind "the AI you can put on the record": decompose an answer into atomic claims, run each
 * through INDEPENDENT verifiers (grounding/evidence, consensus, deterministic checks), and EMIT only claims
 * that pass — ABSTAIN or REJECT the rest — then PQ-attest the exact claim set + policy (ML-DSA-87).
 *
 * HONEST LIMITS (do not remove — council ruling):
 *  - Literal 0% hallucination is IMPOSSIBLE (model + verifier are both probabilistic). This drives UNFLAGGED
 *    hallucination toward ~0 by trading COVERAGE for PRECISION (the reject option). Report coverage/abstention.
 *  - `verified` means "passed the configured policy gates", NOT "true". `consensus` is agreement among the
 *    supplied agents, NOT ground truth. The attestation proves WHAT was checked (claims+evidence+verifiers+
 *    policy), NOT that the answer is correct.
 *  - Verifier INDEPENDENCE matters: two scores from the same model are not two verifiers — require >=2 distinct
 *    verifier TYPES, one of which is evidence-based. The renderer is part of the trust boundary: verified claims
 *    are rendered by a DETERMINISTIC template (no LLM paraphrase), abstained/rejected stay visible.
 * New, self-contained reference code; ML-DSA-87 attestation. Self-test: node pqclaimgate.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const CTX = utf8ToBytes('trelyan-claimgate-attestation-v1');
const sha = (s) => bytesToHex(sha256(typeof s === 'string' ? utf8ToBytes(s) : s));
function canonicalize(v) {
  if (v === undefined) throw new Error('canonicalize: undefined (fail-closed)');
  if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('canonicalize: non-finite');
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}
const mean = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0);
const round = (x, n = 3) => Math.round(x * 10 ** n) / 10 ** n;
const dissentRatio = (c) => (c && c.total_considered ? (c.dissent ? c.dissent.count : 0) / c.total_considered : 0);
const isAtomicClaim = (s) => typeof s === 'string' && s.trim().length > 0;

export const DEFAULT_POLICY = { k: 2, consensusThreshold: 0.6, maxDissentRatio: 0.25, minEvidence: 1, confidenceThreshold: 0.7 };

/* ---------- the emit / abstain / reject decision ---------- */
export function decide(claim, policy = DEFAULT_POLICY) {
  if (!isAtomicClaim(claim.claim)) return { status: 'rejected', reason: 'MALFORMED' };
  const verifiers = claim.verifiers || [];
  if (verifiers.some((v) => v.verdict === 'FAIL')) return { status: 'rejected', reason: 'VERIFIER_FAIL' };

  const grounded = (claim.evidence_refs || []).filter((e) => e.grounded && e.ef_verdict !== 'fail');
  const passes = verifiers.filter((v) => v.verdict === 'PASS');
  const independentTypes = new Set(passes.map((v) => v.type));
  const hasEvidenceVerifier = passes.some((v) => v.type === 'pqef' || v.type === 'source_attestation');

  const consensusOK = (claim.consensus?.strength ?? 0) >= policy.consensusThreshold && dissentRatio(claim.consensus) <= policy.maxDissentRatio;
  const evidenceOK = grounded.length >= policy.minEvidence;
  const verifierOK = passes.length >= policy.k && independentTypes.size >= Math.min(policy.k, 2) && hasEvidenceVerifier;

  const evScore = mean(grounded.map((e) => e.ef_score ?? 0));
  const verifierScore = mean(passes.map((v) => v.score ?? 1));
  claim.confidence = round(Math.min(claim.consensus?.strength ?? 0, evScore, verifierScore)); // weakest link; NOT calibrated truth
  const confidenceOK = claim.confidence >= policy.confidenceThreshold;

  if (consensusOK && evidenceOK && verifierOK && confidenceOK) return { status: 'verified', reason: 'POLICY_PASS' };
  const reason = !evidenceOK ? 'NO_EVIDENCE' : !verifierOK ? 'VERIFIER_SHORTFALL' : !consensusOK ? 'LOW_CONSENSUS' : 'LOW_CONFIDENCE';
  return { status: 'abstained', reason };
}

/* ---------- the gate ---------- */
export class ClaimGate {
  constructor({ verifiers, policy = DEFAULT_POLICY } = {}) { this.verifiers = verifiers || []; this.policy = policy; }
  async evaluate(claim) {
    const results = [];
    for (const v of this.verifiers) { const r = await v.check(claim, claim.evidence_refs || []); results.push({ ...r }); }
    claim.verifiers = results;
    const { status, reason } = decide(claim, this.policy);
    claim.status = status; claim.reason_code = reason;
    return claim;
  }
  async evaluateAll(claims) { const out = []; for (const c of claims) out.push(await this.evaluate(c)); return out; }
  assemble(query, claims) { return assembleAnswer(query, claims, this.policy); }
}

// deterministic, paraphrase-free render of verified claims (the renderer is inside the trust boundary)
function renderClaims(claims) {
  return claims.map((c) => `- ${c.claim} [${(c.evidence_refs || []).map((e) => e.ref).join(', ')}] (confidence ${c.confidence})`).join('\n');
}
export function assembleAnswer(query, claims, policy = DEFAULT_POLICY) {
  const verified = claims.filter((c) => c.status === 'verified');
  const abstained = claims.filter((c) => c.status === 'abstained');
  const rejected = claims.filter((c) => c.status === 'rejected');
  const rendered = verified.length ? renderClaims(verified) : 'No claims could be verified for this query. See the unverified section.';
  return {
    query, mode: 'verified-claims-only', policy,
    emitted: { status: verified.length === 0 ? 'none' : (abstained.length === 0 && rejected.length === 0 ? 'complete' : 'partial'), rendered, verified_claims: verified },
    abstained, rejected,
    coverage: claims.length ? round(verified.length / claims.length) : 0,
    honesty_note: 'verified = passed policy gates, NOT true; consensus = agent agreement, NOT ground truth; attestation proves WHAT was checked, not correctness.',
  };
}

/* ---------- PQ attestation of the emitted claim set + policy ---------- */
const manifestOf = (env) => ({
  query_sha256: sha(env.query), mode: env.mode, policy: env.policy, coverage: env.coverage,
  claims: [...env.emitted.verified_claims, ...env.abstained, ...env.rejected]
    .map((c) => ({ id: c.id, claim_sha256: sha(c.claim), status: c.status, reason: c.reason_code || null, confidence: c.confidence ?? null,
      evidence_sha256: c.evidence_refs != null ? sha(canonicalize(c.evidence_refs)) : null }))   // bind per-claim citations (3rd sweep — forge-proof provenance)
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  sources_sha256: env.sources != null ? sha(canonicalize(env.sources)) : null,                   // bind the retrieved sources (3rd sweep)
  moa_sha256: env.moa != null ? sha(canonicalize(env.moa)) : null,                               // bind the MoA consensus/dissent (3rd sweep)
  ts: env.ts ?? null,
});
export function attestClaimGate(env, order, opts = {}) {
  env.ts = opts.ts ?? env.ts ?? null;
  const manifest = manifestOf(env);
  env.attestation = {
    manifest, signer_pub_hex: bytesToHex(order.publicKey),
    sig_hex: bytesToHex(ml_dsa87.sign(utf8ToBytes(canonicalize(manifest)), order.secretKey, { context: CTX })),
  };
  return env;
}
// verify with a PINNED order key: signature valid AND the envelope's claims still match the signed manifest.
export function verifyClaimGate(env, trustedOrderPub) {
 try { // TOTAL (3rd sweep): a malformed envelope fails CLOSED, never throws
  const a = env && env.attestation;
  if (!a) return { verified: false, reason: 'no attestation' };
  let sigOk = false;
  try { sigOk = a.signer_pub_hex.toLowerCase() === bytesToHex(trustedOrderPub).toLowerCase() && ml_dsa87.verify(hexToBytes(a.sig_hex), utf8ToBytes(canonicalize(a.manifest)), trustedOrderPub, { context: CTX }); } catch { sigOk = false; }
  // BUG (3rd code-security sweep): rebind the WHOLE manifest, not just .claims — otherwise query/mode/policy/coverage/ts
  // that the envelope DISPLAYS are unsigned, and an attacker mutates them while keeping the claim set intact (verify stayed true).
  const manifestMatch = canonicalize(manifestOf(env)) === canonicalize(a.manifest);
  const claimsMatch = canonicalize(manifestOf(env).claims) === canonicalize(a.manifest.claims);
  const verified = sigOk && manifestMatch;
  return { verified, sigOk, manifestMatch, claimsMatch, reason: verified ? 'attestation valid; the FULL manifest (query/mode/policy/coverage/claims/ts) binds the envelope' : !sigOk ? 'signature invalid / not the pinned order key' : 'envelope does not match the signed manifest (tampered query/coverage/policy/mode/claims/ts)' };
 } catch { return { verified: false, sigOk: false, manifestMatch: false, claimsMatch: false, reason: 'malformed envelope' }; }
}

/* ---------- reference (stub) verifiers — pluggable; real ones wrap RAG/NLI/code-exec/pqef ---------- */
export const stubEvidence = { type: 'pqef', id: 'stub-pqef', async check(_c, refs) {
  const r = (refs || []).map((e) => !e.grounded ? { verdict: 'ABSTAIN', score: 0 } : /^bogus:/.test(e.ref) ? { verdict: 'FAIL', score: 0 } : { verdict: 'PASS', score: 0.85 });
  const fail = r.find((x) => x.verdict === 'FAIL'); if (fail) return { type: 'pqef', id: 'stub-pqef', ...fail };
  const pass = r.find((x) => x.verdict === 'PASS'); return pass ? { type: 'pqef', id: 'stub-pqef', ...pass } : { type: 'pqef', id: 'stub-pqef', verdict: 'ABSTAIN', score: 0 };
} };
export const stubSourceAttestation = { type: 'source_attestation', id: 'stub-src', async check(_c, refs) {
  const grounded = (refs || []).filter((e) => e.grounded).length; const ok = grounded > 0 && grounded === (refs || []).length;
  return { type: 'source_attestation', id: 'stub-src', verdict: ok ? 'PASS' : 'ABSTAIN', score: ok ? 1 : 0 };
} };
export const stubConsensusGate = { type: 'consensus_gate', id: 'stub-cons', async check(c) {
  const ok = (c.consensus?.strength ?? 0) >= 0.6 && dissentRatio(c.consensus) <= 0.25;
  return { type: 'consensus_gate', id: 'stub-cons', verdict: ok ? 'PASS' : 'ABSTAIN', score: c.consensus?.strength ?? 0 };
} };

/* ---------- self-test: node pqclaimgate.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const order = ml_dsa87.keygen(new Uint8Array(32).fill(51));
  const fullConsensus = { strength: 0.8, agreement_count: 3, total_considered: 3, dissent: { count: 0, reasons: [] } };
  const claims = [
    { id: 'A', claim: 'ML-KEM-1024 ciphertext is 1568 bytes.', evidence_refs: [{ ref: 'src:fips203', selector: '1568', grounded: true, ef_score: 0.9 }], consensus: fullConsensus, verifiers: [] },
    { id: 'B', claim: 'The attacker key was rotated last Tuesday.', evidence_refs: [], consensus: fullConsensus, verifiers: [] },           // no evidence -> abstain
    { id: 'C', claim: 'ML-DSA private keys are 12 bytes.', evidence_refs: [{ ref: 'bogus:made-up', selector: '12', grounded: true, ef_score: 0.1 }], consensus: { strength: 0.9, total_considered: 3, dissent: { count: 0 } }, verifiers: [] }, // bogus -> FAIL -> reject
    { id: 'D', claim: 'Falcon is the best signature.', evidence_refs: [{ ref: 'src:opinion', grounded: true, ef_score: 0.5 }], consensus: { strength: 0.4, total_considered: 5, dissent: { count: 3 } }, verifiers: [] }, // low consensus -> abstain
  ];
  const gate = new ClaimGate({ verifiers: [stubEvidence, stubSourceAttestation, stubConsensusGate] });

  return gate.evaluateAll(claims).then((evaluated) => {
    ok(evaluated.find((c) => c.id === 'A').status === 'verified', 'grounded + consensus + 3 independent verifiers -> VERIFIED');
    ok(evaluated.find((c) => c.id === 'B').status === 'abstained' && evaluated.find((c) => c.id === 'B').reason_code === 'NO_EVIDENCE', 'no evidence -> ABSTAINED (NO_EVIDENCE)');
    ok(evaluated.find((c) => c.id === 'C').status === 'rejected' && evaluated.find((c) => c.id === 'C').reason_code === 'VERIFIER_FAIL', 'bogus source -> REJECTED (VERIFIER_FAIL)');
    ok(evaluated.find((c) => c.id === 'D').status === 'abstained' && evaluated.find((c) => c.id === 'D').reason_code === 'LOW_CONSENSUS', 'low consensus -> ABSTAINED (LOW_CONSENSUS)');

    const env = gate.assemble('What are the PQC parameter sizes?', evaluated);
    ok(env.emitted.verified_claims.length === 1 && env.emitted.status === 'partial', 'only the 1 verified claim is emitted (partial)');
    ok(env.coverage === 0.25, 'coverage reported honestly (1/4)');
    // the rendered answer must NOT contain any abstained/rejected claim text (zero unflagged hallucination)
    ok(!env.emitted.rendered.includes('rotated last Tuesday') && !env.emitted.rendered.includes('12 bytes') && !env.emitted.rendered.includes('best signature'), 'abstained/rejected claims are NOT in the emitted answer');
    ok(env.abstained.length === 2 && env.rejected.length === 1, 'abstained/rejected claims remain visible (flagged, not dropped)');

    // attestation
    attestClaimGate(env, order, { ts: 1000 });
    ok(verifyClaimGate(env, order.publicKey).verified === true, 'claim-gate attestation verifies under the pinned order key');
    // tamper an emitted claim -> claims no longer match the signed manifest
    const tampered = JSON.parse(JSON.stringify(env)); tampered.emitted.verified_claims[0].claim = 'ML-KEM-1024 ciphertext is 9 bytes.';
    ok(verifyClaimGate(tampered, order.publicKey).claimsMatch === false, 'tampered emitted claim -> claimsMatch false (attestation catches it)');
    // wrong key -> not verified
    const other = ml_dsa87.keygen(new Uint8Array(32).fill(61));
    ok(verifyClaimGate(env, other.publicKey).verified === false, 'attestation under a non-order key -> NOT verified');

    console.log('pqclaimgate self-test: ' + pass + ' pass, ' + fail + ' fail');
    if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
  });
}
if (typeof process !== 'undefined' && process.argv && /pqclaimgate\.mjs$/.test(process.argv[1] || '')) selfTest();
