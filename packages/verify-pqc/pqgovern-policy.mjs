/*!
 * pqgovern-policy — the GOVERN leg: a SIGNED, VERSIONED AI GOVERNANCE POLICY the admission gate enforces.
 *
 * Completes the NIST AI RMF quartet over the trilogy: MAP (pqaibom) ∧ MEASURE (pqeval) ∧ MANAGE (pqtrace)
 * are bound to one model by pqgovernance-record; GOVERN is the ORG's signed statement of WHAT admission
 * criteria it commits to. Today pqgovernance-gate takes an ad-hoc inline `policy` object — so an auditor
 * can verify THAT a model's record passed, but not WHICH policy gated it, nor that the policy was set by
 * an authorized owner. This module makes the admission CRITERIA THEMSELVES verifiable evidence: a
 * compliance owner signs a policy once (pqseal N-leg), and evaluateUnderPolicy verifies+enforces that
 * SIGNED policy, surfacing policy_id/version/issuer in the decision. The evidence chain now answers:
 * "record R was admitted under ComplianceOwner's signed policy P (v3, effective 2026-01-01), which
 * required minAibomGrade B ∧ distinct signers ∧ fully-pinned drift."
 *
 * HONEST SCOPE (claim-hygiene LAW): a signed policy proves WHO set the criteria and WHAT they were and
 * WHEN it was effective — NOT that the criteria are ADEQUATE for any regime. The authoritative WHO is the
 * PINNED SIGNING KEY (sealOpts.trusted); `issuer` is a self-declared label that only agrees with it. It
 * is not a certification,
 * not compliance, not legal advice. Like every leg, "a signed lie is possible": the owner could sign a
 * weak policy; the value is that the policy is authenticated, versioned, and bound into the admission
 * record so weakness is AUDITABLE, not hidden. evaluateUnderPolicy is TOTAL/fail-closed: an unsigned,
 * unpinned, tampered, or (optionally) out-of-window policy => admit:false, regardless of the record.
 *  Self-test: node pqgovern-policy.mjs
 */
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { seal, openSeal } from './pqseal.mjs';
import { evaluateGate, gateReport } from './pqgovernance-gate.mjs';

const V = 'pqgov-policy-1';
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const isInt = (n) => Number.isInteger(n);
// the exact criteria set pqgovernance-gate consumes — canonicalized so the policy hash is stable.
const CRITERIA_KEYS = ['minAibomGrade', 'minEvalPosture', 'requireDistinctSigners', 'requireDriftChecked', 'requireFullyPinnedDrift'];
function normalizeCriteria(c = {}) {
  const out = {};
  out.minAibomGrade = (c.minAibomGrade == null) ? null : String(c.minAibomGrade).toUpperCase();
  out.minEvalPosture = (c.minEvalPosture == null) ? null : String(c.minEvalPosture).toUpperCase();
  out.requireDistinctSigners = !!c.requireDistinctSigners;
  out.requireDriftChecked = !!c.requireDriftChecked;
  out.requireFullyPinnedDrift = !!c.requireFullyPinnedDrift;
  return out;
}

/** build the canonical (unsigned) policy. criteria = the gate policy the org commits to. */
export function buildPolicy(spec = {}) {
  const effective_ts = isInt(spec.effective_ts) ? spec.effective_ts : 0;
  const expiry_ts = isInt(spec.expiry_ts) ? spec.expiry_ts : null;
  if (expiry_ts != null && expiry_ts < effective_ts) throw new Error('expiry_ts must be >= effective_ts');
  return {
    v: V,
    policy_id: typeof spec.policy_id === 'string' && spec.policy_id ? spec.policy_id : 'policy',
    version: isInt(spec.version) && spec.version >= 0 ? spec.version : 0,
    effective_ts, expiry_ts,
    issuer: typeof spec.issuer === 'string' ? spec.issuer : null,
    description: typeof spec.description === 'string' ? spec.description : null,
    criteria: normalizeCriteria(spec.criteria),
  };
}
/** hash of the canonical policy (stable id for anchoring / cross-reference). */
export function policyHash(policy) { return bytesToHex(sha512(utf8ToBytes(canon(policy)))); }
/** sign the policy with the GOVERNANCE OWNER's signer set ([{alg, secretKey, publicKey}, ...]). */
export function signPolicy(policy, signers) {
  const envelope = seal(utf8ToBytes(canon(policy)), signers);
  return { policy, envelope };
}
/** verifyPolicy({policy, envelope}, opts) — TOTAL/fail-closed. Pin the owner via opts.sealOpts.trusted.
 *  opts.atTs (integer): if given, enforce the effective/expiry window. */
export function verifyPolicy(signed, opts = {}) {
  const FAIL = (why) => ({ verified: false, why, sealOk: false, ownerAnchored: false, windowOk: null, policy: null, policy_hash: null });
  try {
    if (!signed || typeof signed !== 'object' || !signed.policy || !signed.envelope) return FAIL('malformed signed policy');
    const p = signed.policy;
    if (p.v !== V || typeof p.policy_id !== 'string' || p.policy_id === '' || !isInt(p.version) || p.version < 0 || !isInt(p.effective_ts)
      || (p.expiry_ts != null && !isInt(p.expiry_ts)) || !p.criteria || typeof p.criteria !== 'object') return FAIL('malformed policy body');
    // defensive parsing (council): verifyPolicy independently enforces the same window sanity buildPolicy does —
    // a hand-crafted signed policy with expiry < effective is malformed and rejected here, not just at build.
    if (p.expiry_ts != null && p.expiry_ts < p.effective_ts) return FAIL('malformed policy body: expiry_ts < effective_ts');
    // the canonical form must round-trip — a hand-crafted policy with extra/renamed fields cannot ride under
    // the signature and then be re-read differently (re-normalize fixpoint over criteria + shape).
    // TRUE fixpoint of buildPolicy: reconstruct EVERY field with buildPolicy's own coercions (issuer/description
    // string-or-null, criteria normalized) — so a signed body carrying a type buildPolicy would never mint (e.g.
    // an OBJECT issuer, or a blank policy_id) fails the reCanon equality and is rejected as non-canonical.
    const reCanon = canon({ v: V, policy_id: p.policy_id, version: p.version, effective_ts: p.effective_ts, expiry_ts: p.expiry_ts ?? null, issuer: (typeof p.issuer === 'string' ? p.issuer : null), description: (typeof p.description === 'string' ? p.description : null), criteria: normalizeCriteria(p.criteria) });
    if (reCanon !== canon(p)) return FAIL('policy is not in canonical form (non-normalizable fields)');
    const sealOpts = opts.sealOpts || {};
    const hasPin = sealOpts.trusted && typeof sealOpts.trusted === 'object' && Object.keys(sealOpts.trusted).length > 0;
    if (!hasPin && !opts.allowUnpinnedSeal) return FAIL('sealOpts.trusted (governance-owner pubkey pins) required, or pass allowUnpinnedSeal:true to accept a self-consistent seal without authenticating the owner');
    // seal + everything downstream operate on the SANITIZED canonical bytes (reCanon, already proven equal to
    // canon(p)), NOT the caller's object — so a live/Proxy policy cannot present strict criteria at verify and
    // lax criteria at the gate read (council TOCTOU). The returned policy is a FROZEN plain snapshot.
    const sealRes = openSeal(utf8ToBytes(reCanon), signed.envelope, sealOpts);
    const sealOk = !!sealRes.verified;
    if (!sealOk) return { verified: false, why: 'policy seal failed', sealOk: false, ownerAnchored: !!sealRes.fullyAnchored, windowOk: null, policy: null, policy_hash: null };
    const snap = JSON.parse(reCanon);
    const policy_hash = policyHash(snap);
    // OPT-IN replay/downgrade resistance (council): the module enforces whatever SIGNED policy it is handed —
    // it cannot know "current" without external state. A caller can PIN the expected policy so a superseded
    // (older, still-validly-signed) policy is rejected. Without these, freshness is the caller's responsibility.
    if (opts.expectedPolicyHash != null && policy_hash !== opts.expectedPolicyHash) return { verified: false, why: 'policy_hash does not match the pinned expectedPolicyHash (stale/replayed/wrong policy)', sealOk, ownerAnchored: !!sealRes.fullyAnchored, windowOk: null, policy: null, policy_hash };
    if (opts.minVersion != null && (!isInt(opts.minVersion) || snap.version < opts.minVersion)) return { verified: false, why: 'policy version ' + snap.version + ' is below the pinned minVersion (superseded policy)', sealOk, ownerAnchored: !!sealRes.fullyAnchored, windowOk: null, policy: null, policy_hash };
    // effective window: OPT-IN via atTs. Absent (null/undefined) = not enforced (a verifier may lack a trusted
    // clock, by design). PRESENT-BUT-INVALID (a non-integer, e.g. a stray "now") FAILS CLOSED — never silently
    // skipped (council: the same fail-open footgun the gate's blank-floor fix closed).
    let windowOk = null;
    if (opts.atTs != null) {
      if (!isInt(opts.atTs)) return { verified: false, why: 'opts.atTs must be an integer timestamp when provided (refusing to silently skip the window)', sealOk, ownerAnchored: !!sealRes.fullyAnchored, windowOk: null, policy: null, policy_hash };
      windowOk = opts.atTs >= snap.effective_ts && (snap.expiry_ts == null || opts.atTs <= snap.expiry_ts);
      if (!windowOk) return { verified: false, why: 'policy is outside its effective window (effective_ts..expiry_ts)', sealOk, ownerAnchored: !!sealRes.fullyAnchored, windowOk, policy: null, policy_hash };
    }
    Object.freeze(snap.criteria); Object.freeze(snap);
    return { verified: true, why: null, sealOk, ownerAnchored: !!sealRes.fullyAnchored, suiteMatch: !!sealRes.suiteMatch, sealKinds: sealRes.kinds || [], windowOk, policy: snap, policy_hash };
  } catch { return FAIL('exception (fail-closed)'); }
}

/** evaluateUnderPolicy(record, verifyOpts, signedPolicy, opts) -> combined GOVERN-bound admission decision.
 *  Verifies the SIGNED policy (fail-closed) then runs the gate under its criteria. admit = policyOk ∧ gate.pass.
 *  opts: { policySealOpts (pin the owner — REQUIRED for an authenticated admission), atTs (integer; enforce
 *    window), requireWindow (block a bounded policy not verified in-window), minVersion / expectedPolicyHash
 *    (pin the current policy against replay of a superseded one) }. Owner authentication is FORCED ON — a
 *    config flag cannot disable it (mirrors the gate); use verifyPolicy directly for self-consistency-only
 *    inspection. The decision surfaces ownerAnchored + windowChecked/windowOk so the evidence never hides
 *    an unauthenticated or un-time-checked policy. TOTAL.
 *  The criteria enforced are EXACTLY the signed policy's — verifyOpts (2nd arg) is the RECORD's pins and
 *  cannot weaken them (the gate forces allowUnpinnedSeal:false on the record legs and only strengthens on
 *  requireDistinctSigners). The returned decision is a RUNTIME verdict surfacing which policy gated it — it
 *  is not itself a signed admission receipt (that would be a further leg). */
export function evaluateUnderPolicy(record, verifyOpts = {}, signedPolicy = null, opts = {}) {
  try {
    // FORCE owner authentication ON (council + the gate's own doctrine): an admission decision must NEVER
    // accept a self-consistent policy seal — a config flag cannot disable authenticity. allowUnpinnedPolicy
    // is deliberately NOT plumbed here; self-consistency-only inspection remains on verifyPolicy directly.
    const pv = verifyPolicy(signedPolicy, { sealOpts: opts.policySealOpts, atTs: opts.atTs, minVersion: opts.minVersion, expectedPolicyHash: opts.expectedPolicyHash, allowUnpinnedSeal: false });
    if (!pv.verified) {
      return { admit: false, reasons: ['governance policy did not verify: ' + (pv.why || 'unknown')], policyVerified: false, ownerAnchored: false, windowChecked: false, windowOk: null, policy: null, gate: null };
    }
    const surfaced = { policy_id: pv.policy.policy_id, version: pv.policy.version, issuer: pv.policy.issuer, effective_ts: pv.policy.effective_ts, expiry_ts: pv.policy.expiry_ts, policy_hash: pv.policy_hash, criteria: pv.policy.criteria };
    const windowChecked = pv.windowOk !== null;                    // false = the owner's temporal bound was NOT time-checked
    // requireWindow (council): a bounded policy must actually have been time-checked in-window. Off by default
    // (a verifier may lack a trusted clock), but windowChecked/windowOk are ALWAYS surfaced so "window not
    // checked" is never invisible in the admission evidence.
    if (opts.requireWindow && !(windowChecked && pv.windowOk === true)) {
      return { admit: false, reasons: ['requireWindow: the policy was not verified within its effective window (supply an integer atTs covering effective_ts..expiry_ts)'], policyVerified: true, ownerAnchored: pv.ownerAnchored, windowChecked, windowOk: pv.windowOk, policy: surfaced, gate: null };
    }
    // the SIGNED policy is the SOLE authority for the criteria it declares — strip criteria-shadowing keys from
    // the caller's RECORD verifyOpts so an unsigned flag can't add/alter enforcement (council: fail-closed, but
    // it made the surfaced criteria misstate what was enforced). requireDistinctSigners comes ONLY from the policy.
    const recordOpts = { ...verifyOpts, requireDistinctSigners: undefined };
    const gate = evaluateGate(record, recordOpts, pv.policy.criteria);
    const reasons = gate.pass ? [] : gate.reasons.slice();
    return { admit: !!gate.pass, reasons, policyVerified: true, ownerAnchored: pv.ownerAnchored, windowChecked, windowOk: pv.windowOk, policy: surfaced, gate };
  } catch { return { admit: false, reasons: ['exception (fail-closed)'], policyVerified: false, ownerAnchored: false, windowChecked: false, windowOk: null, policy: null, gate: null }; }
}

/** report(result) -> human/CI-readable string. TOTAL. */
export function policyReport(r) {
  if (!r || typeof r !== 'object') return 'AI GOVERNANCE ADMISSION: FAIL (block)\n  ✗ malformed result';
  const lines = ['AI GOVERNANCE ADMISSION: ' + (r.admit ? 'ADMIT' : 'BLOCK')];
  if (r.policy) {
    lines.push('  policy:       ' + r.policy.policy_id + ' v' + r.policy.version + (r.policy.issuer ? ' (issuer, self-declared: ' + r.policy.issuer + ')' : '') + '  hash:' + String(r.policy.policy_hash).slice(0, 16) + '…');
    lines.push('  authenticity: ownerAnchored=' + (r.ownerAnchored === true) + '  window=' + (r.windowChecked ? (r.windowOk === true ? 'in-window' : 'OUT-OF-WINDOW') : 'not checked'));
  } else lines.push('  policy:       — (unverified — admission blocked)');
  if (r.gate) lines.push(gateReport(r.gate).split('\n').map((l) => '  ' + l).join('\n'));
  if (!r.admit) for (const why of (r.reasons || [])) lines.push('  ✗ ' + why);
  lines.push('  NOTE: proves the HOLDER OF THE PINNED OWNER KEY set these criteria (issuer/description are');
  lines.push('        self-declared labels, not key-bound), over a self-attested record; not a certification.');
  return lines.join('\n');
}

/* ---------- self-test: node pqgovern-policy.mjs ---------- */
async function selfTest() {
  const gov = await import('./pqgovernance-record.mjs');
  const aibom = await import('./pqaibom.mjs');
  const pqeval = await import('./pqeval.mjs');
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  // three record legs + a DISTINCT governance owner
  const dA = mk(61), dC = mkEd(62), eA = mk(63), eC = mkEd(64), rA = mk(65), rC = mkEd(66), gA = mk(80), gC = mkEd(81);
  const aibomSigners = [dA, dC], evalSigners = [eA, eC], traceSigners = [rA, rC], ownerSigners = [gA, gC];
  const rk = ['lattice', 'classical'];
  const aibomSealOpts = { requireKinds: rk, trusted: { 'ML-DSA-87': dA.publicKey, 'Ed25519': dC.publicKey } };
  const evalSealOpts = { requireKinds: rk, trusted: { 'ML-DSA-87': eA.publicKey, 'Ed25519': eC.publicKey } };
  const traceSealOpts = { requireKinds: rk, trusted: { 'ML-DSA-87': rA.publicKey, 'Ed25519': rC.publicKey } };
  const ownerSealOpts = { requireKinds: rk, trusted: { 'ML-DSA-87': gA.publicKey, 'Ed25519': gC.publicKey } };
  const H = 'a'.repeat(64);
  const manifest = { components: [
    { type: 'model', name: 'acme-llm', version: '1.0', weights_sha256: H, provider: 'Acme', source_url: 'https://hf.co/acme/llm', license: 'Apache-2.0', task: 'text-generation', model_card_url: 'https://hf.co/acme/llm/card' },
    { type: 'dataset', name: 'acme-corpus', hash: H, provenance: 'curated 2025', license: 'CC-BY-4.0', data_classification: 'internal', consent_mechanism: 'licensed', split: 'train' },
  ] };
  const evalRec = {
    eval_suite: { name: 'HELM-lite', version: '1.0', suite_type: pqeval.SUITE_TYPE.registered_standard, registry_ref: 'https://crfm.stanford.edu/helm', expected_metrics: ['mmlu'], expected_safety: ['jailbreak'] },
    methodology: { harness: 'lm-eval-harness', harness_version: '0.4', config_hash: 'cfg', seed_selection_method: 'fixed_standard' },
    metrics: [{ name: 'mmlu', split: 'test', value: 0.71, ci: 0.01, primary: true, n: 14000, contamination: 'checked_clean' }],
    safety: [{ category: 'jailbreak', tested: true, result: 'pass', n_cases: 200 }],
  };
  const run = { steps: [{ kind: 'prompt', actor: 'user', content: 'capital of France?' }, { kind: 'model_output', actor: 'acme-llm', model_id: 'acme-llm', content: 'Paris.', tokens: { input: 5, output: 1 } }] };
  const registry = new Set([pqeval.suiteHash(pqeval.normalizeEval({ eval_suite: evalRec.eval_suite }).eval_suite)]);
  const rec = gov.buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners, evalSigners, traceSigners, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-system', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  const vopts = { aibomSealOpts, evalSealOpts, traceSealOpts, suiteRegistry: registry, loadedComponents: manifest.components };

  const strictSpec = { policy_id: 'acme-prod-admission', version: 3, effective_ts: 500, expiry_ts: 5000, issuer: 'Acme Compliance', description: 'prod model release gate', criteria: { minAibomGrade: 'B', minEvalPosture: 'C', requireDistinctSigners: true, requireDriftChecked: true } };
  const signedPolicy = signPolicy(buildPolicy(strictSpec), ownerSigners);

  // 1. HAPPY PATH: signed policy verifies + gate passes -> ADMIT, decision surfaces WHICH policy
  const d1 = evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 });
  ok(d1.admit === true && d1.policyVerified === true, 'signed policy + passing record -> ADMIT');
  ok(d1.policy.policy_id === 'acme-prod-admission' && d1.policy.version === 3 && d1.policy.issuer === 'Acme Compliance' && /^[0-9a-f]{128}$/.test(d1.policy.policy_hash), 'decision surfaces the signed policy identity + hash (GOVERN evidence)');

  // 2. POLICY NOT PINNED -> fail-closed BLOCK (cannot trust criteria you cannot authenticate)
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, {}).admit === false, 'unpinned policy -> fail-closed BLOCK');

  // 3. TAMPERED CRITERIA under signature -> seal breaks -> BLOCK (attacker weakens the floor)
  const tampered = JSON.parse(JSON.stringify(signedPolicy));
  tampered.policy.criteria.minAibomGrade = 'F';                       // try to weaken the admission floor
  const d3 = evaluateUnderPolicy(rec, vopts, tampered, { policySealOpts: ownerSealOpts, atTs: 1000 });
  ok(d3.admit === false && d3.policyVerified === false, 'tampered policy criteria -> seal fails -> BLOCK');

  // 4. POLICY SIGNED BY THE WRONG PARTY -> not owner-anchored -> BLOCK
  const forgedPolicy = signPolicy(buildPolicy(strictSpec), [mk(200), mkEd(201)]);
  ok(evaluateUnderPolicy(rec, vopts, forgedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === false, 'policy signed by an attacker key -> BLOCK (owner pin)');

  // 5. EXPIRED / NOT-YET-EFFECTIVE window -> BLOCK
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 6000 }).admit === false, 'atTs after expiry_ts -> BLOCK (window)');
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 100 }).admit === false, 'atTs before effective_ts -> BLOCK (window)');
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts }).admit === true, 'no atTs -> window not enforced (still admits under a valid policy)');

  // 6. POLICY VERIFIES but the record FAILS the criteria -> BLOCK with the gate reason
  const strictDrift = signPolicy(buildPolicy({ ...strictSpec, version: 4, criteria: { ...strictSpec.criteria, requireFullyPinnedDrift: true } }), ownerSigners);
  // (all manifest components are hashed here, so fully-pinned drift is satisfied -> still admit)
  ok(evaluateUnderPolicy(rec, vopts, strictDrift, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === true, 'fully-pinned-drift policy + all-hashed inventory -> ADMIT');
  const highBar = signPolicy(buildPolicy({ ...strictSpec, version: 5, criteria: { minAibomGrade: 'A', minEvalPosture: 'A', requireDistinctSigners: true } }), ownerSigners);
  const noDrift = { aibomSealOpts, evalSealOpts, traceSealOpts, suiteRegistry: registry };   // no loadedComponents
  const dHigh = evaluateUnderPolicy(rec, noDrift, highBar, { policySealOpts: ownerSealOpts, atTs: 1000 });
  ok(dHigh.policyVerified === true && dHigh.admit === true, 'record that MEETS an A/A bar admits (grade A Bound, posture A registered)');

  // 7. canonical fixpoint: an injected extra field in the signed policy body is rejected
  const extra = JSON.parse(JSON.stringify(signedPolicy));
  extra.policy.backdoor = true;
  ok(verifyPolicy(extra, { sealOpts: ownerSealOpts }).verified === false, 'non-canonical policy body (injected field) -> REJECTED');

  // 8. verifyPolicy fail-closed on garbage; policyReport total
  ok(verifyPolicy(null, { sealOpts: ownerSealOpts }).verified === false, 'verifyPolicy(null) -> fail-closed');
  ok(verifyPolicy(signedPolicy, {}).verified === false, 'verifyPolicy with no pins -> fail-closed');
  let threw = (f) => { try { f(); return false; } catch { return true; } };
  ok(!threw(() => policyReport(null)) && !threw(() => policyReport({})) && !threw(() => policyReport(d1)), 'policyReport is TOTAL');
  ok(/ADMIT/.test(policyReport(d1)) && /not a certification/.test(policyReport(d1)), 'policyReport renders verdict + honest-scope note');

  // 9. version/hash: different criteria -> different policy_hash (versionable evidence)
  const pHashA = policyHash(buildPolicy(strictSpec));
  const pHashB = policyHash(buildPolicy({ ...strictSpec, criteria: { ...strictSpec.criteria, minAibomGrade: 'A' } }));
  ok(pHashA !== pHashB, 'a change to any criterion changes policy_hash (tamper-evident, versionable)');
  ok(policyHash(buildPolicy(strictSpec)) === pHashA, 'policy_hash is deterministic');

  // 10. SNAPSHOT / TOCTOU defense (council): verifyPolicy returns a FROZEN snapshot decoupled from the caller
  //     object, so a live/mutable policy can't present strict criteria at verify + lax at the gate read.
  const pvSnap = verifyPolicy(signedPolicy, { sealOpts: ownerSealOpts });
  ok(pvSnap.verified && pvSnap.policy !== signedPolicy.policy && Object.isFrozen(pvSnap.policy) && Object.isFrozen(pvSnap.policy.criteria), 'verifyPolicy returns a frozen snapshot decoupled from the caller object (TOCTOU-safe)');
  ok(canon(pvSnap.policy) === canon(signedPolicy.policy), 'snapshot is canonically identical to the signed policy');

  // 11. REPLAY / DOWNGRADE resistance (council, opt-in): pin the current policy by version or hash.
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000, minVersion: 5 }).admit === false, 'a policy older than pinned minVersion -> BLOCK (replay/downgrade resistance)');
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000, minVersion: 3 }).admit === true, 'policy at/above minVersion -> admits');
  const curHash = policyHash(buildPolicy(strictSpec));
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000, expectedPolicyHash: curHash }).admit === true, 'policy matching pinned expectedPolicyHash -> admits');
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000, expectedPolicyHash: 'f'.repeat(128) }).admit === false, 'policy_hash != pinned expectedPolicyHash -> BLOCK (wrong/stale policy)');

  // 12. atTs PRESENT-BUT-INVALID fails CLOSED (council): a stray non-integer must not silently skip the window.
  ok(verifyPolicy(signedPolicy, { sealOpts: ownerSealOpts, atTs: 'now' }).verified === false, "atTs='now' (non-integer) -> REJECTED (no silent window skip)");
  ok(verifyPolicy(signedPolicy, { sealOpts: ownerSealOpts, atTs: 1000.5 }).verified === false, 'atTs non-integer float -> REJECTED');
  ok(verifyPolicy(signedPolicy, { sealOpts: ownerSealOpts }).verified === true, 'atTs ABSENT -> window not enforced (opt-out by design)');

  // 13. verifyPolicy rejects a hand-crafted signed policy with expiry < effective (defensive parsing).
  const badWindow = buildPolicy({ ...strictSpec, effective_ts: 100, expiry_ts: 200 });
  badWindow.effective_ts = 300;                                    // now effective(300) > expiry(200)
  const badSigned = signPolicy(badWindow, ownerSigners);
  ok(verifyPolicy(badSigned, { sealOpts: ownerSealOpts }).verified === false, 'signed policy with expiry_ts < effective_ts -> REJECTED (malformed window)');

  // 14. allowUnpinnedPolicy NO LONGER weakens the admission path (apex-team): owner auth is FORCED on, exactly
  //     as the gate forces allowUnpinnedSeal off. An attacker-self-signed policy cannot admit via a config flag.
  const atkPolicy = signPolicy(buildPolicy({ policy_id: 'acme-prod-admission', version: 99, issuer: 'Acme Compliance', criteria: {} }), [mk(200), mkEd(201)]);
  ok(evaluateUnderPolicy(rec, vopts, atkPolicy, { allowUnpinnedPolicy: true, atTs: 1000 }).admit === false, 'allowUnpinnedPolicy:true no longer admits an attacker-signed policy (owner auth forced on)');
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }).ownerAnchored === true, 'admission decision surfaces ownerAnchored=true for an owner-pinned policy');

  // 15. WINDOW is SURFACED + requireWindow (apex-team): a bounded policy without atTs still admits (opt-out) but
  //     windowChecked:false is surfaced (never hidden), and requireWindow BLOCKS it.
  const dNoWin = evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts });
  ok(dNoWin.admit === true && dNoWin.windowChecked === false, 'no atTs -> admits (opt-out) but windowChecked:false surfaced (not invisible in the evidence)');
  ok(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, requireWindow: true }).admit === false, 'requireWindow + no atTs -> BLOCK (a bounded policy must be time-checked)');
  const dWin = evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000, requireWindow: true });
  ok(dWin.admit === true && dWin.windowChecked === true && dWin.windowOk === true, 'requireWindow + in-window atTs -> ADMIT, windowOk surfaced');

  // 16. reCanon TRUE fixpoint (apex-team): a signed body carrying a type buildPolicy can never mint is rejected.
  const objIssuer = { v: 'pqgov-policy-1', policy_id: 'p', version: 1, effective_ts: 0, expiry_ts: null, issuer: { looksLike: 'Acme Compliance' }, description: null, criteria: { minAibomGrade: null, minEvalPosture: null, requireDistinctSigners: false, requireDriftChecked: false, requireFullyPinnedDrift: false } };
  ok(verifyPolicy(signPolicy(objIssuer, ownerSigners), { sealOpts: ownerSealOpts }).verified === false, 'signed body with an OBJECT issuer -> REJECTED (non-canonical, not in buildPolicy image)');
  ok(verifyPolicy(signPolicy({ ...objIssuer, issuer: null, policy_id: '' }, ownerSigners), { sealOpts: ownerSealOpts }).verified === false, 'signed body with a blank policy_id -> REJECTED (malformed)');

  // 17. SIGNED policy is the SOLE criteria authority (apex-team): a caller verifyOpts.requireDistinctSigners
  //     cannot ADD enforcement the signed policy deliberately omitted.
  const shareVopts2 = { aibomSealOpts: evalSealOpts, evalSealOpts, traceSealOpts: evalSealOpts, suiteRegistry: registry };
  const shareRec2 = gov.buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners: evalSigners, evalSigners, traceSigners: evalSigners, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-system', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  const laxPolicy = signPolicy(buildPolicy({ policy_id: 'lax', version: 1, effective_ts: 0, criteria: { minAibomGrade: 'B', requireDistinctSigners: false } }), ownerSigners);
  ok(evaluateUnderPolicy(shareRec2, shareVopts2, laxPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === true, 'shared-signer record + lax policy (requireDistinctSigners:false) -> ADMIT');
  ok(evaluateUnderPolicy(shareRec2, { ...shareVopts2, requireDistinctSigners: true }, laxPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === true, 'caller verifyOpts.requireDistinctSigners cannot add enforcement the SIGNED policy omitted (signed policy is sole authority)');

  // 18. policyReport surfaces the self-declared issuer + authenticity honestly (claim-hygiene).
  const rep1 = policyReport(evaluateUnderPolicy(rec, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }));
  ok(/issuer, self-declared/.test(rep1) && /ownerAnchored=true/.test(rep1) && /PINNED OWNER KEY/.test(rep1), 'policyReport marks issuer self-declared + surfaces ownerAnchored + an honest WHO note');

  console.log('pqgovern-policy self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgovern-policy\.mjs$/.test(process.argv[1] || '')) selfTest();
