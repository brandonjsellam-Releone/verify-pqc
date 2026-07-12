/*!
 * pqgovernance-gate — a CI/CD ADMISSION GATE over an AI Governance Record (productizes pqgovernance-record).
 *
 * Turns "we CAN verify a governance record" into "this pipeline REFUSES to ship a model unless a valid,
 * cross-bound, drift-clean governance record clears a caller-defined POLICY." Drop it into CI the way a
 * test gate or a CBOM gate sits in a pipeline: exit 0 = admit, exit non-zero = block, with a report.
 *
 * HONEST SCOPE (claim-hygiene LAW): the gate ENFORCES a policy the CALLER sets over a SELF-ATTESTED
 * record; it does NOT certify the model, and it inherits every honest limit of the underlying legs
 * (pqaibom = declared inventory, pqeval = self-reported eval, pqtrace = runner-attested log — see
 * pqgovernance-record.mjs). It authenticates that the DECLARANT/EVALUATOR/RUNNER pinned keys signed a
 * mutually-consistent record ABOUT ONE model, and that the record clears the policy thresholds. It is
 * NOT an endorsement, NOT "certified/approved", and a passing gate does not make any leg's claim true.
 *
 * POLICY (all optional; absent = not enforced):
 *   - minAibomGrade / minEvalPosture : letter floors ('A'>'B'>'C'>'D'>'F'); the record's grade/posture
 *     letter must be >= the floor. (Grades exist only if the record VERIFIES — an unverifiable record
 *     fails the gate outright, before any threshold.)
 *   - requireDistinctSigners : the three legs must carry pairwise-DISJOINT signer key sets — no key signs
 *     two legs (a shared signing key across legs is blocked). NOTE: this establishes distinct KEY MATERIAL
 *     per leg; distinct real-world PARTIES are established only by the caller's per-leg key pins (sealOpts).
 *   - requireDriftChecked : the caller MUST have supplied loadedComponents AND the BOM-reality-drift check
 *     MUST be clean — so the runtime matched the inventory for every HASH-PINNED component. Hashless
 *     components are matched by declared metadata only (surfaced as the drift note); use the flag below.
 *   - requireFullyPinnedDrift : additionally require the drift check to leave ZERO metadata-only (hashless)
 *     components — i.e. every runtime-checked artifact was byte-verified against a declared hash.
 *
 * The gate is TOTAL/fail-closed: any exception, malformed input, or unverifiable record => pass:false.
 *  Self-test: node pqgovernance-gate.mjs
 */
import { hexToBytes } from '@noble/hashes/utils.js';
import { verifyGovernanceRecord } from './pqgovernance-record.mjs';

const GRADE_ORDER = ['F', 'D', 'C', 'B', 'A'];              // index = betterness (A best)
const letterOf = (label) => { const m = /^\s*([A-F])/.exec(String(label ?? '')); return m ? m[1] : 'F'; };
// FAIL-CLOSED: an UNRECOGNISED floor letter (a policy typo) must BLOCK, not silently disable the check —
// so `meets` is false unless `min` is a real grade letter AND `have` >= it.
const meets = (have, min) => { const mi = GRADE_ORDER.indexOf(String(min).toUpperCase()); return mi >= 0 && GRADE_ORDER.indexOf(letterOf(have)) >= mi; };

/** evaluateGate(record, verifyOpts, policy) -> { pass, reasons[], verify, policy, summary }. TOTAL. */
export function evaluateGate(record, verifyOpts = {}, policy = {}) {
  try {
    // requireDistinctSigners is enforced INSIDE the record verifier (so v.verified reflects it).
    // allowUnpinnedSeal is FORCED OFF (council): an admission gate must never accept a self-consistent
    // seal without authenticating the signers — a config flag must not be able to disable authenticity.
    const vOpts = { ...verifyOpts, allowUnpinnedSeal: false, requireDistinctSigners: !!policy.requireDistinctSigners || !!verifyOpts.requireDistinctSigners };
    const v = verifyGovernanceRecord(record, vOpts);
    const reasons = [];
    if (!v.verified) {
      reasons.push('record does not verify: ' + (v.why || 'unknown'));
    } else {
      // thresholds are only meaningful once the record verifies (grades are null otherwise). A floor that is
      // PRESENT but not a recognized grade letter (blank/0/typo) must BLOCK — meets() returns false for an
      // unrecognized floor, so route any NON-NULL floor through it (council: blank floor must fail CLOSED,
      // consistent with the typo'd-floor behavior, not silently skip).
      if (policy.minAibomGrade != null && !meets(v.aibomGrade, policy.minAibomGrade)) reasons.push('AIBOM grade ' + letterOf(v.aibomGrade) + ' is below the required floor ' + String(policy.minAibomGrade).toUpperCase());
      if (policy.minEvalPosture != null && !meets(v.evalPosture, policy.minEvalPosture)) reasons.push('eval posture ' + letterOf(v.evalPosture) + ' is below the required floor ' + String(policy.minEvalPosture).toUpperCase());
      if (policy.requireDriftChecked && !(v.driftChecked && v.driftOk === true)) reasons.push('BOM-reality drift is required to be checked+clean, but loadedComponents were not supplied or drift was detected');
      // requireFullyPinnedDrift: every runtime-checked component must be HASH-pinned — no metadata-only match
      // (council: driftOk:true alone does NOT mean every byte verified; hashless components match on metadata).
      if (policy.requireFullyPinnedDrift && !(v.driftChecked && v.driftOk === true && Array.isArray(v.driftUnpinned) && v.driftUnpinned.length === 0)) reasons.push('requireFullyPinnedDrift: ' + ((v.driftUnpinned && v.driftUnpinned.length) ? v.driftUnpinned.length + ' component(s) matched by declared metadata only (no hash): ' + v.driftUnpinned.join(', ') : 'drift not checked (loadedComponents not supplied)'));
    }
    const pass = !!v.verified && reasons.length === 0;
    // subject is surfaced ONLY when the record verified (council: never label an unauthenticated field
    // "authenticated" — aibomGrade/evalPosture were already gated; subject + driftUnpinned now match).
    const summary = { pass, subject: v.verified ? (v.subject ?? null) : null, aibomGrade: v.verified ? v.aibomGrade : null, evalPosture: v.verified ? v.evalPosture : null,
      modelHashWellFormed: v.modelHashWellFormed, modelInBom: v.modelInBom, subjectConsistent: v.subjectConsistent, distinctSigners: v.distinctSigners, driftChecked: v.driftChecked, driftOk: v.driftOk, driftUnpinned: v.verified ? v.driftUnpinned : null };
    return { pass, reasons, verify: v, policy, summary };
  } catch { return { pass: false, reasons: ['exception (fail-closed)'], verify: null, policy, summary: { pass: false } }; }
}

/** gateReport(result) -> human/CI-readable multi-line string. TOTAL: never throws on malformed input. */
export function gateReport(r) {
  if (!r || typeof r !== 'object') return 'AI GOVERNANCE GATE: FAIL (block)\n  ✗ malformed gate result';
  const s = (r && r.summary) || {};
  const lines = ['AI GOVERNANCE GATE: ' + (r.pass ? 'PASS (admit)' : 'FAIL (block)')];
  if (s.subject != null) lines.push('  subject:      ' + s.subject + '  (authenticated from the signed AIBOM)');
  lines.push('  AIBOM grade:  ' + (s.aibomGrade ?? '—') + '   eval posture: ' + (s.evalPosture ?? '—'));
  lines.push('  checks:       modelHashWellFormed=' + s.modelHashWellFormed + ' modelInBom=' + s.modelInBom + ' subjectConsistent=' + s.subjectConsistent + ' distinctSigners=' + s.distinctSigners + ' driftChecked=' + s.driftChecked + ' driftOk=' + s.driftOk);
  if (Array.isArray(s.driftUnpinned) && s.driftUnpinned.length) lines.push('  drift note:   ' + s.driftUnpinned.length + ' component(s) matched by declared METADATA only (no hash): ' + s.driftUnpinned.join(', '));
  if (!r.pass) for (const why of (r.reasons || [])) lines.push('  ✗ ' + why);
  lines.push('  NOTE: enforces a caller policy over a SELF-ATTESTED record; not a certification or endorsement.');
  return lines.join('\n');
}

/* ---------- CLI: node pqgovernance-gate.mjs <record.json> <config.json> ----------
 * config.json = { pins:{aibom:{ALG:hex,...},eval:{...},trace:{...}}, requireKinds:[...],
 *   suiteRegistry:[hex,...], loadedComponents?:[...], policy:{minAibomGrade,minEvalPosture,
 *   requireDistinctSigners,requireDriftChecked} }  — pubkeys are hex, reconstructed to bytes here. */
async function cli(recPath, cfgPath) {
  const { readFileSync } = await import('fs');
  const record = JSON.parse(readFileSync(recPath, 'utf8'));
  const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
  const trustedOf = (m) => Object.fromEntries(Object.entries(m || {}).map(([alg, hex]) => [alg, hexToBytes(hex)]));
  const sealOptsOf = (m) => ({ requireKinds: cfg.requireKinds, trusted: trustedOf(m) });
  const verifyOpts = {
    aibomSealOpts: sealOptsOf(cfg.pins && cfg.pins.aibom), evalSealOpts: sealOptsOf(cfg.pins && cfg.pins.eval),
    traceSealOpts: sealOptsOf(cfg.pins && cfg.pins.trace), suiteRegistry: cfg.suiteRegistry,
    loadedComponents: cfg.loadedComponents,
  };
  const res = evaluateGate(record, verifyOpts, cfg.policy || {});
  console.log(gateReport(res));
  if (typeof process !== 'undefined' && process.exit) process.exit(res.pass ? 0 : 1);
}

/* ---------- self-test: node pqgovernance-gate.mjs ---------- */
async function selfTest() {
  const gov = await import('./pqgovernance-record.mjs');
  const aibom = await import('./pqaibom.mjs');
  const pqeval = await import('./pqeval.mjs');
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  const dA = mk(61), dC = mkEd(62), eA = mk(63), eC = mkEd(64), rA = mk(65), rC = mkEd(66);
  const aibomSigners = [dA, dC], evalSigners = [eA, eC], traceSigners = [rA, rC];
  const rk = ['lattice', 'classical'];
  const aibomSealOpts = { requireKinds: rk, trusted: { 'ML-DSA-87': dA.publicKey, 'Ed25519': dC.publicKey } };
  const evalSealOpts = { requireKinds: rk, trusted: { 'ML-DSA-87': eA.publicKey, 'Ed25519': eC.publicKey } };
  const traceSealOpts = { requireKinds: rk, trusted: { 'ML-DSA-87': rA.publicKey, 'Ed25519': rC.publicKey } };
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
  const build = (over = {}) => gov.buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners, evalSigners, traceSigners, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-system', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry, ...over });
  const vopts = { aibomSealOpts, evalSealOpts, traceSealOpts, suiteRegistry: registry, loadedComponents: manifest.components };
  const rec = build();

  // 1. clean record + policy it clears -> ADMIT
  const g1 = evaluateGate(rec, vopts, { minAibomGrade: 'B', minEvalPosture: 'C', requireDistinctSigners: true, requireDriftChecked: true });
  ok(g1.pass === true && g1.reasons.length === 0, 'clean record clearing every policy floor -> PASS (admit)');
  ok(/A \(Bound\)/.test(g1.summary.aibomGrade) && g1.summary.subject === 'acme-system', 'summary surfaces the signed subject + AIBOM grade');

  // 2. threshold too high -> BLOCK (grade floor A on eval, but a non-registered suite would be < A; here demand
  //    an impossible-for-this-record floor by requiring driftCheck the caller did NOT run)
  const g2 = evaluateGate(rec, { aibomSealOpts, evalSealOpts, traceSealOpts, suiteRegistry: registry }, { requireDriftChecked: true });
  ok(g2.pass === false && /drift/.test(g2.reasons.join()), 'requireDriftChecked but no loadedComponents -> BLOCK');

  // 3. unverifiable record (attacker-signed eval) -> BLOCK before any threshold
  const forged = build();
  forged.eval = pqeval.signEval(rec.eval.rec, [mk(200), mkEd(201)]);
  const g3 = evaluateGate(forged, vopts, { minAibomGrade: 'F' });
  ok(g3.pass === false && /does not verify/.test(g3.reasons.join()), 'attacker-signed leg -> record fails verify -> BLOCK');

  // 4. grade floor above what the record earns -> BLOCK. Downgrade the AIBOM to a lower grade by dropping
  //    integrity (unhashed model) so it can't reach 'A', then demand minAibomGrade 'A'.
  const lowManifest = { components: [ { type: 'model', name: 'acme-llm', version: '1.0', provider: 'Acme', source_url: 'https://hf.co/acme/llm', license: 'Apache-2.0', task: 'text-generation', model_card_url: 'https://hf.co/acme/llm/card' } ] };
  // NOTE: no weights_sha256 -> model_hash null -> record won't verify at all (modelHashWellFormed false);
  //   this proves the gate blocks it, which is the correct behavior (no model anchor = no admission).
  const lowRec = gov.buildGovernanceRecord({ manifest: lowManifest, evalRec, run }, { aibomSigners, evalSigners, traceSigners, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-system', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  const g4 = evaluateGate(lowRec, vopts, { minAibomGrade: 'A' });
  ok(g4.pass === false, 'record with no model weights anchor -> BLOCK (modelPinned false)');

  // 5. shared-signer record + requireDistinctSigners -> BLOCK; without the requirement -> ADMIT
  const sharedVopts = { aibomSealOpts: evalSealOpts, evalSealOpts, traceSealOpts: evalSealOpts, suiteRegistry: registry, loadedComponents: manifest.components };
  const shared = build({ aibomSigners: evalSigners, traceSigners: evalSigners });
  ok(evaluateGate(shared, sharedVopts, { requireDistinctSigners: true }).pass === false, 'shared signer + requireDistinctSigners -> BLOCK');
  ok(evaluateGate(shared, sharedVopts, {}).pass === true, 'shared signer + no distinct-signer requirement -> ADMIT (opt-in)');

  // 6. fail-closed on garbage + no pins
  ok(evaluateGate(null, vopts, {}).pass === false, 'null record -> fail-closed BLOCK');
  ok(evaluateGate(rec, {}, {}).pass === false, 'no pins -> fail-closed BLOCK');

  // 7. report renders and marks the honest scope
  const rep = gateReport(g1);
  ok(/GATE: PASS/.test(rep) && /SELF-ATTESTED/.test(rep) && /not a certification/.test(rep), 'gateReport renders verdict + honest-scope note');

  // 8. FAIL-CLOSED on a typo'd policy floor: an unrecognised grade letter must BLOCK, not silently pass
  const g8 = evaluateGate(rec, vopts, { minAibomGrade: 'Excellent' });
  ok(g8.pass === false && /below the required floor/.test(g8.reasons.join()), 'unrecognised policy floor (typo) -> BLOCK (fail-closed, not silently disabled)');
  ok(evaluateGate(rec, vopts, { minAibomGrade: 'F', minEvalPosture: 'F' }).pass === true, 'floor F is the minimum and always admits a verifying record');

  // 9. COUNCIL FIX: the gate FORCES allowUnpinnedSeal=false — a caller cannot disable authenticity via a
  //    config flag. A record signed entirely by ATTACKER keys, verified with allowUnpinnedSeal:true and NO
  //    pins, is BLOCKED (pre-fix it would ADMIT on self-consistency).
  const atkAll = build({ aibomSigners: [mk(210), mkEd(211)], evalSigners: [mk(212), mkEd(213)], traceSigners: [mk(214), mkEd(215)] });
  ok(evaluateGate(atkAll, { allowUnpinnedSeal: true }, {}).pass === false, 'gate forces allowUnpinnedSeal=false: an unpinned attacker-signed record is BLOCKED even if the caller passes allowUnpinnedSeal:true');
  ok(evaluateGate(rec, { ...vopts, allowUnpinnedSeal: true }, { minAibomGrade: 'B' }).pass === true, 'the forced override does not break a properly-pinned record');

  // 10. gateReport is TOTAL (apex-team finding): never throws on malformed input.
  let threw = (f) => { try { f(); return false; } catch { return true; } };
  ok(!threw(() => gateReport(null)) && /FAIL \(block\)/.test(gateReport(null)), 'gateReport(null) -> no throw, renders a block verdict');
  ok(!threw(() => gateReport({})) && !threw(() => gateReport({ pass: false })), 'gateReport({}) / partial result -> no throw (total)');

  // 11. BLANK/FALSY floor must FAIL CLOSED (apex-team): a present-but-blank floor from a templated config
  //     must BLOCK, consistent with the typo'd-floor behavior — not silently skip the check.
  ok(evaluateGate(rec, vopts, { minAibomGrade: '' }).pass === false, "blank minAibomGrade '' -> BLOCK (fail-closed, not silently disabled)");
  ok(evaluateGate(rec, vopts, { minEvalPosture: '' }).pass === false, "blank minEvalPosture '' -> BLOCK");
  ok(evaluateGate(rec, vopts, { minAibomGrade: 0 }).pass === false, 'numeric-falsy floor 0 -> BLOCK');
  ok(evaluateGate(rec, vopts, {}).pass === true && evaluateGate(rec, vopts, { minAibomGrade: null }).pass === true, 'ABSENT floor (missing or null) -> not enforced (admits)');

  // 12. SUBJECT is not labelled "authenticated" on a BLOCK path (apex-team): tamper the signed AIBOM subject
  //     (breaks the seal) -> gate blocks AND the report does not stamp the attacker string "authenticated".
  const atkSub = build();
  atkSub.aibom.bom.subject = 'TRUSTED FedRAMP-Authorized Government System'; atkSub.subject = atkSub.aibom.bom.subject;
  const gSub = evaluateGate(atkSub, vopts, { minAibomGrade: 'B' });
  ok(gSub.pass === false && gSub.summary.subject === null, 'tampered-subject record -> BLOCK, summary.subject null (not surfaced from an unverified record)');
  ok(!/authenticated from the signed AIBOM/.test(gateReport(gSub)), 'gateReport does NOT stamp an unverified subject "authenticated" on the block path');

  // 13. driftUnpinned SURFACED + requireFullyPinnedDrift (apex-team): a HASHLESS component matches by metadata
  //     only, so driftOk:true but driftUnpinned non-empty. It is surfaced, and requireFullyPinnedDrift BLOCKS.
  const hlManifest = { components: [
    { type: 'model', name: 'acme-llm', version: '1.0', weights_sha256: H, provider: 'Acme', source_url: 'https://hf.co/acme/llm', license: 'Apache-2.0', task: 'text-generation', model_card_url: 'https://hf.co/acme/llm/card' },
    { type: 'dataset', name: 'acme-corpus', hash: H, provenance: 'curated 2025', license: 'CC-BY-4.0', data_classification: 'internal', consent_mechanism: 'licensed', split: 'train' },
    { type: 'library', name: 'libssl', version: '3.0', license: 'Apache-2.0' },      // HASHLESS -> metadata-only match
  ] };
  const hlRec = gov.buildGovernanceRecord({ manifest: hlManifest, evalRec, run }, { aibomSigners, evalSigners, traceSigners, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-system', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  const hlVopts = { aibomSealOpts, evalSealOpts, traceSealOpts, suiteRegistry: registry, loadedComponents: hlManifest.components };
  const gHl = evaluateGate(hlRec, hlVopts, { requireDriftChecked: true });
  ok(gHl.pass === true && Array.isArray(gHl.summary.driftUnpinned) && gHl.summary.driftUnpinned.length === 1, 'hashless component: drift clean but driftUnpinned surfaced (1 metadata-only component)');
  ok(/matched by declared METADATA only/.test(gateReport(gHl)), 'gateReport surfaces the drift note for the hashless component');
  ok(evaluateGate(hlRec, hlVopts, { requireFullyPinnedDrift: true }).pass === false, 'requireFullyPinnedDrift -> a metadata-only (hashless) component BLOCKS admission');

  console.log('pqgovernance-gate self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}

if (typeof process !== 'undefined' && process.argv && /pqgovernance-gate\.mjs$/.test(process.argv[1] || '')) {
  if (process.argv.length >= 4) cli(process.argv[2], process.argv[3]);
  else selfTest();
}
