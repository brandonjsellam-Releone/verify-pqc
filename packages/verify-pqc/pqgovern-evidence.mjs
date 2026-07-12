/*!
 * pqgovern-evidence — the AI GOVERNANCE EVIDENCE PACK: one self-contained, independently-verifiable
 * artifact over the whole NIST-AI-RMF quartet (reference, DRAFT).
 *
 * Hand an auditor/customer ONE file + the trusted public keys, and they re-derive the ENTIRE governed
 * admission from scratch: MAP (AIBOM) ∧ MEASURE (eval) ∧ MANAGE (trace) cross-bound to one model
 * (pqgovernance-record), gated by the owner's SIGNED policy (pqgovern-policy) — no live services, no
 * trust in the packager's word. The pack BINDS its contents by hash (tamper-evident even unsigned) and
 * can carry a PACKAGER seal so the bundle's provenance (who assembled it, when) is itself attestable.
 *
 * HONEST SCOPE (claim-hygiene LAW): the pack proves the admission was computed CORRECTLY from the
 * embedded, signed artifacts under the VERIFIER's own pins — it verifies the CRYPTOGRAPHIC integrity
 * and the policy LOGIC of the chain. It does NOT verify the FACTUAL claims inside each leg (that the
 * eval was actually run, that the declared inventory is complete) — those are trusted on their
 * signatures, NOT independently checked — and it does NOT certify the model, its safety, or compliance.
 * It inherits every leg's honest limit (declared inventory / self-reported eval / runner-attested log /
 * owner-set criteria). The verifier supplies the trusted anchors; the pack never carries its own
 * "trust" nor its own verdict — the admission is ALWAYS re-derived. verifyEvidencePack is TOTAL/
 * fail-closed, and returns `admit` as the SOLE admission boolean (never conflate integrity with admit).
 *  Self-test: node pqgovern-evidence.mjs
 */
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { seal, openSeal } from './pqseal.mjs';
import * as policy from './pqgovern-policy.mjs';

const V = 'pqgov-evidence-1';
const DOM = V + ':';   // domain tag for the packager seal — prevents cross-context signature replay of a bare hash
const PACK_KEYS = new Set(['v', 'created_ts', 'packager', 'record', 'policy', 'pack_hash', 'envelope']);
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const hashHex = (obj) => bytesToHex(sha512(utf8ToBytes(canon(obj))));
const isInt = (n) => Number.isInteger(n);

/** build the pack. In: {record (a governance record), signedPolicy}. The core (record+policy) is bound by
 *  pack_hash. Optional packSigners seal that core so the PACKAGER's provenance is attestable. */
export function buildEvidencePack({ record, signedPolicy }, opts = {}) {
  if (!record || !signedPolicy) throw new Error('buildEvidencePack requires {record, signedPolicy}');
  const core = { v: V, created_ts: isInt(opts.created_ts) ? opts.created_ts : 0, packager: typeof opts.packager === 'string' ? opts.packager : null, record, policy: signedPolicy };
  const pack_hash = hashHex(core);
  const pack = { ...core, pack_hash };
  if (opts.packSigners) pack.envelope = seal(utf8ToBytes(DOM + pack_hash), opts.packSigners);   // domain-separated packager provenance over the BOUND hash
  return pack;
}

/** verifyEvidencePack(pack, opts) — TOTAL/fail-closed. Re-derives the whole admission from the embedded
 *  artifacts under the VERIFIER's pins. opts carries the record leg pins + policy owner pins + registry +
 *  window/version + optional packSealOpts (to authenticate the packager) + loadedComponents (drift). */
export function verifyEvidencePack(pack, opts = {}) {
  // NOTE (council): `admit` is the SOLE admission verdict — downstream MUST gate on it, NEVER on integrity.
  const FAIL = (why) => ({ admit: false, integrityOk: false, artifactsVerified: false, packagerAnchored: null, why, decision: null });
  try {
    if (!pack || typeof pack !== 'object' || pack.v !== V || !pack.record || !pack.policy || typeof pack.pack_hash !== 'string') return FAIL('malformed evidence pack');
    // STRICT top-level schema — no unbound extra field may ride along in the bundle (kills inert-but-present injection).
    for (const k of Object.keys(pack)) if (!PACK_KEYS.has(k)) return FAIL('unexpected top-level field in pack: ' + k);
    // CAPTURE ONCE (council TOCTOU): the hash check and the re-derivation MUST see the SAME artifacts, so a
    // getter/Proxy that returns a benign record to hashing and a different one to evaluation cannot pass.
    const record = pack.record, signedPolicy = pack.policy;
    const core = { v: V, created_ts: pack.created_ts, packager: pack.packager ?? null, record, policy: signedPolicy };
    if (hashHex(core) !== pack.pack_hash) return FAIL('pack_hash does not bind the pack contents (tampered)');
    // optional PACKAGER provenance (bundle-level only — record+policy carry their OWN signatures regardless).
    let packagerAnchored = null;
    if (pack.envelope) {
      const so = opts.packSealOpts || {};
      const hasPin = so.trusted && typeof so.trusted === 'object' && Object.keys(so.trusted).length > 0;
      if (!hasPin && !opts.allowUnpinnedPackager) return { ...FAIL('packSealOpts (packager pins) required to authenticate the bundle, or pass allowUnpinnedPackager:true'), integrityOk: true };
      const sr = openSeal(utf8ToBytes(DOM + pack.pack_hash), pack.envelope, so);   // domain-separated (anti cross-context replay)
      if (!sr.verified) return { ...FAIL('packager seal failed'), integrityOk: true };
      packagerAnchored = !!sr.fullyAnchored;
    } else if (opts.requirePackagerSeal) {   // opt-in: a consumer that demands bundle provenance blocks an unsigned/stripped pack
      return { ...FAIL('requirePackagerSeal: the bundle is not packager-sealed'), integrityOk: true };
    }
    // RE-DERIVE the whole governed admission independently — the pack carries NO trust AND NO verdict of its own.
    const verifyOpts = { aibomSealOpts: opts.aibomSealOpts, evalSealOpts: opts.evalSealOpts, traceSealOpts: opts.traceSealOpts, suiteRegistry: opts.suiteRegistry, loadedComponents: opts.loadedComponents, requireDistinctSigners: opts.requireDistinctSigners };
    const decision = policy.evaluateUnderPolicy(record, verifyOpts, signedPolicy, { policySealOpts: opts.policySealOpts, atTs: opts.atTs, minVersion: opts.minVersion, expectedPolicyHash: opts.expectedPolicyHash, requireWindow: opts.requireWindow });
    // EXPLICIT, non-conflatable fields: integrityOk (bundle well-formed + hash-bound + packager-authentic if
    // sealed), artifactsVerified (embedded record+policy cryptographically verify), admit (the verdict).
    const artifactsVerified = !!decision.policyVerified;
    return { admit: !!decision.admit, integrityOk: true, artifactsVerified, packagerAnchored,
      why: artifactsVerified ? null : ('embedded artifacts did not verify: ' + (decision.reasons && decision.reasons[0])), decision };
  } catch { return FAIL('exception (fail-closed)'); }
}

/** evidenceReport(pack, verdict) -> human/CI-readable audit summary. TOTAL. */
export function evidenceReport(pack, verdict) {
  if (!verdict || typeof verdict !== 'object') return 'AI GOVERNANCE EVIDENCE PACK: FAIL (malformed verdict)';
  const lines = ['AI GOVERNANCE EVIDENCE PACK — ADMISSION: ' + (verdict.admit ? 'ADMIT' : 'BLOCK')];
  if (pack && typeof pack === 'object') lines.push('  pack:         ' + String(pack.pack_hash).slice(0, 16) + '…' + (pack.packager ? '  packager (self-declared): ' + pack.packager : '') + (pack.envelope ? '  [packager-sealed]' : '  [unsigned bundle — hash-bound only]'));
  lines.push('  integrity:    integrityOk=' + verdict.integrityOk + '  artifactsVerified=' + verdict.artifactsVerified + '  packagerAnchored=' + verdict.packagerAnchored);
  if (verdict.decision) lines.push(policy.policyReport(verdict.decision).split('\n').map((l) => '  ' + l).join('\n'));
  if (!verdict.artifactsVerified && verdict.why) lines.push('  ✗ ' + verdict.why);
  lines.push('  NOTE: gate on `admit` (NOT integrity). Re-derives the admission from the embedded SIGNED');
  lines.push('        artifacts under the VERIFIER\'s own pins — verifies the crypto + policy LOGIC of the');
  lines.push('        chain; FACTUAL claims inside each leg are trusted on their signatures, NOT independently');
  lines.push('        checked. Inherits every leg\'s honest limit; not a certification of the model.');
  return lines.join('\n');
}

/* ---------- self-test: node pqgovern-evidence.mjs ---------- */
async function selfTest() {
  const gov = await import('./pqgovernance-record.mjs');
  const aibom = await import('./pqaibom.mjs');
  const pqeval = await import('./pqeval.mjs');
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  const declarant = [mk(11), mkEd(12)], evaluator = [mk(13), mkEd(14)], runner = [mk(15), mkEd(16)], owner = [mk(17), mkEd(18)], packager = [mk(19), mkEd(20)];
  const rk = ['lattice', 'classical'];
  const pins = (s) => ({ requireKinds: rk, trusted: { 'ML-DSA-87': s[0].publicKey, 'Ed25519': s[1].publicKey } });
  const aibomSealOpts = pins(declarant), evalSealOpts = pins(evaluator), traceSealOpts = pins(runner), ownerSealOpts = pins(owner), packSealOpts = pins(packager);
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
  const record = gov.buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-llm-prod', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  const signedPolicy = policy.signPolicy(policy.buildPolicy({ policy_id: 'acme-ai-release', version: 3, effective_ts: 500, expiry_ts: 5000, issuer: 'Acme Compliance', criteria: { minAibomGrade: 'B', minEvalPosture: 'C', requireDistinctSigners: true, requireDriftChecked: true } }), owner);
  // the verifier's independent anchor set (what an auditor is handed out-of-band)
  const vopts = { aibomSealOpts, evalSealOpts, traceSealOpts, policySealOpts: ownerSealOpts, suiteRegistry: registry, loadedComponents: manifest.components, atTs: 1000, minVersion: 3, requireWindow: true, requireDistinctSigners: true };

  // 1. build + INDEPENDENTLY verify a packager-sealed pack -> ADMIT
  const pack = buildEvidencePack({ record, signedPolicy }, { packager: 'Acme Release Eng', created_ts: 1200, packSigners: packager });
  const v = verifyEvidencePack(pack, { ...vopts, packSealOpts });
  ok(v.integrityOk && v.artifactsVerified && v.admit && v.packagerAnchored === true, 'a packager-sealed pack re-verifies end-to-end + ADMITs under independent pins');
  ok(/A \(Bound\)/.test(v.decision.gate.summary.aibomGrade) && v.decision.policy.policy_id === 'acme-ai-release', 'the re-derived decision carries the AIBOM grade + which policy gated it');
  console.log('\n' + evidenceReport(pack, v) + '\n');

  // 2. UNSIGNED bundle still hash-binds + re-verifies (packager provenance is optional)
  const bare = buildEvidencePack({ record, signedPolicy }, { packager: 'anon', created_ts: 1200 });
  const vb = verifyEvidencePack(bare, vopts);
  ok(vb.integrityOk && vb.artifactsVerified && vb.admit && vb.packagerAnchored === null, 'an unsigned bundle still hash-binds + re-verifies (packager provenance optional)');

  // 3. TAMPER the embedded record -> pack_hash mismatch -> BLOCK (integrity broken)
  const t1 = JSON.parse(JSON.stringify(pack)); t1.record.subject = 'TRUSTED FedRAMP System';
  ok(verifyEvidencePack(t1, { ...vopts, packSealOpts }).integrityOk === false && verifyEvidencePack(t1, { ...vopts, packSealOpts }).admit === false, 'tampering the embedded record breaks pack integrity -> REJECTED (integrityOk false, admit false)');
  // 4. TAMPER the embedded policy criteria -> pack_hash mismatch
  const t2 = JSON.parse(JSON.stringify(pack)); t2.policy.policy.criteria.minAibomGrade = 'F';
  ok(verifyEvidencePack(t2, { ...vopts, packSealOpts }).integrityOk === false, 'tampering the embedded policy breaks pack integrity -> REJECTED');

  // 5. WRONG packager pin -> packager seal fails (integrity of contents holds, but bundle not authentic)
  const wrongPack = { requireKinds: rk, trusted: { 'ML-DSA-87': mk(99).publicKey, 'Ed25519': mkEd(98).publicKey } };
  ok(verifyEvidencePack(pack, { ...vopts, packSealOpts: wrongPack }).artifactsVerified === false, 'a pack sealed by an unrecognised packager -> REJECTED (packager pin)');
  // 6. a sealed pack with NO packSealOpts supplied -> fail-closed (cannot authenticate the bundle)
  ok(verifyEvidencePack(pack, vopts).admit === false, 'a packager-sealed pack verified without packSealOpts -> fail-closed');

  // 7. artifact failure propagates: a stale policy (below minVersion) -> not admitted
  const stalePack = buildEvidencePack({ record, signedPolicy: policy.signPolicy(policy.buildPolicy({ policy_id: 'acme-ai-release', version: 1, effective_ts: 0, issuer: 'Acme Compliance', criteria: {} }), owner) }, { packager: 'x', created_ts: 1200, packSigners: packager });
  ok(verifyEvidencePack(stalePack, { ...vopts, packSealOpts }).admit === false, 'a pack whose embedded policy is below minVersion -> BLOCK (replay resistance flows through)');

  // 8. SEMANTIC (council, critical): integrity/artifacts OK yet admit FALSE — downstream MUST gate on `admit`,
  //    never on integrity. Policy demands fully-pinned drift over a record with a hashless component.
  const hlManifest = { components: [ ...manifest.components, { type: 'library', name: 'libssl', version: '3.0', license: 'Apache-2.0' } ] };
  const hlRec = gov.buildGovernanceRecord({ manifest: hlManifest, evalRec, run }, { aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-llm-prod', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  const hlPolicy = policy.signPolicy(policy.buildPolicy({ policy_id: 'strict', version: 3, effective_ts: 0, issuer: 'Acme Compliance', criteria: { requireFullyPinnedDrift: true } }), owner);
  const hlPack = buildEvidencePack({ record: hlRec, signedPolicy: hlPolicy }, { packager: 'x', created_ts: 1200, packSigners: packager });
  const w = verifyEvidencePack(hlPack, { aibomSealOpts, evalSealOpts, traceSealOpts, policySealOpts: ownerSealOpts, suiteRegistry: registry, loadedComponents: hlManifest.components, atTs: 1000, packSealOpts });
  ok(w.integrityOk === true && w.artifactsVerified === true && w.admit === false, 'integrity+artifacts VERIFY yet admit=FALSE (a policy the record fails) — proves admit is the sole verdict, not integrity');

  // 9. STRICT top-level schema — an injected ride-along field is rejected
  ok(verifyEvidencePack({ ...pack, backdoor: true }, { ...vopts, packSealOpts }).integrityOk === false, 'an injected top-level field -> REJECTED (strict pack schema)');
  // 10. requirePackagerSeal — a consumer demanding bundle provenance blocks an unsigned (or envelope-stripped) pack
  ok(verifyEvidencePack(bare, { ...vopts, requirePackagerSeal: true }).admit === false, 'requirePackagerSeal -> an unsigned bundle is BLOCKED (provenance downgrade guard)');
  ok(verifyEvidencePack(pack, { ...vopts, packSealOpts, requirePackagerSeal: true }).admit === true, 'requirePackagerSeal -> a properly packager-sealed pack still ADMITs');

  // 11. fail-closed on garbage + report totality
  ok(verifyEvidencePack(null, vopts).admit === false && verifyEvidencePack({ v: 'x' }, vopts).admit === false, 'malformed pack -> fail-closed');
  let threw = (f) => { try { f(); return false; } catch { return true; } };
  ok(!threw(() => evidenceReport(null, null)) && !threw(() => evidenceReport(pack, v)), 'evidenceReport is TOTAL');
  ok(/gate on `admit`/.test(evidenceReport(pack, v)) && /not a certification/.test(evidenceReport(pack, v)), 'evidenceReport carries the gate-on-admit + honest-scope note');

  console.log('pqgovern-evidence self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgovern-evidence\.mjs$/.test(process.argv[1] || '')) selfTest();
