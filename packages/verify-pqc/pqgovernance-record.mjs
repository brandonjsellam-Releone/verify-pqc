/*!
 * pqgovernance-record — the AI GOVERNANCE RECORD: MAP ∧ MEASURE ∧ MANAGE, cross-bound to ONE model.
 *
 * The capstone of the AI-governance trilogy — a single verifiable artifact tying together, for one
 * model (identity = model weights hash):
 *   - pqaibom  (MAP)     : what went INTO the system — signed by the DECLARANT.
 *   - pqeval   (MEASURE) : how it was evaluated       — signed by the EVALUATOR (aibom_ref + model_hash
 *                          cross-bound to the AIBOM's declared model).
 *   - pqtrace  (MANAGE)  : what it did at runtime      — signed by the RUNNER (step-0 commits the AIBOM's
 *                          runtime_binding + the model_hash, tying the run to the declared inventory AND to
 *                          the one anchored model — so a multi-model AIBOM can't let one trace serve two).
 *                          The record embeds the trace WITHOUT its per-step salts (owner-held), so sharing
 *                          the record does not disclose committed prompts/outputs (pqtrace privacy design).
 * Each leg is a SELF-ATTESTATION signed by a leg-specific signer set (the intended deployment is three
 * INDEPENDENT parties: declarant / evaluator / runner). The record proves the three attestations are
 * ABOUT THE SAME MODEL and mutually consistent — it does NOT make any leg's underlying claim
 * independently true (each leg keeps its own honest scope: pqaibom = declared inventory, pqeval =
 * self-reported eval, pqtrace = runner-attested log). Three honest scopes (apex review, 11 Jul 2026):
 *   - MODEL IDENTITY is anchored to a REAL weights hash: verify REQUIRES model_hash to be a 32/64-byte
 *     hex digest, so a null anchor cannot make the eval↔AIBOM model cross-bind pass vacuously.
 *   - SUBJECT is read from the SIGNED AIBOM (abom.subject), cross-checked equal across all three signed
 *     legs; the unsigned top-level record.subject label is never trusted as authority (it must merely
 *     agree). The returned subject is the signed one.
 *   - DISTINCT SIGNERS are SURFACED (distinctSigners), computed from the three envelopes' signer key
 *     sets — one operator COULD sign all three legs, so distinctness is ENFORCED only under
 *     opts.requireDistinctSigners:true (opt-in), never silently assumed.
 * A verifier that supplies its independently-observed loadedComponents also gets BOM-reality-drift
 * checked.
 *
 * verifyGovernanceRecord is TOTAL/fail-closed and requires each leg's pins (declarant / evaluator /
 * runner) + the eval's suiteRegistry, inheriting every leg's apex-hardening.
 *  Self-test: node pqgovernance-record.mjs
 */
import * as aibom from './pqaibom.mjs';
import * as pqeval from './pqeval.mjs';
import * as trace from './pqtrace.mjs';

const V = 'pqgov-1';
const isHex = (s, bytes) => typeof s === 'string' && new RegExp('^[0-9a-fA-F]{' + bytes * 2 + '}$').test(s);
// the SET of signer public keys behind a signed leg's pqseal envelope, for cross-leg separation-of-duties.
const signerKeySet = (envelope) => new Set((envelope && Array.isArray(envelope.legs) ? envelope.legs.map((l) => l.pub_hex).filter(Boolean) : []));
// pairwise DISJOINT = no key signs two legs (council: string-inequality let [K1,K2] vs [K1,K3] pass while sharing K1).
const disjoint = (x, y) => { for (const k of x) if (y.has(k)) return false; return true; };

/** build the record. In: {manifest, evalRec, run}. Opts carry the three signer sets + subject/ids. */
export function buildGovernanceRecord({ manifest, evalRec = {}, run = {} }, opts = {}) {
  const bom = aibom.buildAibom(manifest, { assuranceLevel: opts.assuranceLevel ?? aibom.ASSURANCE.declared, subject: opts.subject ?? null, declarant: opts.declarant ?? null, generated_ts: opts.generated_ts ?? 0 });
  const signedBom = aibom.signAibom(bom, opts.aibomSigners);
  // the subject model's weights hash is the SHARED identity anchor across the three legs.
  const model = (bom.components || []).find((c) => c.type === 'model');
  const model_hash = model ? model.weights_sha256 : null;

  const ev = pqeval.buildEval({ ...evalRec, subject: opts.subject ?? null, model_hash, aibom_ref: bom.runtime_binding },
    { ts: opts.generated_ts ?? 0, declarant: opts.evaluator ?? null, suiteRegistry: opts.suiteRegistry });
  const signedEval = pqeval.signEval(ev, opts.evalSigners);

  const w = new trace.TraceWriter({ session_id: opts.session_id ?? null, runner: opts.runner ?? 'runner' });
  const t0 = Number.isInteger(opts.generated_ts) ? opts.generated_ts : 0;
  // step-0 config meta commits (under the runner's seal) BOTH the subject AND the model_hash the run was
  // about — so the MANAGE leg is bound to the SAME model as MAP/MEASURE (council: without model_hash here,
  // a multi-model AIBOM lets ONE trace certify records about different models). Runner-attested, per pqtrace.
  const cfg = w.addStep({ kind: 'config', actor: 'runner', content: bom.runtime_binding, ts: t0, meta: { subject: opts.subject ?? null, model_hash } });
  let ts = t0;
  for (const s of (Array.isArray(run.steps) ? run.steps : [])) w.addStep({ ...s, ts: ++ts });
  const sealedTrace = w.finish(opts.traceSigners, { ended_ts: ts });

  // STRIP the per-step HMAC salts (council: pqtrace's privacy design keeps salts with the OWNER, NOT in the
  // shareable artifact — embedding them lets a record-holder dictionary-attack committed prompts/outputs).
  // The step-0 runtime_binding disclosure travels separately via the non-secret top-level binding_salt, so
  // verification is unaffected while private run-step contents stay committed-but-undisclosed.
  const { salts, ...traceNoSalts } = sealedTrace;
  return { v: V, subject: opts.subject ?? null, model_hash, aibom: signedBom, eval: signedEval, trace: traceNoSalts, runtime_binding: bom.runtime_binding, binding_salt: cfg.salt_hex };
}

/** verifyGovernanceRecord — TOTAL/fail-closed. Verifies each leg under its OWN pins, cross-binds the
 * eval + trace to the AIBOM's model/inventory, and (if loadedComponents supplied) checks drift. */
export function verifyGovernanceRecord(record, opts = {}) {
  const FAIL = (why) => ({ verified: false, why, aibomOk: false, evalOk: false, traceOk: false, crossBound: false, modelHashWellFormed: false, modelInBom: false, subjectConsistent: false, distinctSigners: false, driftChecked: false, driftOk: null, driftUnpinned: null });
  try {
    if (!record || record.v !== V || !record.aibom || !record.eval || !record.trace) return FAIL('malformed record');
    const a = aibom.verifyAibom(record.aibom, { sealOpts: opts.aibomSealOpts, allowUnpinnedSeal: opts.allowUnpinnedSeal });
    // verifyEval's opts.aibom cross-binds: eval.aibom_ref === aibom.runtime_binding AND eval.model_hash
    // is a declared model's weights hash — so the signed eval attestation is provably ABOUT the mapped
    // model (the evaluator self-attests a measurement of it; the measurement itself is not independently
    // proven — "a signed lie is possible").
    const e = pqeval.verifyEval(record.eval, { sealOpts: opts.evalSealOpts, suiteRegistry: opts.suiteRegistry, allowUnpinnedSeal: opts.allowUnpinnedSeal, aibom: record.aibom.bom });
    const t = trace.verifyTrace(record.trace, { sealOpts: opts.traceSealOpts, allowUnpinnedSeal: opts.allowUnpinnedSeal, disclosures: { 0: { content: record.runtime_binding, salt_hex: record.binding_salt } } });
    const abom = record.aibom.bom;
    // MODEL-BYTES ANCHOR (apex review): the model-identity anchor must be a REAL weights hash — a null
    // model_hash would make model_hash===model_hash vacuously true. modelHashWellFormed names EXACTLY what
    // this checks (32/64-byte hex shape); the cryptographic binding is crossBound below (council: the old
    // name "modelPinned" overclaimed a syntactic shape check as a cryptographic pin).
    const modelHashWellFormed = isHex(record.model_hash, 32) || isHex(record.model_hash, 64);
    // SELF-CONTAINED model binding (council defense-in-depth): the SIGNED AIBOM must itself declare a model
    // whose weights hash IS record.model_hash — so the "one model" property is enforced HERE, not only
    // inherited from verifyEval's internal aibom check.
    const modelInBom = modelHashWellFormed && (abom.components || []).some((c) => c.type === 'model' && c.weights_sha256 === record.model_hash);
    // MANAGE leg bound to the SAME model (council): the runner's SIGNED step-0 config meta must attest
    // model_hash === record.model_hash — so a multi-model AIBOM cannot let one trace certify a record about
    // a DIFFERENT declared model. (Runner self-attestation of which model ran, per pqtrace's trust model.)
    const traceModelHash = (record.trace.steps && record.trace.steps[0] && record.trace.steps[0].meta) ? record.trace.steps[0].meta.model_hash : undefined;
    const traceBound = !!(record.runtime_binding === abom.runtime_binding && t.contentOk === true && modelHashWellFormed && traceModelHash === record.model_hash);
    const evalBound = !!(e.verified && record.eval.rec && modelHashWellFormed && record.eval.rec.model_hash === record.model_hash && record.eval.rec.aibom_ref === abom.runtime_binding);
    // SUBJECT is authenticated from the SIGNED legs, never from the unsigned top-level label (apex review:
    // attribution-spoofing). All three legs must agree, and the top-level label must match the signed one.
    const traceSubject = (record.trace.steps && record.trace.steps[0] && record.trace.steps[0].meta) ? record.trace.steps[0].meta.subject : undefined;
    const subjectConsistent = !!(abom.subject != null && record.subject === abom.subject && record.eval.rec.subject === abom.subject && traceSubject === abom.subject);
    // DISTINCT SIGNERS surfaced (not merely assumed): the three legs' signer key sets must be pairwise
    // DISJOINT — no key may sign two legs (true separation of duties), not merely non-identical sets.
    const sA = signerKeySet(record.aibom.envelope), sE = signerKeySet(record.eval.envelope), sT = signerKeySet(record.trace.envelope);
    const distinctSigners = !!(sA.size && sE.size && sT.size && disjoint(sA, sE) && disjoint(sE, sT) && disjoint(sA, sT));
    const crossBound = !!(a.verified && modelHashWellFormed && modelInBom && evalBound && traceBound && subjectConsistent);
    const driftChecked = !!opts.loadedComponents;
    const drift = driftChecked ? aibom.checkBomRealityDrift(abom, opts.loadedComponents) : null;
    const driftOk = driftChecked ? !drift.drift : null;
    // SURFACE the hashless components (council): checkBomRealityDrift matches a hashless component by declared
    // METADATA only, so driftOk:true does NOT mean "every byte verified". Callers (the gate) can require this
    // list be empty. Never dropped silently — "signed vs surfaced".
    const driftUnpinned = driftChecked ? ((drift && drift.unpinned) || []) : null;
    const verified = !!(a.verified && e.verified && t.verified && crossBound && driftOk !== false && (!opts.requireDistinctSigners || distinctSigners));
    const why = !a.verified ? 'aibom: ' + a.why : !e.verified ? 'eval: ' + e.why : !t.verified ? 'trace: ' + t.why
      : !modelHashWellFormed ? 'model_hash is not a well-formed weights hash — the model-identity anchor is missing'
      : !modelInBom ? 'the signed AIBOM does not declare a model whose weights hash is record.model_hash'
      : !subjectConsistent ? 'subject is inconsistent across the signed legs (or the top-level label is unauthenticated)'
      : !crossBound ? 'the three legs are not cross-bound to one model/inventory'
      : (opts.requireDistinctSigners && !distinctSigners) ? 'requireDistinctSigners: the three legs share a signing identity'
      : (driftOk === false) ? drift.alert : null;
    return { verified, why, aibomOk: a.verified, evalOk: e.verified, traceOk: t.verified, crossBound, modelHashWellFormed, modelInBom, subjectConsistent, distinctSigners, evalBound, traceBound, driftChecked, driftOk, driftUnpinned,
      subject: abom.subject, aibomGrade: a.verified ? a.grade : null, evalPosture: e.verified ? e.posture : null };
  } catch { return FAIL('exception (fail-closed)'); }
}

/* ---------- self-test: node pqgovernance-record.mjs ---------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  // THREE distinct attesting parties: declarant (AIBOM), evaluator (eval), runner (trace)
  const dA = mk(61), dC = mkEd(62), eA = mk(63), eC = mkEd(64), rA = mk(65), rC = mkEd(66);
  const aibomSigners = [dA, dC], evalSigners = [eA, eC], traceSigners = [rA, rC];
  const aibomSealOpts = { requireKinds: ['lattice', 'classical'], trusted: { 'ML-DSA-87': dA.publicKey, 'Ed25519': dC.publicKey } };
  const evalSealOpts = { requireKinds: ['lattice', 'classical'], trusted: { 'ML-DSA-87': eA.publicKey, 'Ed25519': eC.publicKey } };
  const traceSealOpts = { requireKinds: ['lattice', 'classical'], trusted: { 'ML-DSA-87': rA.publicKey, 'Ed25519': rC.publicKey } };
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
  const build = (over = {}) => buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners, evalSigners, traceSigners, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-system', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry, ...over });
  const vopts = { aibomSealOpts, evalSealOpts, traceSealOpts, suiteRegistry: registry };

  // 1. HAPPY PATH — three distinct parties, all verify, all cross-bound to one model
  const rec = build();
  const v = verifyGovernanceRecord(rec, { ...vopts, loadedComponents: manifest.components });
  ok(v.verified && v.aibomOk && v.evalOk && v.traceOk && v.crossBound, 'happy path: AIBOM ∧ eval ∧ trace verify + cross-bound to one model');
  ok(/A \(Bound\)/.test(v.aibomGrade) && /registered_standard/.test(v.evalPosture), 'record surfaces both the AIBOM grade + eval posture');
  ok(aibomSealOpts.trusted['ML-DSA-87'] !== evalSealOpts.trusted['ML-DSA-87'] && evalSealOpts.trusted['ML-DSA-87'] !== traceSealOpts.trusted['ML-DSA-87'], 'declarant, evaluator, runner are three distinct signing identities');

  // 2. eval ABOUT A DIFFERENT MODEL -> evalBound false -> REJECTED (cross-binding)
  const wrongModel = build();
  wrongModel.eval = pqeval.signEval(pqeval.buildEval({ ...evalRec, subject: 'acme-system', model_hash: 'b'.repeat(64), aibom_ref: rec.runtime_binding }, { ts: 1000, declarant: 'EvalLab', suiteRegistry: registry }), evalSigners);
  wrongModel.model_hash = 'b'.repeat(64);
  ok(verifyGovernanceRecord(wrongModel, vopts).verified === false, 'eval about a DIFFERENT model_hash than the AIBOM declares -> REJECTED');

  // 3. eval bound to a DIFFERENT AIBOM (wrong aibom_ref) -> evalBound false
  const wrongRef = build();
  wrongRef.eval = pqeval.signEval(pqeval.buildEval({ ...evalRec, subject: 'acme-system', model_hash: H, aibom_ref: 'c'.repeat(128) }, { ts: 1000, declarant: 'EvalLab', suiteRegistry: registry }), evalSigners);
  ok(verifyGovernanceRecord(wrongRef, vopts).evalBound === false, 'eval whose aibom_ref points elsewhere -> not cross-bound');

  // 4. each leg's pins are enforced independently: swap in an attacker-signed eval -> evalOk false
  const atkEval = [mk(200), mkEd(201)];
  const forgedEval = build();
  forgedEval.eval = pqeval.signEval(rec.eval.rec, atkEval);
  ok(verifyGovernanceRecord(forgedEval, vopts).evalOk === false, 'eval sealed by ATTACKER keys -> evalOk false (evaluator pin)');

  // 5. BOM-reality drift on the runtime -> REJECTED
  const swapped = JSON.parse(JSON.stringify(manifest.components)); swapped[0].weights_sha256 = 'd'.repeat(64);
  ok(verifyGovernanceRecord(rec, { ...vopts, loadedComponents: swapped }).verified === false, 'runtime loaded a different model -> BOM-reality drift -> REJECTED');

  // 6. drift is OPT-IN (no loadedComponents -> driftOk null, still verifies on the three signed legs)
  const vNo = verifyGovernanceRecord(rec, vopts);
  ok(vNo.verified === true && vNo.driftChecked === false && vNo.driftOk === null, 'no loadedComponents -> driftOk null (not synthetic true), still verifies');

  // 7. fail-closed with no pins
  ok(verifyGovernanceRecord(rec, {}).verified === false, 'unpinned verify FAILS CLOSED');

  // 8. ATTRIBUTION SPOOF (apex review): mutate the UNSIGNED top-level subject label -> REJECTED, and the
  //    returned subject is the SIGNED one (abom.subject), never the attacker's label.
  const spoof = build();
  spoof.subject = 'TRUSTED MegaCorp Certified System';
  const vSpoof = verifyGovernanceRecord(spoof, vopts);
  ok(vSpoof.verified === false && vSpoof.subjectConsistent === false, 'tampered top-level subject label -> REJECTED (subjectConsistent false)');
  ok(vSpoof.subject === 'acme-system', 'returned subject is the SIGNED AIBOM subject, not the unsigned label');
  ok(verifyGovernanceRecord(rec, vopts).subject === 'acme-system' && verifyGovernanceRecord(rec, vopts).subjectConsistent === true, 'honest record: subjectConsistent true, subject surfaced from the signed leg');

  // 9. VACUOUS MODEL ANCHOR (apex review): a null model_hash must NOT let the eval↔AIBOM model cross-bind
  //    pass via null===null. Build a record with a null model-identity anchor -> REJECTED.
  const nullModel = build();
  nullModel.model_hash = null;
  nullModel.eval = pqeval.signEval(pqeval.buildEval({ ...evalRec, subject: 'acme-system', model_hash: null, aibom_ref: nullModel.runtime_binding }, { ts: 1000, declarant: 'EvalLab', suiteRegistry: registry }), evalSigners);
  const vNull = verifyGovernanceRecord(nullModel, vopts);
  ok(vNull.verified === false && vNull.modelHashWellFormed === false, 'null model_hash (vacuous null===null anchor) -> REJECTED (modelHashWellFormed false)');
  ok(verifyGovernanceRecord(rec, vopts).modelHashWellFormed === true && verifyGovernanceRecord(rec, vopts).modelInBom === true, 'honest record: modelHashWellFormed + modelInBom true (real weights hash declared in the AIBOM)');

  // 10. DISTINCT SIGNERS surfaced + opt-in enforcement: three separate signer sets -> distinctSigners true.
  ok(verifyGovernanceRecord(rec, vopts).distinctSigners === true, 'three separate signer sets -> distinctSigners true (surfaced)');
  // one operator signs ALL THREE legs: still verifies by default (distinctness is opt-in), but distinctSigners
  // false, and requireDistinctSigners:true REJECTS it.
  const sharedVopts = { aibomSealOpts: evalSealOpts, evalSealOpts, traceSealOpts: evalSealOpts, suiteRegistry: registry };
  const shared = build({ aibomSigners: evalSigners, traceSigners: evalSigners });
  const vShared = verifyGovernanceRecord(shared, sharedVopts);
  ok(vShared.verified === true && vShared.distinctSigners === false, 'one operator signs all three legs -> verifies by default but distinctSigners:false (surfaced, not silently assumed)');
  ok(verifyGovernanceRecord(shared, { ...sharedVopts, requireDistinctSigners: true }).verified === false, 'requireDistinctSigners:true -> a shared-signer record is REJECTED');

  // 11. SET-DISJOINT distinct signers (council): a key shared across TWO legs (aibom+eval both include dA)
  //     must make distinctSigners FALSE — the old string-inequality [dA,dC]!=[dA,eC] wrongly passed.
  const shareVopts = { aibomSealOpts, evalSealOpts: { requireKinds: ['lattice', 'classical'], trusted: { 'ML-DSA-87': dA.publicKey, 'Ed25519': eC.publicKey } }, traceSealOpts, suiteRegistry: registry, loadedComponents: manifest.components };
  const shareRec = build({ evalSigners: [dA, eC] });                 // eval shares dA with the AIBOM leg
  const vShare = verifyGovernanceRecord(shareRec, shareVopts);
  ok(vShare.aibomOk && vShare.evalOk && vShare.traceOk && vShare.distinctSigners === false, 'a key shared across two legs -> distinctSigners FALSE (pairwise-disjoint, not string-inequality)');
  ok(verifyGovernanceRecord(shareRec, { ...shareVopts, requireDistinctSigners: true }).verified === false, 'requireDistinctSigners:true -> a shared-KEY (not just shared-set) record is REJECTED');

  // 12. SELF-CONTAINED model binding (council): a well-formed model_hash NOT declared in the signed AIBOM
  //     is rejected (modelInBom false) even though it is valid hex.
  const wrongHash = build();
  wrongHash.model_hash = 'e'.repeat(64);                             // valid hex, but not the AIBOM's model (H='a'*64)
  const vWrong = verifyGovernanceRecord(wrongHash, vopts);
  ok(vWrong.verified === false && vWrong.modelInBom === false, 'model_hash not declared as a model in the signed AIBOM -> REJECTED (modelInBom false)');

  // 13. MULTI-MODEL leg-swap (apex-team): with a 2-model AIBOM, the runner's SIGNED step-0 meta.model_hash
  //     binds the MANAGE leg to ONE model, so a byte-identical trace cannot certify a record about the OTHER.
  const HB = 'b'.repeat(64);
  const multiManifest = { components: [
    { type: 'model', name: 'flagship-A', version: '1.0', weights_sha256: H, provider: 'Acme', source_url: 'https://hf.co/acme/a', license: 'Apache-2.0', task: 'text-generation', model_card_url: 'https://hf.co/acme/a/card' },
    { type: 'model', name: 'cheap-B', version: '1.0', weights_sha256: HB, provider: 'Acme', source_url: 'https://hf.co/acme/b', license: 'Apache-2.0', task: 'text-generation', model_card_url: 'https://hf.co/acme/b/card' },
    { type: 'dataset', name: 'acme-corpus', hash: H, provenance: 'curated 2025', license: 'CC-BY-4.0', data_classification: 'internal', consent_mechanism: 'licensed', split: 'train' },
  ] };
  const mvopts = { aibomSealOpts, evalSealOpts, traceSealOpts, suiteRegistry: registry };   // no loadedComponents (drift opt-in; the two manifests differ)
  const recA = buildGovernanceRecord({ manifest: multiManifest, evalRec, run }, { aibomSigners, evalSigners, traceSigners, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-system', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  ok(verifyGovernanceRecord(recA, mvopts).verified === true, 'multi-model AIBOM: the record for the FIRST declared model verifies');
  // swap ONLY the eval leg to be about model B + set top-level model_hash=HB; keep the byte-identical trace.
  const recB = { ...recA, model_hash: HB, eval: pqeval.signEval(pqeval.buildEval({ ...evalRec, subject: 'acme-system', model_hash: HB, aibom_ref: recA.runtime_binding }, { ts: 1000, declarant: 'EvalLab', suiteRegistry: registry }), evalSigners) };
  const vB = verifyGovernanceRecord(recB, mvopts);
  ok(vB.evalOk === true && vB.modelInBom === true && vB.traceBound === false && vB.verified === false, 'a byte-identical trace CANNOT certify a record about a DIFFERENT declared model (step-0 attests model A) -> REJECTED (traceBound false)');

  console.log('pqgovernance-record self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgovernance-record\.mjs$/.test(process.argv[1] || '')) selfTest();
