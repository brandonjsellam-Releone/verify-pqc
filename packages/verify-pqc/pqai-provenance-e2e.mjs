/*!
 * pqai-provenance-e2e — the AI PROVENANCE RECORD: pqaibom (what went IN) ∧ pqtrace (what it DID),
 * bound by the BOM-reality-drift bridge. End-to-end composition test over BOTH real modules.
 *
 * The coherent product story, exercised for real (not asserted): a deployer publishes
 *   (1) a signed pqaibom — the declared static inventory (models/datasets/tools) + an assurance grade;
 *   (2) a signed pqtrace of a run whose FIRST step commits that AIBOM's runtime_binding hash — so the
 *       execution log is cryptographically tied to the exact declared inventory; and
 *   (3) at verify time, WHEN the verifier supplies its independently-observed loadedComponents, they are
 *       checked against the signed BOM (checkBomRealityDrift) — the static declaration is only honest if
 *       the runtime independently matches it.
 * A record verifies iff: the AIBOM verifies under the declarant's pins, the trace verifies under the
 * runner's pins, the trace is bound to THIS BOM's runtime_binding (disclosed), and drift is not DETECTED.
 * If loadedComponents is omitted, drift is NOT checked (driftChecked:false, driftOk:null) — the record can
 * still verify on the two signed artifacts, but makes NO runtime claim. WHEN loadedComponents is supplied
 * (an honest, independent observer that hashes what was actually loaded), this catches the "BOM says model
 * X, the runtime actually loaded model Y (swapped/poisoned)" attack — and, via the full-component binding,
 * a dropped sandbox / enabled egress / swapped licence too — for every component that declares a hash
 * (hashless components are matched by declared fields only; see `unpinned`).
 *
 * HONEST SCOPE (inherits both modules'): pqaibom attests a DECLARED manifest (self-attested, grade =
 * declaration assurance, not verified truth); pqtrace is runner-attested LOG provenance, not model
 * provenance. This record binds the two so a runtime that DRIFTS from the declaration is detectable —
 * it does not make either module's underlying claim independently true. Self-test: node pqai-provenance-e2e.mjs
 */
import * as aibom from './pqaibom.mjs';
import * as trace from './pqtrace.mjs';

/** Build an AI Provenance Record: sign the AIBOM, record+seal a trace whose config step commits the
 * AIBOM's runtime_binding. `run.steps` = [{kind, actor, content, model_id?, tool_name?, policy_id?}]. */
export function buildProvenanceRecord({ manifest, run = {} }, opts = {}) {
  const level = Number.isInteger(opts.assuranceLevel) ? opts.assuranceLevel : aibom.ASSURANCE.declared;
  const bom = aibom.buildAibom(manifest, { assuranceLevel: level, subject: opts.subject ?? null, declarant: opts.declarant ?? null, generated_ts: opts.generated_ts ?? 0 });
  const signedBom = aibom.signAibom(bom, opts.aibomSigners);

  const w = new trace.TraceWriter({ session_id: opts.session_id ?? null, runner: opts.subject ?? 'runner' });
  const t0 = Number.isInteger(opts.generated_ts) ? opts.generated_ts : 0;
  // step 0 BINDS the run to the declared inventory: its content is the AIBOM's runtime_binding hash.
  const cfg = w.addStep({ kind: 'config', actor: 'runner', content: bom.runtime_binding, ts: t0, meta: { aibom_subject: opts.subject ?? null } });
  let ts = t0;
  for (const s of (Array.isArray(run.steps) ? run.steps : [])) w.addStep({ ...s, ts: ++ts });
  const sealedTrace = w.finish(opts.traceSigners, { ended_ts: ts });

  return { v: 'pqai-provenance-1', aibom: signedBom, trace: sealedTrace, runtime_binding: bom.runtime_binding, binding_salt: cfg.salt_hex };
}

/** verifyProvenanceRecord — TOTAL/fail-closed. Verifies both artifacts under their pins, that the
 * trace is bound to THIS AIBOM, and (if loadedComponents given) that the runtime did not drift. */
export function verifyProvenanceRecord(record, opts = {}) {
  const FAIL = (why) => ({ verified: false, why, aibomOk: false, traceOk: false, boundToBom: false, driftChecked: false, driftOk: null });
  try {
    if (!record || record.v !== 'pqai-provenance-1' || !record.aibom || !record.trace) return FAIL('malformed record');
    const a = aibom.verifyAibom(record.aibom, { sealOpts: opts.aibomSealOpts, allowUnpinnedSeal: opts.allowUnpinnedSeal });
    // the trace's step-0 config must OPEN to the AIBOM's runtime_binding (proves the run declared THIS inventory)
    const t = trace.verifyTrace(record.trace, { sealOpts: opts.traceSealOpts, allowUnpinnedSeal: opts.allowUnpinnedSeal, disclosures: { 0: { content: record.runtime_binding, salt_hex: record.binding_salt } } });
    const boundToBom = !!(a.verified && record.runtime_binding === record.aibom.bom.runtime_binding && t.contentOk === true);
    // DRIFT is OPT-IN: if the verifier supplies no independently-observed loadedComponents, drift is NOT
    // checked -> driftOk:null (mirrors verifyAibom's anchorOk:null), NEVER a synthetic 'true'. A relying
    // party can then distinguish "artifacts valid" from "runtime validated" (apex review).
    const driftChecked = !!opts.loadedComponents;
    const drift = driftChecked ? aibom.checkBomRealityDrift(record.aibom.bom, opts.loadedComponents) : null;
    const driftOk = driftChecked ? !drift.drift : null;
    const verified = !!(a.verified && t.verified && boundToBom && driftOk !== false);   // unchecked (null) does not fail; detected drift (false) does
    const why = !a.verified ? 'aibom: ' + a.why : !t.verified ? 'trace: ' + t.why : !boundToBom ? 'trace not bound to this AIBOM' : (driftOk === false) ? drift.alert : null;
    return { verified, why, aibomOk: a.verified, traceOk: t.verified, boundToBom, driftChecked, driftOk, unpinned: drift ? drift.unpinned : undefined, aibomGrade: a.verified ? a.grade : null };
  } catch { return FAIL('exception (fail-closed)'); }
}

/* ---------- self-test: node pqai-provenance-e2e.mjs ---------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  // distinct declarant (AIBOM) and runner (trace) key sets — two different attesting parties
  const dA = mk(21), dC = mkEd(22), rA = mk(31), rC = mkEd(32);
  const aibomSigners = [dA, dC], traceSigners = [rA, rC];
  const aibomSealOpts = { requireKinds: ['lattice', 'classical'], trusted: { 'ML-DSA-87': dA.publicKey, 'Ed25519': dC.publicKey } };
  const traceSealOpts = { requireKinds: ['lattice', 'classical'], trusted: { 'ML-DSA-87': rA.publicKey, 'Ed25519': rC.publicKey } };
  const Hm = 'a'.repeat(64);

  const manifest = { components: [
    { type: 'model', name: 'acme-llm', version: '1.0', weights_sha256: Hm, provider: 'Acme', source_url: 'https://hf.co/acme/llm', license: 'Apache-2.0', task: 'text-generation', model_card_url: 'https://hf.co/acme/llm/card' },
    { type: 'dataset', name: 'acme-corpus', hash: Hm, provenance: 'curated 2025', license: 'CC-BY-4.0', data_classification: 'internal', consent_mechanism: 'licensed', split: 'train' },
    { type: 'tool', name: 'web_search', schema_hash: Hm, network_egress: true, sandboxed: true },
  ] };
  const run = { steps: [
    { kind: 'prompt', actor: 'user', content: 'What is the capital of France?' },
    { kind: 'model_output', actor: 'acme-llm', model_id: 'acme-llm', content: 'Paris.', tokens: { input: 12, output: 3 } },
  ] };
  const build = (over = {}) => buildProvenanceRecord({ manifest, run }, { aibomSigners, traceSigners, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-system', declarant: 'Acme Inc', generated_ts: 1000, ...over });

  // 1. HAPPY PATH — both verify, bound, no drift; the AIBOM is A (Bound), the run is tied to it
  const rec = build();
  const v = verifyProvenanceRecord(rec, { aibomSealOpts, traceSealOpts, loadedComponents: manifest.components });
  ok(v.verified && v.aibomOk && v.traceOk && v.boundToBom && v.driftOk, 'happy path: AIBOM ∧ trace verify, bound, no drift');
  ok(/A \(Bound\)/.test(v.aibomGrade), 'record surfaces the AIBOM grade "A (Bound)"');

  // 2. BOM-REALITY DRIFT — the runtime loaded a model with a DIFFERENT weight hash (swap/poison)
  const swapped = JSON.parse(JSON.stringify(manifest.components)); swapped[0].weights_sha256 = 'b'.repeat(64);
  const vd = verifyProvenanceRecord(rec, { aibomSealOpts, traceSealOpts, loadedComponents: swapped });
  ok(vd.verified === false && vd.driftOk === false && /DRIFT/.test(vd.why || ''), 'runtime loaded a different model -> BOM-REALITY DRIFT -> record REJECTED');

  // 3. TRACE NOT BOUND to this AIBOM — tamper the claimed binding
  const rb = JSON.parse(JSON.stringify(rec)); rb.runtime_binding = 'c'.repeat(128);
  ok(verifyProvenanceRecord(rb, { aibomSealOpts, traceSealOpts, loadedComponents: manifest.components }).boundToBom === false, 'a trace whose step-0 does not open to this AIBOM binding -> NOT bound -> REJECTED');

  // 4. FORGED TRACE (attacker runner keys) -> traceOk false even though the AIBOM is genuine
  const recF = build();
  recF.trace = trace.TraceWriter ? (() => { const w = new trace.TraceWriter({ runner: 'acme-system' }); w.addStep({ kind: 'config', actor: 'runner', content: rec.runtime_binding, ts: 1000 }); w.addStep({ kind: 'model_output', actor: 'evil', content: 'Berlin.', ts: 1001 }); return w.finish([mk(200), mkEd(201)], { ended_ts: 1001 }); })() : recF.trace;
  ok(verifyProvenanceRecord(recF, { aibomSealOpts, traceSealOpts, loadedComponents: manifest.components }).traceOk === false, 'trace sealed by ATTACKER runner keys -> traceOk false -> REJECTED');

  // 5. FORGED AIBOM GRADE (claim A on an L0) -> aibomOk false
  const recG = build({ assuranceLevel: aibom.ASSURANCE.declared });
  recG.aibom.bom.grade.letter = 'A'; recG.aibom.bom.grade.label = 'A (Declared)';
  ok(verifyProvenanceRecord(recG, { aibomSealOpts, traceSealOpts, loadedComponents: manifest.components }).aibomOk === false, 'forged AIBOM grade -> aibomOk false -> REJECTED');

  // 6. FAIL-CLOSED — no pins on either artifact
  ok(verifyProvenanceRecord(rec, { loadedComponents: manifest.components }).verified === false, 'unpinned verify FAILS CLOSED');

  // 7. two DISTINCT attesting parties — the declarant (AIBOM) and runner (trace) keys differ
  ok(aibomSealOpts.trusted['ML-DSA-87'] !== traceSealOpts.trusted['ML-DSA-87'], 'declarant and runner are distinct signing identities (static vs runtime attestation)');

  // 8. APEX-REVIEW regression: drift is OPT-IN — when loadedComponents is omitted, driftOk is null (not synthetic true)
  const vNoDrift = verifyProvenanceRecord(rec, { aibomSealOpts, traceSealOpts });
  ok(vNoDrift.driftChecked === false && vNoDrift.driftOk === null && vNoDrift.verified === true, 'no loadedComponents -> driftChecked:false, driftOk:null (NOT synthetic true), record still verifies on the 2 signed artifacts');
  ok(v.driftChecked === true && v.driftOk === true, 'with loadedComponents -> driftChecked:true, driftOk:true (a real runtime check ran)');
  // a runtime attribute drift (sandbox dropped) is caught when loadedComponents is supplied
  const dropped = JSON.parse(JSON.stringify(manifest.components)); dropped.find((c) => c.name === 'web_search').sandboxed = false;
  ok(verifyProvenanceRecord(rec, { aibomSealOpts, traceSealOpts, loadedComponents: dropped }).verified === false, 'runtime drops the tool sandbox -> drift DETECTED -> record REJECTED');

  console.log('pqai-provenance-e2e self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqai-provenance-e2e\.mjs$/.test(process.argv[1] || '')) selfTest();
