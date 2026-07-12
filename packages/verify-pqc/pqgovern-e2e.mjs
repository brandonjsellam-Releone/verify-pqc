/*!
 * pqgovern-e2e — SUITE-LEVEL end-to-end integration test for the AI-GOVERNANCE QUARTET (reference, DRAFT).
 *
 * Every per-module self-test verifies ONE leg. This proves the four NIST-AI-RMF products COMPOSE, through
 * their intended PUBLIC APIs, into one cryptographically-bound admission decision — and that a tamper at
 * ANY stage breaks the whole chain. The by-INVOCATION complement to formal/pqgovern_admission_z3.py (which
 * proves the same admission soundness symbolically): "prove it, don't claim it" at the integration level.
 *
 * SCENARIO — "an org ships an AI model, PQ-attested + governed end to end, four independent parties":
 *   1. MAP      (pqaibom)              the DECLARANT signs an AI Bill of Materials (model + training data)
 *   2. MEASURE  (pqeval)               the EVALUATOR signs an evaluation bound to the AIBOM's model
 *   3. MANAGE   (pqtrace)              the RUNNER seals an execution trace committing the model + inventory
 *   4. CAPSTONE (pqgovernance-record)  the three legs are cross-bound to ONE model (buildGovernanceRecord)
 *   5. GOVERN   (pqgovern-policy)      the COMPLIANCE OWNER signs a versioned admission policy
 *   6. ADMIT    (evaluateUnderPolicy)  owner-pinned policy + owner-pinned record + drift-clean -> ADMIT
 *   7. BLOCK BATTERY                    every tamper/attack is REJECTED with the right reason
 *   8. SEAL     (pqseal)               one AND-composition over every stage's digest -> the whole flow is one record
 *   9. TRANSPARENCY                     the admission -> Evidence Pack -> ANCHOR (inclusion) -> fork-refusing MONITOR
 *      (pqgovern-evidence/anchor/         -> WITNESS quorum; a split-view (two heads at one size) is CAUGHT end-to-end
 *       monitor/witness)
 * Self-test: node pqgovern-e2e.mjs
 */
import * as aibom from './pqaibom.mjs';
import * as pqeval from './pqeval.mjs';
import * as gov from './pqgovernance-record.mjs';
import * as policy from './pqgovern-policy.mjs';
import * as evidence from './pqgovern-evidence.mjs';
import * as anchor from './pqgovern-anchor.mjs';
import * as monitor from './pqgovern-monitor.mjs';
import * as witness from './pqgovern-witness.mjs';
import { seal, openSeal } from './pqseal.mjs';
import { PQTransparencyLog } from './pqsign.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

const dig = (obj) => bytesToHex(sha512(utf8ToBytes(JSON.stringify(obj))));

async function main() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };

  // FOUR independent parties (distinct 2-leg lattice+classical signer sets)
  const declarant = [mk(11), mkEd(12)], evaluator = [mk(13), mkEd(14)], runner = [mk(15), mkEd(16)], owner = [mk(17), mkEd(18)];
  const rk = ['lattice', 'classical'];
  const pins = (s) => ({ requireKinds: rk, trusted: { 'ML-DSA-87': s[0].publicKey, 'Ed25519': s[1].publicKey } });
  const aibomSealOpts = pins(declarant), evalSealOpts = pins(evaluator), traceSealOpts = pins(runner), ownerSealOpts = pins(owner);

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

  // 1-4. MAP ∧ MEASURE ∧ MANAGE cross-bound to ONE model (the intended composition API).
  const record = gov.buildGovernanceRecord({ manifest, evalRec, run }, {
    aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner, assuranceLevel: aibom.ASSURANCE.bound,
    subject: 'acme-llm-prod', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  const vopts = { aibomSealOpts, evalSealOpts, traceSealOpts, suiteRegistry: registry, loadedComponents: manifest.components };
  const rv = gov.verifyGovernanceRecord(record, { ...vopts, requireDistinctSigners: true });
  ok(rv.verified && rv.crossBound && rv.distinctSigners && rv.modelInBom, 'stages 1-4: AIBOM ∧ eval ∧ trace cross-bound to ONE model by three distinct parties');

  // 5. GOVERN — the compliance owner signs a versioned admission policy.
  const signedPolicy = policy.signPolicy(policy.buildPolicy({
    policy_id: 'acme-ai-release', version: 3, effective_ts: 500, expiry_ts: 5000, issuer: 'Acme Compliance',
    description: 'prod AI model release gate', criteria: { minAibomGrade: 'B', minEvalPosture: 'C', requireDistinctSigners: true, requireDriftChecked: true },
  }), owner);

  // 6. ADMIT — owner-pinned policy over the owner-pinned, drift-clean record.
  const decision = policy.evaluateUnderPolicy(record, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000, minVersion: 3, requireWindow: true });
  ok(decision.admit === true && decision.policyVerified === true && decision.ownerAnchored === true && decision.windowChecked === true, 'stage 6: ADMIT under an owner-authenticated, in-window policy (evidence surfaced)');
  ok(/A \(Bound\)/.test(decision.gate.summary.aibomGrade) && decision.policy.policy_id === 'acme-ai-release' && decision.policy.version === 3, 'admission evidence carries the AIBOM grade + which signed policy gated it');
  console.log('\n' + policy.policyReport(decision) + '\n');

  // 7. BLOCK BATTERY — a tamper/attack at ANY stage breaks the whole admission.
  const clone = (x) => JSON.parse(JSON.stringify(x));
  // (a) attribution spoof — mutate the unsigned top-level subject
  const spoof = clone(record); spoof.subject = 'TRUSTED FedRAMP System';
  ok(policy.evaluateUnderPolicy(spoof, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === false, 'BLOCK (a): tampered subject label (attribution spoof)');
  // (b) attacker-signed MEASURE leg — evaluator pin
  const forgedEval = clone(record); forgedEval.eval = pqeval.signEval(record.eval.rec, [mk(200), mkEd(201)]);
  ok(policy.evaluateUnderPolicy(forgedEval, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === false, 'BLOCK (b): attacker-signed eval leg (evaluator pin)');
  // (c) wrong model — eval about a different model_hash than the AIBOM declares
  const wrongModel = clone(record); wrongModel.model_hash = 'e'.repeat(64);
  ok(policy.evaluateUnderPolicy(wrongModel, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === false, 'BLOCK (c): record model_hash not the AIBOM-declared model (cross-binding)');
  // (d) stale policy replay — an older validly-signed weaker policy below minVersion
  const stale = policy.signPolicy(policy.buildPolicy({ policy_id: 'acme-ai-release', version: 1, effective_ts: 0, issuer: 'Acme Compliance', criteria: {} }), owner);
  ok(policy.evaluateUnderPolicy(record, vopts, stale, { policySealOpts: ownerSealOpts, atTs: 1000, minVersion: 3 }).admit === false, 'BLOCK (d): superseded policy replay below minVersion');
  // (e) out-of-window when required
  ok(policy.evaluateUnderPolicy(record, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 9000, requireWindow: true }).admit === false, 'BLOCK (e): policy past expiry_ts under requireWindow');
  // (f) unpinned policy — owner authentication is forced on
  ok(policy.evaluateUnderPolicy(record, vopts, signedPolicy, { allowUnpinnedPolicy: true, atTs: 1000 }).admit === false, 'BLOCK (f): unpinned policy (owner auth forced on the admission path)');
  // (g) attacker-signed policy — wrong owner
  const forgedPolicy = policy.signPolicy(policy.buildPolicy({ policy_id: 'acme-ai-release', version: 3, effective_ts: 500, issuer: 'Acme Compliance', criteria: {} }), [mk(210), mkEd(211)]);
  ok(policy.evaluateUnderPolicy(record, vopts, forgedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === false, 'BLOCK (g): policy signed by a non-owner key');
  // (h) grade floor the record cannot meet — policy demands eval posture A over a record whose... (use minAibomGrade beyond A is impossible; demand fully-pinned drift with a hashless component)
  const hlManifest = { components: [ ...manifest.components, { type: 'library', name: 'libssl', version: '3.0', license: 'Apache-2.0' } ] };
  const hlRec = gov.buildGovernanceRecord({ manifest: hlManifest, evalRec, run }, { aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-llm-prod', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  const hlVopts = { aibomSealOpts, evalSealOpts, traceSealOpts, suiteRegistry: registry, loadedComponents: hlManifest.components };
  const strictDrift = policy.signPolicy(policy.buildPolicy({ policy_id: 'strict', version: 3, effective_ts: 0, issuer: 'Acme Compliance', criteria: { requireFullyPinnedDrift: true } }), owner);
  ok(policy.evaluateUnderPolicy(hlRec, hlVopts, strictDrift, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === false, 'BLOCK (h): requireFullyPinnedDrift with a hashless (metadata-only) component');
  // (i) runtime drift — the loaded inventory differs from the AIBOM
  const swapped = clone(manifest.components); swapped[0].weights_sha256 = 'd'.repeat(64);
  ok(policy.evaluateUnderPolicy(record, { ...vopts, loadedComponents: swapped }, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000 }).admit === false, 'BLOCK (i): BOM-reality drift (runtime loaded a different model)');

  // sanity: the CLEAN record still admits after the whole battery (0-regression / no shared mutation)
  ok(policy.evaluateUnderPolicy(record, vopts, signedPolicy, { policySealOpts: ownerSealOpts, atTs: 1000, minVersion: 3, requireWindow: true }).admit === true, 'the clean record still ADMITS after the battery (no shared-state corruption)');

  // 8. SEAL — one AND-composition over every stage's digest: the whole governed admission is ONE record.
  const flowDigest = { record: dig(record), policy: dig(signedPolicy), decision: dig({ admit: decision.admit, policy: decision.policy, grade: decision.gate.summary.aibomGrade }) };
  const flowSeal = seal(utf8ToBytes(JSON.stringify(flowDigest)), owner);
  const flowOpen = openSeal(utf8ToBytes(JSON.stringify(flowDigest)), flowSeal, ownerSealOpts);
  ok(flowOpen.verified === true, 'stage 8: the entire governed-admission flow seals into ONE owner-signed record');
  const tampered = { ...flowDigest, decision: dig({ admit: true }) };   // flip the recorded verdict
  ok(openSeal(utf8ToBytes(JSON.stringify(tampered)), flowSeal, ownerSealOpts).verified === false, 'tampering the sealed flow record is detected');

  // 9. TRANSPARENCY TIER — the governed admission is bundled into a self-verifiable Evidence Pack, ANCHORED into an
  //    RFC-6962 log, followed by a fork-refusing MONITOR, co-signed by a WITNESS quorum, and a split-view is CAUGHT.
  const tvopts = { ...vopts, policySealOpts: ownerSealOpts, atTs: 1000, minVersion: 3, requireWindow: true, requireDistinctSigners: true };
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(90));
  const W1 = ml_dsa87.keygen(new Uint8Array(32).fill(91)), W2 = ml_dsa87.keygen(new Uint8Array(32).fill(92));

  // 9a. EVIDENCE PACK — the whole admission re-derives under the VERIFIER's own pins (the pack carries no verdict).
  const pack = evidence.buildEvidencePack({ record, signedPolicy }, { created_ts: 2000 });
  ok(evidence.verifyEvidencePack(pack, tvopts).admit === true, 'stage 9a: the governed admission bundles into a self-verifiable Evidence Pack (admit re-derived under verifier pins)');

  // 9b. ANCHOR — the pack is recorded in an append-only log; inclusion is proven under the pinned STH.
  const log = new PQTransparencyLog();
  const { index } = anchor.anchorAdmission(pack, log, { anchored_ts: 2100 });
  const sth = log.signedTreeHead(logKey.secretKey, { ts: 8000 });
  const inc = log.inclusion(index);
  const av = anchor.verifyAnchoredAdmission({ pack, entry: log.entries[index], inclusion: inc, sth, logPub: logKey.publicKey }, tvopts);
  ok(av.admit === true && av.anchored === true, 'stage 9b: the admission is ANCHORED (inclusion proven under the pinned STH; admit re-derived)');

  // 9c. MONITOR — a fork-refusing watcher follows the log; the admission is on the monitored append-only chain.
  const mon = new monitor.GovernLogMonitor({ logPub: logKey.publicKey });
  ok(mon.ingestSTH(sth).accepted === true, 'stage 9c: a fork-refusing MONITOR accepts the signed head');
  ok(mon.verifyAdmission({ pack, entry: log.entries[index], inclusion: inc, sth }, tvopts).onMonitoredChain === true, 'stage 9c: the anchored admission is on the monitored chain');

  // 9d. WITNESS QUORUM — a witness co-signs the head; a single-witness quorum is consistent.
  const trusted = [W1.publicKey, W2.publicKey];
  const obs1 = witness.witnessObserve(sth, logKey.publicKey, W1.secretKey, W1.publicKey, { observed_ts: 1 });
  ok(witness.gossipReconcile([obs1], logKey.publicKey, { trustedWitnesses: trusted }).consistent === true, 'stage 9d: a WITNESS co-signs the anchored head -> quorum consistent');

  // 9e. SPLIT-VIEW CAUGHT — the log serves a DIFFERENT head at the same size to W2; the reconciler flags equivocation.
  const log2 = new PQTransparencyLog();
  anchor.anchorAdmission(evidence.buildEvidencePack({ record, signedPolicy }, { created_ts: 3000 }), log2, {});   // 1 entry, DIFFERENT content -> different root
  const forkSth = log2.signedTreeHead(logKey.secretKey, { ts: 8100 });   // same size, different root, SAME log key
  const obs2 = witness.witnessObserve(forkSth, logKey.publicKey, W2.secretKey, W2.publicKey, { observed_ts: 1 });
  const recon = witness.gossipReconcile([obs1, obs2], logKey.publicKey, { trustedWitnesses: trusted });
  ok(recon.equivocation === true && recon.equivocations[0].type === 'exact-size-fork', 'stage 9e: a WITNESS QUORUM CATCHES the split-view (log served two heads at one size) — full transparency tier end-to-end');

  console.log('pqgovern-e2e self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}

if (typeof process !== 'undefined' && process.argv && /pqgovern-e2e\.mjs$/.test(process.argv[1] || '')) main();
