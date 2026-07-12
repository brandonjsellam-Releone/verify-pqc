/*!
 * pqgovern-anchor — TRANSPARENCY-anchored AI governance admissions (reference, DRAFT).
 *
 * The governance quartet proves WHO set WHAT criteria and WHETHER a model was admitted. This adds the
 * missing PUBLIC-ACCOUNTABILITY dimension: bind each governed admission's evidence into an append-only
 * RFC-6962 transparency log, so anyone holding a pinned log key can prove "this exact governance
 * evidence pack was recorded at this position/time" (inclusion) and detect a log that equivocates
 * (serves two histories of the same size). The anchor commits the pack_hash (which itself binds the
 * record+policy), so the admission is ALWAYS re-derived from the pack — the log records EXISTENCE +
 * ORDER + TIME, never a claimed verdict.
 *
 * HONEST SCOPE (claim-hygiene LAW): inclusion proves the pack was in the log the STH commits to, under
 * a log key the VERIFIER pins — it does NOT certify the model, nor prove the log is COMPLETE (a
 * withholding log can omit entries; completeness needs a witness/gossip quorum — see pqkt). APPEND-ONLY
 * across successive STHs is NOT given by inclusion alone — a monitor must run verifyLogConsistency (RFC-
 * 6962 consistency proofs) to catch a history rewrite. The entry's `anchored_ts` is SELF-DECLARED by the
 * anchorer; the authoritative time is the STH's signed `ts` (surfaced as anchoredAt.ts). It inherits
 * every governance leg's honest limit. The admission verdict is recomputed by verifyAnchoredAdmission,
 * never trusted from the log entry. TOTAL/fail-closed.
 *  Self-test: node pqgovern-anchor.mjs
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { PQTransparencyLog, verifySTH, entryLeafHash, verifyInclusionRFC, verifyConsistency } from './pqsign.mjs';
import * as evidence from './pqgovern-evidence.mjs';

const V = 'pqgov-anchor-1';
const ANCHOR_KIND = 'pqgov-admission';
const isInt = (n) => Number.isInteger(n);

/** the log-leaf projection of an admission — commits the pack_hash + the identity metadata (order/time
 * come from the log). The pack_hash binds the record+policy, so this leaf is tamper-evident vs the pack. */
export function admissionEntry(pack, opts = {}) {
  if (!pack || typeof pack !== 'object' || typeof pack.pack_hash !== 'string') throw new Error('admissionEntry requires an evidence pack with a pack_hash');
  const p = pack.policy && pack.policy.policy;
  const model = pack.record && (pack.record.model_hash ?? null);
  const subject = pack.record && (pack.record.subject ?? null);
  return {
    kind: ANCHOR_KIND, v: V, pack_hash: pack.pack_hash,
    policy_id: p ? p.policy_id : null, policy_version: p ? p.version : null,
    model_hash: model, subject,
    anchored_ts: isInt(opts.anchored_ts) ? opts.anchored_ts : 0,
  };
}

/** append an admission's evidence to the transparency log. REFUSES a duplicate pack_hash (best-effort
 * anti-equivocation within one log view — a second, different anchor of the same pack is rejected). */
export function anchorAdmission(pack, log, opts = {}) {
  if (!(log instanceof PQTransparencyLog)) throw new Error('anchorAdmission requires a PQTransparencyLog');
  const entry = admissionEntry(pack, opts);
  const dup = log.entries.find((e) => e && e.kind === ANCHOR_KIND && e.pack_hash === entry.pack_hash);
  if (dup) throw new Error('this admission pack_hash is already anchored in the log');
  const index = log.append(entry);
  return { index, entry };
}

/** verifyAnchoredAdmission({pack, entry, inclusion, sth, logPub}, opts) — TOTAL/fail-closed.
 *  Re-derives the admission from the pack (verifier's own pins via opts) AND proves the pack is INCLUDED
 *  in the log at inclusion.index under the pinned STH (opts.logPub or logView.logPub). */
export function verifyAnchoredAdmission(anchor, opts = {}) {
  // NOTE (evidence-pack lesson, applied proactively): `admit` is the SOLE admission verdict; `anchored`
  // means "provably in the log under the pinned STH"; `artifactsVerified` means "crypto verifies". There
  // is NO composite `verified` field that could be mistaken for admission — a valid, anchored record can
  // still BLOCK. Gate admission on `admit`; gate "publicly recorded" on `anchored`.
  const FAIL = (why) => ({ admit: false, anchored: false, integrityOk: false, artifactsVerified: false, why, evidence: null, anchoredAt: null });
  try {
    if (!anchor || typeof anchor !== 'object' || !anchor.pack || !anchor.entry || !anchor.inclusion || !anchor.sth) return FAIL('malformed anchor');
    const { pack, entry, inclusion, sth } = anchor;
    const logPub = anchor.logPub || opts.logPub;
    if (!logPub) return FAIL('a pinned log public key (logPub) is required to authenticate the STH');
    // 1. RE-DERIVE the admission from the pack under the verifier's pins (the log carries NO verdict).
    const ev = evidence.verifyEvidencePack(pack, opts);
    const base = { admit: !!ev.admit, integrityOk: ev.integrityOk, artifactsVerified: ev.artifactsVerified, evidence: ev };
    // 2. the anchored entry must refer to THIS pack + be its canonical projection.
    if (entry.kind !== ANCHOR_KIND || entry.v !== V || entry.pack_hash !== pack.pack_hash) return { ...base, anchored: false, why: 'the log entry does not refer to this pack', anchoredAt: null };
    // index must be in range for the STH's tree (council: explicit bound, don't rely on the RFC walker alone).
    if (!isInt(inclusion.index) || !isInt(sth.tree_size) || inclusion.index < 0 || inclusion.index >= sth.tree_size) return { ...base, anchored: false, why: 'inclusion index out of range for the STH tree size', anchoredAt: null };
    // 3. INCLUSION: the entry is a leaf of the tree the pinned STH commits to (RFC-6962).
    const sthOk = verifySTH(sth, logPub);
    const leaf = entryLeafHash(entry);
    const leafBound = inclusion.leaf && bytesToHex(leaf) === bytesToHex(inclusion.leaf);
    const sizeOk = inclusion.tree_size === sth.tree_size;
    const anchored = !!(sthOk && leafBound && sizeOk && verifyInclusionRFC(leaf, inclusion.index, sth.tree_size, (inclusion.proof || []).map((x) => x.sibling), hexToBytes(sth.root_hex)));
    return { ...base, anchored,
      why: !ev.artifactsVerified ? ('evidence: ' + (ev.why || 'artifacts did not verify')) : (!anchored ? 'admission is not provably anchored under the pinned STH' : null),
      anchoredAt: anchored ? { index: inclusion.index, tree_size: sth.tree_size, ts: sth.ts ?? null } : null };
  } catch { return FAIL('exception (fail-closed)'); }
}

/** verifyLogConsistency(oldSth, newSth, consistencyProof, logPub) — the APPEND-ONLY guard (council/Qwen:
 * same-size fork detection alone is NOT enough — a log can rewrite history via a LARGER, non-consistent
 * STH whose prefix was mutated). Verifies BOTH STHs under the pinned log key AND that the old tree is an
 * RFC-6962 CONSISTENT PREFIX of the new one (via pqsign.verifyConsistency, machine-checked in
 * rfc6962_consistency_algo_z3), so a prefix-mutation / history-rewrite between two observed STHs is caught.
 * A monitor runs this across successive STHs to hold the log append-only. TOTAL/fail-closed. */
export function verifyLogConsistency(oldSth, newSth, consistencyProof, logPub) {
  try {
    if (!oldSth || !newSth || !logPub || !Array.isArray(consistencyProof)) return { consistent: false, why: 'malformed input' };
    if (!isInt(oldSth.tree_size) || !isInt(newSth.tree_size) || typeof oldSth.root_hex !== 'string' || typeof newSth.root_hex !== 'string') return { consistent: false, why: 'malformed STH' };
    if (!verifySTH(oldSth, logPub) || !verifySTH(newSth, logPub)) return { consistent: false, why: 'an STH is not authentic under the pinned log key' };
    if (newSth.tree_size < oldSth.tree_size) return { consistent: false, why: 'newSth is smaller than oldSth (non-monotonic — the log shrank)' };
    const proof = consistencyProof.map((x) => (x && x.sibling) ? x.sibling : x);
    const ok = verifyConsistency(oldSth.tree_size, newSth.tree_size, hexToBytes(oldSth.root_hex), hexToBytes(newSth.root_hex), proof);
    return { consistent: !!ok, why: ok ? null : 'the old tree is NOT a consistent prefix of the new tree (history rewrite / prefix mutation)' };
  } catch { return { consistent: false, why: 'exception (fail-closed)' }; }
}

/** detectLogEquivocation(sths) — flag a log that served TWO histories of the SAME size with DIFFERENT
 * roots (an exact-size fork). This is NECESSARY BUT NOT SUFFICIENT for append-only — a DIFFERENT-size
 * history rewrite is caught only by verifyLogConsistency (above). Use both. */
export function detectLogEquivocation(sths) {
  const bySize = new Map();
  for (const s of Array.isArray(sths) ? sths : []) {
    if (!s || !isInt(s.tree_size) || typeof s.root_hex !== 'string') continue;
    const prior = bySize.get(s.tree_size);
    if (prior !== undefined && prior !== s.root_hex) return { equivocation: true, tree_size: s.tree_size, reason: 'the log served two different roots for one tree size' };
    if (prior === undefined) bySize.set(s.tree_size, s.root_hex);
  }
  return { equivocation: false };
}

/* ---------- self-test: node pqgovern-anchor.mjs ---------- */
async function selfTest() {
  const gov = await import('./pqgovernance-record.mjs');
  const aibom = await import('./pqaibom.mjs');
  const pqeval = await import('./pqeval.mjs');
  const policy = await import('./pqgovern-policy.mjs');
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
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
  const record = gov.buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-llm-prod', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry });
  const signedPolicy = policy.signPolicy(policy.buildPolicy({ policy_id: 'acme-ai-release', version: 3, effective_ts: 500, expiry_ts: 5000, issuer: 'Acme Compliance', criteria: { minAibomGrade: 'B', minEvalPosture: 'C', requireDistinctSigners: true, requireDriftChecked: true } }), owner);
  const pack = evidence.buildEvidencePack({ record, signedPolicy }, { packager: 'Acme Release Eng', created_ts: 1200 });
  const vopts = { aibomSealOpts, evalSealOpts, traceSealOpts, policySealOpts: ownerSealOpts, suiteRegistry: registry, loadedComponents: manifest.components, atTs: 1000, minVersion: 3, requireWindow: true, requireDistinctSigners: true };

  // 1. anchor the admission into a transparency log + verify inclusion under the pinned log key
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(9));
  const log = new PQTransparencyLog();
  const { index } = anchorAdmission(pack, log, { anchored_ts: 1300 });
  const sth = log.signedTreeHead(logKey.secretKey, { ts: 5000 });
  const anchor = { pack, entry: log.entries[index], inclusion: log.inclusion(index), sth, logPub: logKey.publicKey };
  const v = verifyAnchoredAdmission(anchor, vopts);
  ok(v.anchored && v.admit && v.artifactsVerified, 'an anchored admission verifies: re-derived ADMIT + provably included under the pinned STH');
  ok(v.anchoredAt.index === index && v.anchoredAt.tree_size === 1, 'the anchor surfaces WHERE (index) + tree size it was recorded');
  ok(anchor.entry.policy_id === 'acme-ai-release' && anchor.entry.policy_version === 3 && anchor.entry.model_hash === H, 'the log entry carries the policy id/version + model_hash metadata (extraction from signedPolicy.policy is correct)');

  // 2. WRONG log key -> STH fails -> not anchored
  const wrongKey = ml_dsa87.keygen(new Uint8Array(32).fill(8));
  ok(verifyAnchoredAdmission({ ...anchor, logPub: wrongKey.publicKey }, vopts).anchored === false, 'a wrong/un-pinned log key -> STH fails -> NOT anchored');
  // 3. no logPub -> fail-closed
  ok(verifyAnchoredAdmission({ pack, entry: anchor.entry, inclusion: anchor.inclusion, sth }, vopts).anchored === false, 'no pinned log key -> fail-closed');

  // 4. entry for a DIFFERENT pack -> rejected (entry.pack_hash mismatch)
  const other = evidence.buildEvidencePack({ record, signedPolicy }, { packager: 'x', created_ts: 9999 });
  ok(verifyAnchoredAdmission({ ...anchor, pack: other }, vopts).anchored === false, 'the log entry must refer to THIS pack (pack_hash bind) -> mismatch REJECTED');

  // 5. TAMPERED inclusion proof (forged index) -> inclusion fails
  const badInc = { ...anchor, inclusion: { ...anchor.inclusion, index: 5 } };
  ok(verifyAnchoredAdmission(badInc, vopts).anchored === false, 'a forged inclusion index -> RFC-6962 inclusion fails -> NOT anchored');

  // 6. the ADMISSION verdict is still re-derived (not trusted from the log): a stale-policy pack anchors but does NOT admit
  const stalePack = evidence.buildEvidencePack({ record, signedPolicy: policy.signPolicy(policy.buildPolicy({ policy_id: 'p', version: 1, effective_ts: 0, issuer: 'x', criteria: {} }), owner) }, { packager: 'x', created_ts: 1200 });
  const log2 = new PQTransparencyLog(); const { index: i2 } = anchorAdmission(stalePack, log2, {}); const sth2 = log2.signedTreeHead(logKey.secretKey, { ts: 6000 });
  const va = verifyAnchoredAdmission({ pack: stalePack, entry: log2.entries[i2], inclusion: log2.inclusion(i2), sth: sth2, logPub: logKey.publicKey }, { ...vopts, minVersion: 3 });
  ok(va.anchored === true && va.admit === false, 'an admission is ANCHORED (recorded) yet re-derives to BLOCK — the log records existence, not a verdict');

  // 7. duplicate anchor of the same pack_hash is refused (best-effort anti-equivocation)
  let threw = (f) => { try { f(); return false; } catch { return true; } };
  ok(threw(() => anchorAdmission(pack, log, {})), 'a second anchor of the same pack_hash is REFUSED');

  // 8. log equivocation: two STHs of the same size with different roots -> flagged
  ok(detectLogEquivocation([{ tree_size: 1, root_hex: 'aa' }, { tree_size: 1, root_hex: 'bb' }]).equivocation === true, 'two roots for one tree size -> equivocation flagged');
  ok(detectLogEquivocation([sth, sth]).equivocation === false, 'the same STH twice -> no equivocation');

  // 8b. APPEND-ONLY via RFC-6962 CONSISTENCY (council/Qwen critical): same-size fork detection alone can't
  //     catch a different-size history rewrite — verifyLogConsistency does. A consistent extension verifies;
  //     a missing proof / non-monotonic / unpinned STH is rejected.
  const clog = new PQTransparencyLog();
  anchorAdmission(evidence.buildEvidencePack({ record, signedPolicy }, { created_ts: 2000 }), clog, {});
  const sthOld = clog.signedTreeHead(logKey.secretKey, { ts: 7000 });                 // tree size 1
  anchorAdmission(evidence.buildEvidencePack({ record, signedPolicy }, { created_ts: 2001 }), clog, {});
  anchorAdmission(evidence.buildEvidencePack({ record, signedPolicy }, { created_ts: 2002 }), clog, {});
  const sthNew = clog.signedTreeHead(logKey.secretKey, { ts: 7100 });                 // tree size 3
  const cproof = clog.consistency(sthOld.tree_size).proof;
  ok(verifyLogConsistency(sthOld, sthNew, cproof, logKey.publicKey).consistent === true, 'a consistent append-only extension (size 1 -> 3) verifies');
  ok(verifyLogConsistency(sthOld, sthNew, [], logKey.publicKey).consistent === false, 'an EMPTY consistency proof for a real 1->3 extension -> REJECTED (verifyConsistency is engaged, not just the STH pin)');
  ok(verifyLogConsistency(sthNew, sthOld, cproof, logKey.publicKey).consistent === false, 'non-monotonic (new < old — the log shrank) -> REJECTED');
  ok(verifyLogConsistency(sthOld, sthNew, cproof, wrongKey.publicKey).consistent === false, 'an STH not signed by the pinned log key -> REJECTED');
  ok(verifyLogConsistency(null, sthNew, cproof, logKey.publicKey).consistent === false, 'malformed input -> fail-closed');

  // 9. fail-closed on garbage
  ok(verifyAnchoredAdmission(null, vopts).anchored === false && verifyAnchoredAdmission({}, vopts).admit === false, 'malformed anchor -> fail-closed');

  console.log('pqgovern-anchor self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgovern-anchor\.mjs$/.test(process.argv[1] || '')) selfTest();
