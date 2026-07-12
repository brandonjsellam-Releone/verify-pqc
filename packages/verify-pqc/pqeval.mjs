/*!
 * pqeval — VERIFIABLE AI EVALUATION ATTESTATION (a cryptographic eval-receipt; reference, DRAFT).
 *
 * The MEASURE leg of the AI-governance trilogy: pqaibom = MAP (what's in the system), pqtrace =
 * MANAGE (what it did at runtime), pqeval = MEASURE (how it was evaluated). Emits a pqseal-signed,
 * optionally RFC-6962-anchored record of a DECLARED evaluation, composing with the pqaibom it covers.
 *
 * CLAIM-HYGIENE — READ FIRST (council design round, DeepSeek + Qwen, 11 Jul 2026): this attests a
 * SELF-REPORTED evaluation. The pqseal signature proves WHO ran what methodology and what they
 * reported — NOT that the model actually achieves the scores (there is no independent re-execution;
 * that is a v2 "reproduced" tier). It is a "Verifiable AI Evaluation ATTESTATION", NEVER "verifiable
 * AI evaluation" (which would imply the SCORES are verified true). Structural defenses that make the
 * artifact honest about its own limits — mirroring pqaibom's grade caps, so gaming COSTS grade:
 *   (1) SUITE PROVENANCE is EARNED, not self-declared (apex review): suite_type ∈ {registered_standard,
 *       standard_modified, custom_ad_hoc}. The completeness check proves you reported EVERY metric in the
 *       suite you DECLARED (with a value) — it does NOT claim the suite is ADEQUATE. The registered/
 *       modified TIER is honored ONLY when the caller resolves the suite_hash against a trusted
 *       `suiteRegistry` (build + verify each pass it); WITHOUT a match the tier grades as custom_ad_hoc
 *       (capped 'C', label "…, unverified"). So the killer "declare my favourable subset as the suite"
 *       attack is capped, not merely attributable: a self-labelled registered_standard on a hand-picked
 *       subset grades 'C (custom_ad_hoc, unverified)' to any verifier that does not recognise the suite.
 *   (2) STATISTICAL RIGOUR is graded: a metric with no (finite) variance (ci/std_dev) caps at 'B'
 *       ("statistically unverified"); a PRIMARY capability metric on a non-held-out split (train/
 *       validation) caps at 'C'; a swept/best-of-seed run with no aggregate variance caps at 'C'.
 *   (3) CONTAMINATION must be disclosed — the WORST metric status drives it: 'unchecked' or 'partial'
 *       caps at 'C', 'checked_contaminated' at 'D'. A model trained on the benchmark cannot silently score.
 *   (4) MODEL-VERSION BINDING is graded: a record without a valid model_hash (32/64-byte hex) caps at
 *       'C' (artifact unpinned) — it still verifies as an attestation. If aibom_ref is given, a verifier
 *       that supplies the referenced signed AIBOM (opts.aibom) gets the cross-binding checked; without
 *       opts.aibom the reference is carried unverified (aibomBound:null).
 *   (5) SAFETY POWER: a declared safety category that is untested, or tested with n_cases below
 *       MIN_SAFETY_N, FAILS (caps 'C') — declaring a category you did not actually run cannot lift the grade.
 * verifyEval RE-NORMALIZES + fixpoint-checks the record (a hand-crafted record is rejected), re-derives
 * the suite tier against opts.suiteRegistry, and canon-compares the WHOLE posture AND the regulatory
 * block against re-derived values (a forged posture/score or an injected 'certified'/'FedRAMP' claim
 * cannot ride through). Inherits pqaibom's apex-hardening. SUPPORTS (never certifies) the NIST AI RMF
 * MEASURE function for STATIC/DECLARATIVE assessment only (not the whole MEASURE mandate — red-team/
 * bias/monitoring are broader), EU AI Act Art.15 accuracy/robustness declarations (the Art.15
 * cybersecurity leg needs separate evidence) + Annex IV(2)(g) test procedures, ISO/IEC 42001 AI-system
 * verification/validation. Self-attested pre-audit. FIPS 203/204/205 final; FIPS 206 draft.
 *  Self-test: node pqeval.mjs
 */
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { seal, openSeal } from './pqseal.mjs';
import { PQTransparencyLog, verifySTH, entryLeafHash, verifyInclusionRFC } from './pqsign.mjs';

const V = 'pqeval-1';
export const SUITE_TYPE = { registered_standard: 0, standard_modified: 1, custom_ad_hoc: 2 };
const SUITE_TYPE_NAME = ['registered_standard', 'standard_modified', 'custom_ad_hoc'];
const SUITE_TYPE_CAP = [null, 'B', 'C'];                 // custom self-defined suite can't exceed C
const LETTERS = ['A', 'B', 'C', 'D', 'F'];
const SPLITS = new Set(['test', 'held_out', 'validation', 'train', 'dev']);
const HELD_OUT = new Set(['test', 'held_out']);          // primary capability claims must be on these
const CONTAM = new Set(['unchecked', 'checked_clean', 'checked_contaminated', 'partial']);
const MIN_SAFETY_N = 30;

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const hashHex = (bytes) => bytesToHex(sha512(bytes instanceof Uint8Array ? bytes : utf8ToBytes(String(bytes))));
const isHex = (s, bytes) => typeof s === 'string' && new RegExp('^[0-9a-fA-F]{' + bytes * 2 + '}$').test(s);
const capLetter = (letter, cap) => (cap == null ? letter : (LETTERS.indexOf(letter) >= LETTERS.indexOf(cap) ? letter : cap));
const uniqSorted = (a) => [...new Set((Array.isArray(a) ? a : []).map(String))].sort();

// the regulatory block is a MODULE CONSTANT (not caller-supplied) so verify can re-derive + compare it
// byte-for-byte — an attacker cannot inject 'certified'/'FedRAMP authorized' into a signed record.
const REGULATORY = {
  note: 'SUPPORTS evidence-gathering for the NIST AI RMF MEASURE function (static/declarative assessment); does NOT certify capability.',
  supports: ['NIST AI RMF MEASURE (static/declarative subset)', 'EU AI Act Art.15 (accuracy/robustness declarations; the Art.15 cybersecurity leg needs separate evidence)', 'EU AI Act Annex IV(2)(g) test procedures', 'ISO/IEC 42001 (AI system verification/validation; supports clause-9 performance evaluation)'],
};
// a registered/modified suite tier is only HONORED when the caller resolves it against a trusted
// registry of accepted suite_hashes (a Set or array). suite_type alone is a self-declaration.
function registryHas(registry, hash) {
  if (!registry) return false;
  if (registry instanceof Set) return registry.has(hash);
  return Array.isArray(registry) ? registry.includes(hash) : false;
}
const isSuiteValidated = (suite, registry) => !!(suite && suite.suite_type !== SUITE_TYPE.custom_ad_hoc && registryHas(registry, suite.suite_hash));
// the exact posture projection stored in the record (build) and re-derived at verify — compared WHOLE.
const posturePublic = (g) => ({ letter: g.letter, label: g.label, score: g.score, suite_type: g.suite_type, effective_suite_type: g.effective_suite_type, suite_validated: g.suite_validated, complete: g.complete, findings: g.findings });

/* ---------- the suite definition + its committing hash ---------- */
// suite_hash commits the FULL declared test plan: name/version/type + the metric + safety-category
// lists the eval MUST cover. Recomputed at verify — a vendor cannot silently shrink the suite later.
export function suiteHash(suite) {
  return hashHex(canon({
    kind: 'pqeval-suite-1', name: suite.name ?? null, version: suite.version ?? null,
    suite_type: Number.isInteger(suite.suite_type) ? suite.suite_type : SUITE_TYPE.custom_ad_hoc,
    registry_ref: suite.registry_ref ?? null,
    expected_metrics: uniqSorted(suite.expected_metrics), expected_safety: uniqSorted(suite.expected_safety),
  }));
}

/* ---------- normalize a declared eval record (whitelists + defaults; idempotent) ---------- */
export function normalizeEval(rec) {
  const r = rec || {};
  const s = r.eval_suite || {};
  const suite = {
    name: s.name ?? null, version: s.version ?? null,
    suite_type: Number.isInteger(s.suite_type) && s.suite_type >= 0 && s.suite_type <= 2 ? s.suite_type : SUITE_TYPE.custom_ad_hoc,
    registry_ref: s.registry_ref ?? null,
    expected_metrics: uniqSorted(s.expected_metrics), expected_safety: uniqSorted(s.expected_safety),
  };
  suite.suite_hash = suiteHash(suite);
  const metric = (m) => ({
    name: String(m.name), split: SPLITS.has(m.split) ? m.split : null,
    // Number.isFinite (not typeof==='number') so NaN/Infinity collapse to null — closes the two-preimage
    // gap where canon serialises NaN->null but a live NaN would read as "has variance" / "has value".
    value: Number.isFinite(m.value) ? m.value : null,
    // read the already-normalized `variance` first so normalize is IDEMPOTENT (pqaibom lesson: pass 1
    // derives `variance` from ci/std_dev and drops those sources; pass 2 must not recompute to null).
    variance: Number.isFinite(m.variance) ? m.variance : (Number.isFinite(m.std_dev) ? m.std_dev : (Number.isFinite(m.ci) ? m.ci : null)),
    higher_is_better: m.higher_is_better === false ? false : true, primary: !!m.primary,
    n: Number.isInteger(m.n) ? m.n : null,
    contamination: CONTAM.has(m.contamination) ? m.contamination : 'unchecked',
  });
  const metrics = (Array.isArray(r.metrics) ? r.metrics : []).filter((m) => m && typeof m.name === 'string' && m.name).map(metric);
  const safety = (Array.isArray(r.safety) ? r.safety : []).filter((x) => x && typeof x.category === 'string' && x.category)
    .map((x) => ({ category: String(x.category), tested: !!x.tested, result: x.result ?? null, n_cases: Number.isInteger(x.n_cases) ? x.n_cases : 0 }));
  const dataset_refs = (Array.isArray(r.dataset_refs) ? r.dataset_refs : []).filter((d) => d && typeof d.name === 'string')
    .map((d) => ({ name: String(d.name), hash: typeof d.hash === 'string' ? d.hash : null }));
  const methodology = {
    harness: r.methodology?.harness ?? null, harness_version: r.methodology?.harness_version ?? null,
    config_hash: r.methodology?.config_hash ?? null, seed_selection_method: r.methodology?.seed_selection_method ?? null,
  };
  // stable ordering (idempotence): metrics by name, safety by category, datasets by name
  metrics.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  safety.sort((a, b) => (a.category < b.category ? -1 : a.category > b.category ? 1 : 0));
  dataset_refs.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return {
    subject: r.subject ?? null, model_hash: typeof r.model_hash === 'string' ? r.model_hash : null,
    aibom_ref: r.aibom_ref ?? null, eval_suite: suite, methodology, metrics, safety, dataset_refs,
  };
}

/* ---------- completeness + posture (deterministic; letter CAPPED by suite/rigour) ----------
 * suiteValidated: the caller (build OR verify) resolved the declared suite against a trusted registry
 * of registered-standard batteries. If NOT validated, a registered_standard/standard_modified claim is
 * treated as custom_ad_hoc for capping (apex review: suite_type is a self-declared integer — the tier
 * must be EARNED against a registry, never trusted). A verifier that omits the registry recomputes a
 * lower posture -> postureOk mismatch -> the record cannot present an unearned registered-tier 'A'. */
export function gradeEval(norm, suiteValidated = false) {
  const suite = norm.eval_suite;
  const findings = [];
  const push = (dim, status, detail) => findings.push({ dim, status, detail });
  // a metric only COUNTS as reported if it carries a finite numeric value (apex review: value:null was
  // "complete" but reports no score — a failing benchmark could hide in plain sight).
  const reported = new Set(norm.metrics.filter((m) => Number.isFinite(m.value)).map((m) => m.name));
  // a safety category only counts as covered if it was actually TESTED with adequate power (apex review:
  // tested:false scored 'pass' and inverted the incentive — not running a test beat running it weakly).
  const coveredSafety = new Set(norm.safety.filter((x) => x.tested && x.n_cases >= MIN_SAFETY_N).map((x) => x.category));

  // 1 COMPLETENESS — every metric (with a value) + safety category (tested+powered) the suite commits to.
  const missingMetrics = suite.expected_metrics.filter((m) => !reported.has(m));
  const missingSafety = suite.expected_safety.filter((c) => !coveredSafety.has(c));
  const emptyNonCustom = suite.suite_type !== SUITE_TYPE.custom_ad_hoc && suite.expected_metrics.length === 0;
  const complete = missingMetrics.length === 0 && missingSafety.length === 0 && !emptyNonCustom;
  push('completeness', complete ? 'pass' : 'fail', complete ? 'every declared-suite metric reported with a value + safety category tested & powered'
    : emptyNonCustom ? 'a non-custom suite declares NO expected metrics (vacuous)' : 'MISSING/unreported from the committed suite: ' + [...missingMetrics, ...missingSafety].join(', '));

  // 2 STATISTICAL RIGOUR — variance present; primary metrics on a held-out split; swept seeds need aggregate.
  const noVariance = norm.metrics.some((m) => m.variance == null);
  const primaryOffTest = norm.metrics.some((m) => m.primary && !(m.split && HELD_OUT.has(m.split)));
  const sweptNoAgg = /swept|multi|best/i.test(String(norm.methodology.seed_selection_method || '')) && noVariance;
  push('rigour', (noVariance || primaryOffTest || sweptNoAgg) ? 'fail' : 'pass',
    sweptNoAgg ? 'a SWEPT/best-of-seed run reports no aggregate variance (seed cherry-picking)' : noVariance ? 'a metric reports no variance (ci/std_dev) — statistically unverified' : primaryOffTest ? 'a PRIMARY metric is not on a held-out/test split' : 'variance reported + primary metrics on held-out splits');

  // 3 CONTAMINATION — WORST status across metrics; EVERY whitelisted enum maps to a defined severity.
  const contamRank = { checked_contaminated: 3, partial: 2, unchecked: 1, checked_clean: 0 };
  const worstContam = norm.metrics.reduce((w, m) => Math.max(w, contamRank[m.contamination] ?? 1), 0);
  push('contamination', worstContam >= 3 ? 'fail' : worstContam >= 1 ? 'partial' : 'pass',
    worstContam >= 3 ? 'a metric is on a CONTAMINATED dataset (train/test leak)' : worstContam === 2 ? 'a metric discloses PARTIAL contamination — potential leak' : worstContam === 1 ? 'contamination UNCHECKED for a metric — potential leak' : 'contamination checked clean');

  // 4 SAFETY POWER — a declared safety category must be tested with adequate power (tested:false FAILS).
  const badSafety = norm.safety.some((x) => !x.tested || x.n_cases < MIN_SAFETY_N);
  push('safety_power', norm.safety.length === 0 ? 'na' : badSafety ? 'fail' : 'pass',
    badSafety ? 'a declared safety category is untested or under-powered (n_cases < ' + MIN_SAFETY_N + ')' : 'safety categories tested & adequately sampled');

  // 5 ARTIFACT BINDING — the exact model evaluated is pinned
  const bound = isHex(norm.model_hash, 32) || isHex(norm.model_hash, 64);
  push('binding', bound ? 'pass' : 'fail', bound ? 'model_hash pins the evaluated artifact' : 'no model_hash — the evaluated artifact is not pinned');

  const weight = { pass: 1, partial: 0.5, fail: 0 };
  const graded = findings.filter((f) => f.status !== 'na');
  const raw = graded.length ? graded.reduce((s, f) => s + weight[f.status], 0) / graded.length : 0;
  let uncapped = !complete ? 'F' : raw >= 0.9 ? 'A' : raw >= 0.75 ? 'B' : raw >= 0.6 ? 'C' : raw >= 0.4 ? 'D' : 'F';
  const st = (dim) => { const f = findings.find((x) => x.dim === dim); return f ? f.status : 'na'; };
  // EFFECTIVE suite type: an unvalidated registered/modified claim is treated as custom for capping.
  const effType = suiteValidated ? suite.suite_type : SUITE_TYPE.custom_ad_hoc;
  let letter = capLetter(uncapped, SUITE_TYPE_CAP[effType]);                                          // (1) suite provenance
  if (st('rigour') === 'fail') letter = capLetter(letter, (primaryOffTest || sweptNoAgg) ? 'C' : 'B'); // (2) no-variance->B, off-test/swept->C
  if (st('contamination') === 'partial') letter = capLetter(letter, 'C');                             // (3) unchecked/partial contamination
  if (st('contamination') === 'fail') letter = capLetter(letter, 'D');                                // contaminated
  if (st('safety_power') === 'fail') letter = capLetter(letter, 'C');                                 // (4) untested/under-powered safety
  if (st('binding') === 'fail') letter = capLetter(letter, 'C');                                      // (5) no model_hash
  return { letter, uncapped_letter: uncapped, score: Math.round(raw * 100), complete,
    suite_type: suite.suite_type, effective_suite_type: effType, suite_validated: suiteValidated, suite_type_name: SUITE_TYPE_NAME[effType],
    label: letter + ' (' + SUITE_TYPE_NAME[effType] + (suiteValidated || suite.suite_type === SUITE_TYPE.custom_ad_hoc ? '' : ', unverified') + ')', findings, capped: letter !== uncapped };
}

/* ---------- build / sign / anchor / verify ---------- */
// opts.suiteRegistry (Set|array of accepted suite_hashes) — the registered/modified tier is only
// EARNED against it. Without it, a registered-tier claim grades as custom (capped C).
export function buildEval(rec, opts = {}) {
  const norm = normalizeEval(rec);
  const posture = gradeEval(norm, isSuiteValidated(norm.eval_suite, opts.suiteRegistry));
  return {
    v: V, claim_scope: 'self-attested-evaluation', ...norm,
    ts: Number.isFinite(opts.ts) ? opts.ts : null, declarant: opts.declarant ?? null,
    posture: posturePublic(posture), regulatory: REGULATORY,
  };
}
export function signEval(rec, signers) {
  if (!rec || rec.v !== V) throw new Error('not a pqeval-1 object');
  return { rec, envelope: seal(utf8ToBytes(canon(rec)), signers) };
}
export function appendEval(log, signed) { return log.append({ kind: 'pqeval-anchor', rec: signed.rec, envelope: signed.envelope }); }

/** verifyEval({rec, envelope}, opts) — TOTAL/fail-closed. Re-normalizes + fixpoint-checks, recomputes
 * the suite_hash + full posture, verifies the seal (pin declarant via opts.sealOpts.trusted — else
 * fail closed); optional RFC-6962 inclusion; optional aibom_ref cross-binding to a signed AIBOM. */
export function verifyEval({ rec, envelope } = {}, opts = {}) {
  const FAIL = (why) => ({ verified: false, why, sealOk: false, normOk: false, suiteOk: false, postureOk: false, regulatoryOk: false, scopeOk: false, suiteValidated: false, runnerAnchored: false, anchorOk: null });
  try {
    if (!rec || rec.v !== V || !envelope) return FAIL('malformed input');
    const sealOpts = opts.sealOpts || {};
    const hasPin = sealOpts.trusted && typeof sealOpts.trusted === 'object' && Object.keys(sealOpts.trusted).length > 0;
    if (!hasPin && !opts.allowUnpinnedSeal) return FAIL('sealOpts.trusted (declarant pubkey pins) required, or set allowUnpinnedSeal:true');
    const scopeOk = rec.claim_scope === 'self-attested-evaluation';
    if (!scopeOk) return FAIL('missing/invalid claim_scope');
    // re-normalize + FIXPOINT (pqaibom lesson): the signed body must already be normalized, else a
    // hand-crafted record could bypass the whitelist/defaults/ordering the posture recompute relies on.
    const { v, claim_scope, ts, declarant, posture, regulatory, ...body } = rec;
    const norm = normalizeEval(body);
    if (canon(norm) !== canon(body)) return { ...FAIL('record body not normalized — hand-crafted record rejected'), scopeOk };
    // suite_hash must recompute (the vendor cannot shrink the committed suite after the fact)
    const suiteOk = rec.eval_suite && rec.eval_suite.suite_hash === suiteHash(rec.eval_suite);
    // re-validate the suite tier against the verifier's OWN registry — a self-declared registered_standard
    // is only honored if THIS verifier recognises it; else the posture recomputes lower and mismatches.
    const suiteValidated = isSuiteValidated(rec.eval_suite, opts.suiteRegistry);
    const g = gradeEval(norm, suiteValidated);
    // compare the WHOLE posture object (not a 6-key subset) + re-derive regulatory — closes the carve-out
    // where an injected posture.certified / regulatory 'FedRAMP authorized' rode through under signature.
    const postureOk = !!(rec.posture && canon(rec.posture) === canon(posturePublic(g)));
    const regulatoryOk = canon(rec.regulatory ?? null) === canon(REGULATORY);
    const sealRes = openSeal(utf8ToBytes(canon(rec)), envelope, sealOpts);
    const sealOk = !!sealRes.verified;
    const base = { sealOk, normOk: true, suiteOk: !!suiteOk, postureOk, regulatoryOk, scopeOk, suiteValidated, runnerAnchored: !!sealRes.fullyAnchored };
    if (!sealOk) return { verified: false, why: 'seal failed', ...base, anchorOk: null };
    if (!suiteOk) return { verified: false, why: 'suite_hash does not recompute (suite committed-set changed)', ...base, anchorOk: null };
    if (!postureOk) return { verified: false, why: 'posture does not reproduce from the record (or a registered-tier claim this verifier cannot validate)', ...base, anchorOk: null };
    if (!regulatoryOk) return { verified: false, why: 'regulatory block does not match the canonical text (injection)', ...base, anchorOk: null };
    let anchorOk = null;
    if (opts.logView) {
      const { entry, inclusion, sth, logPub } = opts.logView;
      anchorOk = false;
      if (entry && entry.kind === 'pqeval-anchor' && entry.rec && canon(entry.rec) === canon(rec) && inclusion && sth) {
        const leaf = entryLeafHash(entry);
        anchorOk = verifySTH(sth, logPub) && bytesToHex(leaf) === bytesToHex(inclusion.leaf) && inclusion.tree_size === sth.tree_size
          && verifyInclusionRFC(leaf, inclusion.index, sth.tree_size, (inclusion.proof || []).map((p) => p.sibling), hexToBytes(sth.root_hex));
      }
      if (!anchorOk) return { verified: false, why: 'log anchor failed', ...base, anchorOk };
    }
    // optional composition: the eval's model_hash must match the referenced AIBOM's model
    let aibomBound = null;
    if (opts.aibom) {
      const models = (opts.aibom.components || []).filter((c) => c.type === 'model');
      // require a REAL model_hash before matching — else null===null would "bind" any AIBOM with an
      // unpinned model (apex review: vacuous model-identity anchor).
      const pinned = isHex(rec.model_hash, 32) || isHex(rec.model_hash, 64);
      aibomBound = !!(rec.aibom_ref && opts.aibom.runtime_binding === rec.aibom_ref && pinned && models.some((m) => m.weights_sha256 === rec.model_hash));
      if (!aibomBound) return { verified: false, why: 'aibom_ref / model_hash does not bind the referenced AIBOM', ...base, anchorOk, aibomBound };
    }
    return { verified: true, why: null, ...base, anchorOk, aibomBound, posture: g.label, postureDetail: { letter: g.letter, score: g.score, suite_type_name: SUITE_TYPE_NAME[g.suite_type], findings: g.findings } };
  } catch { return FAIL('exception (fail-closed)'); }
}

/* ---------- self-test: node pqeval.mjs ---------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const A = (() => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(51)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; })();
  const C = (() => { const sk = new Uint8Array(32).fill(53); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })();
  const signers = [A, C];
  const sealOpts = { requireKinds: ['lattice', 'classical'], trusted: { 'ML-DSA-87': A.publicKey, 'Ed25519': C.publicKey } };
  const H = 'a'.repeat(64);

  // a rigorous, REGISTERED-STANDARD, complete, clean eval -> can reach A
  const strong = {
    subject: 'acme-llm@1.0', model_hash: H, aibom_ref: null,
    eval_suite: { name: 'HELM-lite', version: '1.0', suite_type: SUITE_TYPE.registered_standard, registry_ref: 'https://crfm.stanford.edu/helm', expected_metrics: ['mmlu', 'gsm8k'], expected_safety: ['jailbreak'] },
    methodology: { harness: 'lm-eval-harness', harness_version: '0.4', config_hash: 'cfg', seed_selection_method: 'fixed_standard' },
    metrics: [
      { name: 'mmlu', split: 'test', value: 0.71, ci: 0.01, primary: true, n: 14000, contamination: 'checked_clean' },
      { name: 'gsm8k', split: 'test', value: 0.62, std_dev: 0.02, primary: true, n: 1300, contamination: 'checked_clean' },
    ],
    safety: [{ category: 'jailbreak', tested: true, result: 'pass', n_cases: 200 }],
    dataset_refs: [{ name: 'mmlu', hash: H }],
  };
  // the verifier's trusted registry of registered-standard suites (a Set of accepted suite_hashes)
  const registry = new Set([suiteHash(normalizeEval(strong).eval_suite)]);
  const reg = { ts: 1, suiteRegistry: registry };   // build-opts that earn the registered tier

  // 1. registered tier is EARNED against the registry: A only WITH the registry (build + verify)
  const e = buildEval(strong, { ts: 1000, declarant: 'Acme Inc', suiteRegistry: registry });
  ok(e.posture.letter === 'A' && /registered_standard/.test(e.posture.label) && e.posture.suite_validated === true, 'registry-validated registered-standard eval -> "A (registered_standard)"');
  const signed = signEval(e, signers);
  ok(verifyEval(signed, { sealOpts, suiteRegistry: registry }).verified === true, 'signed eval verifies WITH the registry (suite tier re-validated)');
  // THE KILLER, now CAPPED not just attributable: the SAME record to a verifier WITHOUT the registry
  // recomputes as custom_ad_hoc -> posture mismatch -> NOT an 'A'.
  const vNoReg = verifyEval(signed, { sealOpts });
  ok(vNoReg.verified === false && vNoReg.suiteValidated === false, 'a registered-tier A does NOT verify for a verifier that cannot validate the suite (posture recomputes to custom C)');
  // and building the same favourable subset WITHOUT registry backing grades C (custom, unverified)
  ok(LETTERS.indexOf(buildEval(strong, { ts: 1 }).posture.letter) >= LETTERS.indexOf('C'), 'a self-declared registered_standard with no registry match -> capped C (custom_ad_hoc, unverified)');

  // 2. gaming caps (built WITH registry so the base is A and the SPECIFIC vector shows its cap)
  const cap = (mut, m) => { const r = JSON.parse(JSON.stringify(strong)); mut(r); return LETTERS.indexOf(buildEval(r, reg).posture.letter); };
  ok(cap((r) => { r.metrics[0].contamination = 'unchecked'; }) >= LETTERS.indexOf('C'), 'contamination unchecked -> C');
  ok(cap((r) => { r.metrics[0].contamination = 'partial'; }) >= LETTERS.indexOf('C'), 'contamination PARTIAL (was whitelisted-but-unhandled) -> C');
  ok(cap((r) => { r.metrics[0].contamination = 'checked_contaminated'; }) >= LETTERS.indexOf('D'), 'contamination contaminated -> D');
  ok(cap((r) => { delete r.metrics[0].ci; }) >= LETTERS.indexOf('B'), 'a metric with no variance -> B');
  ok(cap((r) => { r.metrics[0].ci = NaN; }) >= LETTERS.indexOf('B'), 'a NaN variance -> B (Number.isFinite; two-preimage gap closed)');
  ok(cap((r) => { r.metrics[0].split = 'validation'; }) >= LETTERS.indexOf('C'), 'a PRIMARY metric on a validation split -> C');
  ok(cap((r) => { r.methodology.seed_selection_method = 'swept_best'; delete r.metrics[0].ci; }) >= LETTERS.indexOf('C'), 'a swept/best-of-seed run with no aggregate variance -> C');
  ok(cap((r) => { r.model_hash = null; }) >= LETTERS.indexOf('C'), 'no model_hash (unpinned artifact) -> C');
  ok(cap((r) => { r.metrics[1].value = null; }) === LETTERS.indexOf('F'), 'a committed metric reported with value:null (no score) -> incomplete -> F');
  ok(cap((r) => { r.safety[0].tested = false; }) >= LETTERS.indexOf('C'), 'a declared safety category tested:false (not run) -> C (cannot lift the grade by not testing)');
  ok(cap((r) => { r.safety[0].n_cases = 1; }) >= LETTERS.indexOf('C'), 'a safety category tested with n_cases=1 -> C');
  // every contamination enum maps to a defined cap (root-cause guard for whitelisted-but-unhandled)
  ok([...CONTAM].every((c) => { const r = JSON.parse(JSON.stringify(strong)); r.metrics[0].contamination = c; const st = buildEval(r, reg).posture.findings.find((f) => f.dim === 'contamination').status; return ['pass', 'partial', 'fail'].includes(st); }), 'EVERY contamination enum maps to a defined grade status (no silent pass)');

  // 3. INJECTION into the carved-out objects -> verify REJECTS (posture + regulatory now full-compared)
  const inj = JSON.parse(JSON.stringify(e)); inj.posture.certified = true;
  ok(verifyEval(signEval(inj, signers), { sealOpts, suiteRegistry: registry }).verified === false, 'injected posture.certified:true -> REJECTED (whole-posture canon compare)');
  const injReg = JSON.parse(JSON.stringify(e)); injReg.regulatory = { note: 'Independently verified capability.', supports: ['FedRAMP authorized'] };
  ok(verifyEval(signEval(injReg, signers), { sealOpts, suiteRegistry: registry }).regulatoryOk === false, 'injected regulatory "FedRAMP authorized" -> REJECTED (regulatory re-derived)');

  // 4. forged posture / suite shrink / hand-crafted / attacker-key / fail-closed
  const forged = JSON.parse(JSON.stringify(e)); forged.posture.letter = 'A'; forged.posture.label = 'A (custom_ad_hoc)';
  ok(verifyEval(signEval(forged, signers), { sealOpts, suiteRegistry: registry }).verified === false, 'forged posture -> REJECTED (posture recompute)');
  const shrink = JSON.parse(JSON.stringify(e)); shrink.eval_suite.expected_metrics = ['mmlu'];
  ok(verifyEval(signEval(shrink, signers), { sealOpts, suiteRegistry: registry }).verified === false, 'shrinking the committed suite (suite_hash stale) -> REJECTED');
  const hand = JSON.parse(JSON.stringify(e)); hand.metrics.push({ name: 'zzz', bogus: 'x' });
  ok(verifyEval(signEval(hand, signers), { sealOpts, suiteRegistry: registry }).verified === false, 'hand-crafted un-normalized record -> REJECTED (fixpoint)');
  const atk = [(() => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(200)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; })(), (() => { const sk = new Uint8Array(32).fill(201); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })()];
  ok(verifyEval(signEval(e, atk), { sealOpts, suiteRegistry: registry }).verified === false, 'attacker-key seal -> REJECTED under declarant pins');
  ok(verifyEval(signed, { suiteRegistry: registry }).verified === false, 'unpinned verify FAILS CLOSED');

  // 5. determinism + idempotence + anchor
  ok(canon(buildEval(strong, { ts: 1000, declarant: 'Acme Inc', suiteRegistry: registry })) === canon(e), 'eval build is deterministic');
  const n1 = normalizeEval(strong); ok(canon(n1) === canon(normalizeEval(n1)), 'normalizeEval is IDEMPOTENT (verify-fixpoint safety invariant)');
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(9));
  const log = new PQTransparencyLog(); const idx = appendEval(log, signed);
  const sth = log.signedTreeHead(logKey.secretKey, { ts: 5000 });
  ok(verifyEval(signed, { sealOpts, suiteRegistry: registry, logView: { entry: log.entries[idx], inclusion: log.inclusion(idx), sth, logPub: logKey.publicKey } }).verified === true, 'anchored eval verifies incl. RFC-6962 inclusion');

  console.log('pqeval self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqeval\.mjs$/.test(process.argv[1] || '')) selfTest();
