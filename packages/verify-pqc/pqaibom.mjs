/*!
 * pqaibom — verifiable AI BILL OF MATERIALS (ML-BOM) + AI DECLARATION ASSURANCE grade (reference, DRAFT).
 *
 * The static-component complement to pqtrace's runtime provenance: pqaibom = "what went INTO the AI
 * system" (models, datasets, adapters, prompts, tools, merge/quantization/alignment lineage);
 * pqtrace = "what it DID at runtime". Emits a CycloneDX 1.6 ML-BOM + a signed, optionally
 * transparency-anchored declaration, mirroring pqcbom's free-badge -> paid-evidence funnel for the
 * AI supply chain.
 *
 * CLAIM-HYGIENE — READ FIRST (council design + apex-team review, 10-11 Jul 2026): this attests a
 * DECLARED manifest. The pqseal signature proves WHO made the claim, NOT that the claim is TRUE — a
 * signed AIBOM can be a "signed lie". Structural defenses that make the artifact honest about that:
 *   (1) ASSURANCE LEVEL (first-class, signed): L0 'declared' (self-attested, no hash check) | L1
 *       'bound' (every DECLARED component hash checked against local bytes — EARNED via bindManifest();
 *       components that declare no hash are NOT covered and remain L0-quality inside an L1 BOM) | L2
 *       'reproduced' (independently downloaded + hashed). The grade ALWAYS renders as "Letter (Level)".
 *       WITHOUT bindManifest(), the level is a CALLER ASSERTION and the signature binds only WHO
 *       asserted it — bindManifest() is the honest path to L1.
 *   (2) The letter is CAPPED by the level: an L0 declaration can NEVER exceed 'B'. So "A" structurally
 *       implies a DECLARED assurance level of at least L1 (machine-checked: formal/pqaibom_grade_cap_
 *       z3.py). Whether that L1 was EARNED (hashes actually checked) rests on the declarant having used
 *       bindManifest — the cap makes the overclaim impossible to GRADE, not impossible to ASSERT.
 *   (3) `claim_scope: 'self-attested-declaration'` is a mandatory signed field verifyAibom refuses
 *       without; verifyAibom RE-NORMALIZES + fixpoint-checks the components (a hand-crafted BOM is
 *       rejected) and recomputes the FULL grade; the grade EXCLUDES vacuous (no-applicable-component)
 *       dimensions — an empty or AI-component-free BOM grades 'F', never a vacuous 'A'; a mislabeled
 *       model is flagged; a model with no TRAINING dataset (eval_set/test do not count) caps at 'C'.
 * It is "AI DECLARATION ASSURANCE", never "AI Trust Posture". SUPPORTS (never certifies) evidence-
 * gathering for EU AI Act Annex IV (inventory + data-provenance subset), NIST AI RMF (MAP-2), the
 * NTIA SBOM minimum elements + CISA SBOM/AIBOM guidance, OMB M-25-21/22 (2025 successors to the
 * rescinded M-24-10), ISO/IEC 42001 Annex A. FIPS 203/204/205 final; FIPS 206 draft.
 *
 * BOM-REALITY DRIFT (the pqtrace bridge): runtimeBindingHash(bom) binds the FULL normalized component
 * set; a deployer passes the components an HONEST, INDEPENDENT observer reports as loaded (it does not
 * itself read bytes) and checkBomRealityDrift flags any mismatch — including a dropped sandbox / enabled
 * egress / swapped licence or consent, not only an identity/hash change. The check is as trustworthy as
 * the observation, and components declaring no hash (`unpinned`) are matched by declared fields only, so
 * a byte-level swap of a same-name/attributes hashless artifact is NOT drift-covered. The static BOM is
 * only honest if the runtime independently enforces it.
 *  Self-test: node pqaibom.mjs
 */
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { seal, openSeal } from './pqseal.mjs';
import { PQTransparencyLog, verifySTH, entryLeafHash, verifyInclusionRFC } from './pqsign.mjs';

const V = 'pqaibom-1';
const CDX_SPEC = '1.6';
export const ASSURANCE = { declared: 0, bound: 1, reproduced: 2 };
const ASSURANCE_NAME = ['Declared', 'Bound', 'Reproduced'];
const LEVEL_LETTER_CAP = ['B', 'A', 'A'];                // L0 declarations cannot reach 'A' (anti-overclaim)
const LETTERS = ['A', 'B', 'C', 'D', 'F'];               // best -> worst; index 0 = best
const COMPONENT_TYPES = new Set(['model', 'dataset', 'adapter', 'prompt', 'tool', 'library', 'vector_store', 'guardrail', 'eval_set']);
const CONSENT = new Set(['opt-in', 'opt-out', 'public-domain', 'synthetic', 'licensed', 'contractual']);   // 'unknown' is NOT a pass
const DATA_CLASS = new Set(['public', 'internal', 'confidential', 'pii', 'sensitive-pii']);                // 'unknown' is NOT a pass
const MODEL_ONLY_FIELDS = ['weights_sha256', 'base_model', 'parent_models', 'merge_method'];   // unambiguous model-defining fields (narrowed to cut mislabel false-positives — Qwen seat)

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const hashHex = (bytes) => bytesToHex(sha512(bytes instanceof Uint8Array ? bytes : utf8ToBytes(String(bytes))));
const isHex = (s, bytes) => typeof s === 'string' && new RegExp('^[0-9a-fA-F]{' + bytes * 2 + '}$').test(s);
const anyHex = (s) => isHex(s, 32) || isHex(s, 48) || isHex(s, 64);   // sha256 / sha384 / sha512
const capLetter = (letter, cap) => (LETTERS.indexOf(letter) >= LETTERS.indexOf(cap) ? letter : cap);   // worse-or-equal wins

// restrictive/review-needed licences (leads, not a legal ruling). Extended (apex review): use-restricted
// AI licences (OpenRAIL/RAIL/*-community/acceptable-use/academic) + spaced/spelled forms.
const NONCOMMERCIAL = /(-NC\b|non[\s-]?commercial|cc-by-nc|research[\s-]?only|proprietary|evaluation[\s-]?only|open[\s-]?rail|\brail\b|community[\s-]licen[sc]e|acceptable[\s-]use|academic[\s-]use)/i;
// copyleft incl. v-suffix (GPLv3/AGPLv3/LGPLv2.1) and spelled-out GPL family. Tightened (fix-verification
// round): dropped bare `gnu\s`/`affero` — they over-matched permissive GNU licences (e.g. "GNU
// All-Permissive"); only the GPL abbreviations + the spelled-out "(Lesser/Affero) General Public License".
const COPYLEFT = /((^|[^a-z])(a?gpl|lgpl|sspl|osl|epl|mpl|cddl|eupl)(v?\s?\d|[-\s]|$)|(lesser |affero )?general public licen[sc]e)/i;
const UNKNOWN_LICENSE = (l) => { const s = String(l ?? '').trim(); return !s || /^(unknown|none|n\/?a|tbd|\?|null)$/i.test(s); };  // post-trim-empty (incl. ' ') = unknown
const primaryHash = (c) => c.weights_sha256 || c.hash || c.corpus_hash || c.schema_hash || c.manifest_hash || null;
const bomRefOf = (c) => c.type + '/' + c.name + '@' + (c.version ?? '');

/* ---------- normalize a declared manifest into typed components (+ mislabel detection) ---------- */
export function normalizeComponents(manifest) {
  const raw = Array.isArray(manifest) ? manifest : (manifest && Array.isArray(manifest.components) ? manifest.components : []);
  const out = [];
  for (const c of raw) {
    if (!c || !COMPONENT_TYPES.has(c.type) || typeof c.name !== 'string' || !c.name) continue;
    // MISLABEL: a non-model/adapter component carrying model-only fields is a suspected mislabeled model.
    // PRESERVE a prior flag (c.mislabel===true) so normalize is IDEMPOTENT (fix-verification round): pass 1
    // sets the flag AND strips the model-only fields, so pass 2 could not re-detect it — without this an
    // honestly-built BOM with a flagged component would fail its own verify fixpoint. Setting mislabel
    // only ever LOWERS the grade, so preserving a caller-supplied flag cannot be abused.
    const mislabel = c.mislabel === true || ((c.type !== 'model' && c.type !== 'adapter') && MODEL_ONLY_FIELDS.some((f) => c[f] !== undefined && c[f] !== null));
    const base = { type: c.type, name: c.name, version: c.version ?? null, license: c.license ?? null };
    if (mislabel) base.mislabel = true;
    if (c.type === 'model') {
      out.push({ ...base, weights_sha256: c.weights_sha256 ?? null, source_url: c.source_url ?? null, provider: c.provider ?? null,
        task: c.task ?? null, base_model: c.base_model ?? null, parent_models: Array.isArray(c.parent_models) ? c.parent_models.slice(0, 32) : null,
        merge_method: c.merge_method ?? null, quantization: c.quantization ?? null, alignment: c.alignment ?? null,
        hyperparameters: c.hyperparameters ?? null, training_compute: c.training_compute ?? null, energy: c.energy ?? null,
        modality: c.modality ?? null, model_card_url: c.model_card_url ?? null, params: c.params ?? null });
    } else if (c.type === 'dataset' || c.type === 'eval_set') {
      out.push({ ...base, hash: c.hash ?? null, source: c.source ?? null, provenance: c.provenance ?? null, split: c.split ?? null,
        data_classification: c.data_classification ?? null, consent_mechanism: c.consent_mechanism ?? null,
        acquisition_method: c.acquisition_method ?? null, collection_period: c.collection_period ?? null });
    } else if (c.type === 'adapter') {
      out.push({ ...base, hash: c.hash ?? null, base_model: c.base_model ?? null });
    } else if (c.type === 'prompt') {
      out.push({ ...base, hash: c.hash ?? null, role: c.role ?? null });
    } else if (c.type === 'tool') {
      out.push({ ...base, schema_hash: c.schema_hash ?? null, side_effects: !!c.side_effects, network_egress: !!c.network_egress,
        sandboxed: c.sandboxed ?? null, auth_required: c.auth_required ?? null, source_uri: c.source_uri ?? null, manifest_hash: c.manifest_hash ?? null });
    } else if (c.type === 'vector_store') {
      out.push({ ...base, embedding_model: c.embedding_model ?? null, corpus_hash: c.corpus_hash ?? null });
    } else if (c.type === 'guardrail') {
      out.push({ ...base, policy_id: c.policy_id ?? null, hash: c.hash ?? null });
    } else { // library
      out.push({ ...base, hash: c.hash ?? null });   // libraries may carry a hash so a swap is drift-detectable
    }
  }
  // DEDUPE EXACT duplicates only (canon of the whole component) — duplicate-padding cannot dilute
  // fractional grade dimensions (apex review #5), while two legitimately-DISTINCT components sharing a
  // name/version but differing in split/hash/attributes are PRESERVED (fix-verification round — dedup by
  // identity-tuple wrongly merged same-name train/test splits).
  const seen = new Set();
  return out.filter((c) => { const k = canon(c); if (seen.has(k)) return false; seen.add(k); return true; });
}

/* ---------- EARN assurance L1: hash-bind declared components against real bytes ----------
 * resolve(component) -> Uint8Array | null (the actual bytes for the component's primary artifact).
 * Returns the level ACTUALLY earned (bound iff every declared hash was resolved AND matched), so a
 * caller cannot claim L1 without the module having checked. Model weights use SHA-256 (weights_sha256);
 * other components' `hash` alg is taken from the declared hex length (32B sha256 / 64B sha512). */
export function bindManifest(manifest, resolve) {
  const comps = normalizeComponents(manifest);
  let declaredHashes = 0, checked = 0; const mismatches = [];
  for (const c of comps) {
    const declared = primaryHash(c);
    if (!declared) continue;
    declaredHashes++;
    let bytes = null; try { bytes = resolve(c); } catch { bytes = null; }
    if (!(bytes instanceof Uint8Array)) continue;
    checked++;
    const alg = (c.type === 'model' || isHex(declared, 32)) ? sha256 : (isHex(declared, 64) ? sha512 : sha256);
    if (bytesToHex(alg(bytes)).toLowerCase() !== String(declared).toLowerCase()) mismatches.push({ name: c.name, declared });
  }
  const allChecked = declaredHashes > 0 && checked === declaredHashes && mismatches.length === 0;
  return { manifest, level: allChecked ? ASSURANCE.bound : ASSURANCE.declared, declaredHashes, checked, mismatches, allChecked };
}

/* ---------- the grade (deterministic; vacuous dims EXCLUDED; letter CAPPED by assurance level) ---------- */
export function gradeAibom(components, assuranceLevel = ASSURANCE.declared) {
  const level = Number.isInteger(assuranceLevel) && assuranceLevel >= 0 && assuranceLevel <= 2 ? assuranceLevel : 0;
  const models = components.filter((c) => c.type === 'model');
  const dsets = components.filter((c) => c.type === 'dataset' || c.type === 'eval_set');
  const tools = components.filter((c) => c.type === 'tool');
  // fraction over a population; returns null when the population is empty (dimension is N/A — EXCLUDED,
  // never counted as a vacuous pass — the apex-team "empty BOM grades A" fix).
  const frac = (arr, pred) => (arr.length ? arr.filter(pred).length / arr.length : null);
  const score3 = (f) => (f === null ? 'na' : f >= 0.999 ? 'pass' : f >= 0.5 ? 'partial' : 'fail');   // partial needs a MAJORITY
  const avgFrac = (...fs) => { const v = fs.filter((f) => f !== null); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null; };

  const findings = [];
  const push = (dim, status, detail) => findings.push({ dim, status, detail });

  // 1 integrity — model weights + dataset hashes pinned
  push('integrity', score3(avgFrac(frac(models, (m) => isHex(m.weights_sha256, 32)), frac(dsets, (d) => anyHex(d.hash)))), 'model weights + dataset hashes pinned');
  // 2 provenance — source + provider present; and MERGED models must declare their parent lineage.
  //   (No tautology: 'lineage' population is only the merged models; foundation models are N/A.)
  push('provenance', score3(frac(models, (m) => !!(m.source_url && m.provider))), 'source + provider declared');
  // lineage population = ANY derived model (base_model, parent_models, OR merge_method), so a merge cannot
  // dodge by omitting merge_method while declaring parents. NO TAUTOLOGY (apex review): a base/parent
  // reference only PASSES if it is INTERNALLY CONSISTENT — the named base/parents are themselves declared
  // as model/adapter components — so a fabricated one-word base_model no longer buys a free-pass dimension.
  const declaredNames = new Set(components.filter((c) => c.type === 'model' || c.type === 'adapter').map((c) => c.name));
  const parentsOf = (m) => (Array.isArray(m.parent_models) ? m.parent_models : []).concat(m.base_model ? [m.base_model] : []);
  const derived = models.filter((m) => m.base_model || (Array.isArray(m.parent_models) && m.parent_models.length) || m.merge_method);
  push('lineage', score3(frac(derived, (m) => { const ps = parentsOf(m); return ps.length > 0 && ps.every((p) => declaredNames.has(String(p))); })), 'derived/merged models declare lineage that resolves to declared components');
  // 3 licensing — present + not unknown; restrictive flagged (caps, see below)
  const licKnown = frac(components, (c) => !UNKNOWN_LICENSE(c.license));
  const anyRestrictive = components.some((c) => c.license && (NONCOMMERCIAL.test(c.license) || COPYLEFT.test(c.license)));
  push('licensing', licKnown === null ? 'na' : (licKnown >= 0.999 ? (anyRestrictive ? 'partial' : 'pass') : score3(licKnown)), anyRestrictive ? 'restrictive/non-commercial licence present — review' : 'licences declared');
  // 4 known-risk — unlicensed+unprovenanced model, OR an egress tool NOT affirmatively sandboxed (fail-CLOSED)
  const riskyModel = models.some((m) => UNKNOWN_LICENSE(m.license) && !m.provider);
  const riskyTool = tools.some((t) => t.network_egress && t.sandboxed !== true);          // omitting sandboxed no longer dodges
  const mislabeled = components.some((c) => c.mislabel);
  push('known_risk', (components.length === 0) ? 'na' : (riskyModel || riskyTool || mislabeled) ? 'fail' : 'pass',
    mislabeled ? 'suspected MISLABELED model (model-only fields on a non-model component)' : riskyModel ? 'model with no licence and no provider' : riskyTool ? 'tool with network egress not affirmatively sandboxed' : 'no flagged high-risk component');
  // 5 documentation — model cards + dataset provenance
  push('documentation', score3(avgFrac(frac(models, (m) => !!m.model_card_url), frac(dsets, (d) => !!d.provenance))), 'model cards + dataset provenance');
  // 6 data-governance — datasets carry a DEFINITE classification + consent (unknown is NOT a pass).
  //   COMPLETENESS FLOOR (both council seats, CRITICAL): a BOM declaring a model but ZERO datasets is
  //   HIDING its training data — the highest-governance-risk element — not "nothing to govern". Force
  //   FAIL (never N/A) + cap the letter (below), closing the "declare no dataset to dodge governance and
  //   reach A" exploit AND the avgFrac null-drop that would otherwise inflate integrity/documentation.
  //   TRAINING-DATA floor (apex review — closes the "eval_set / test-split satisfies the floor" dodge):
  //   the floor is satisfied only by a TRAINING dataset (type 'dataset' whose split is train/pretraining/
  //   fine-tune, or unspecified = treated as training). An eval_set or a test/validation split does NOT
  //   count — declaring a token eval set no longer hides the actual training corpus.
  const TRAIN_SPLIT = /^(train|pre-?train(ing)?|fine[\s-]?tune|sft|rlhf|dpo|instruct)/i;
  // satisfied by a TRAINING dataset (train/fine-tune split, or unspecified) OR a vector_store corpus —
  // so a RAG / retrieval / inference-only system (which has a knowledge corpus, not a training set) is
  // not wrongly failed (fix-verification round). An eval_set or a test/validation split still does NOT
  // satisfy it (that was the dodge). A system declaring a model but NO data of either kind caps at C.
  const hasData = components.some((c) => (c.type === 'dataset' && (c.split == null || TRAIN_SPLIT.test(String(c.split)))) || c.type === 'vector_store');
  const hasModelsNoData = models.length > 0 && !hasData;
  push('data_governance', hasModelsNoData ? 'fail'
    : score3(avgFrac(frac(dsets, (d) => DATA_CLASS.has(d.data_classification)), frac(dsets, (d) => CONSENT.has(d.consent_mechanism)))),
    hasModelsNoData ? 'model(s) declared but NO training dataset or retrieval corpus — data provenance undocumented' : 'definite data classification + consent basis');

  const weight = { pass: 1, partial: 0.5, fail: 0 };
  const graded = findings.filter((f) => f.status !== 'na');                                // vacuous dims excluded
  const hasAiCore = models.length > 0 || dsets.length > 0;                                  // an AIBOM must declare a model or dataset
  const raw = graded.length ? graded.reduce((s, f) => s + weight[f.status], 0) / graded.length : 0;
  // no AI-core component (empty / library-only) => 'F': there is nothing AI-substantive to assure (no vacuous pass).
  const uncapped = (!hasAiCore || graded.length === 0) ? 'F' : raw >= 0.9 ? 'A' : raw >= 0.75 ? 'B' : raw >= 0.6 ? 'C' : raw >= 0.4 ? 'D' : 'F';
  const st = (dim) => { const f = findings.find((x) => x.dim === dim); return f ? f.status : 'na'; };
  let letter = capLetter(uncapped, LEVEL_LETTER_CAP[level]);                               // (1) assurance-level cap
  if (anyRestrictive) letter = capLetter(letter, 'B');                                     // (2) clean-licence cap
  if (mislabeled) letter = capLetter(letter, 'C');                                         // (3) mislabeled-model cap
  if (st('known_risk') === 'fail') letter = capLetter(letter, 'C');                        // (4) a flagged high-risk component can't be A/B
  if (st('integrity') === 'partial' || st('integrity') === 'fail') letter = capLetter(letter, 'B');  // (5) no top grade with unhashed components
  if (hasModelsNoData) letter = capLetter(letter, 'C');                                    // (6) completeness floor — undeclared training data / retrieval corpus
  return { score: Math.round(raw * 100), letter, uncapped_letter: uncapped, level, level_name: ASSURANCE_NAME[level],
    label: letter + ' (' + ASSURANCE_NAME[level] + ')', graded_dims: graded.length, findings, capped: letter !== uncapped };
}

/* ---------- build the BOM (deterministic; caller supplies generated_ts) ---------- */
export function buildAibom(manifest, opts = {}) {
  const level = Number.isInteger(opts.assuranceLevel) ? opts.assuranceLevel : ASSURANCE.declared;
  const components = normalizeComponents(manifest);
  const grade = gradeAibom(components, level);
  const bom = {
    v: V, spec: 'CycloneDX-' + CDX_SPEC + '-mlbom',
    claim_scope: 'self-attested-declaration',
    subject: opts.subject ?? null, declarant: opts.declarant ?? null,
    assurance_level: level, assurance_name: ASSURANCE_NAME[level],
    generated_ts: Number.isFinite(opts.generated_ts) ? opts.generated_ts : null,
    components, grade: { letter: grade.letter, label: grade.label, score: grade.score, level, graded_dims: grade.graded_dims, findings: grade.findings },
    regulatory: {
      note: 'SUPPORTS evidence-gathering; does NOT certify compliance.',
      maps: ['EU AI Act Annex IV (inventory + data-provenance subset)', 'NIST AI RMF MAP-2',
        'NTIA SBOM minimum elements (2021) + CISA SBOM/AIBOM guidance', 'OMB M-25-21/M-25-22 (2025, successors to M-24-10)', 'ISO/IEC 42001 Annex A'],
    },
  };
  bom.runtime_binding = runtimeBindingHash(bom);
  return bom;
}

/* ---------- CycloneDX 1.6 ML-BOM projection (NTIA-minimum-element aware) ---------- */
const CDX_TYPE = { model: 'machine-learning-model', adapter: 'machine-learning-model', guardrail: 'machine-learning-model',
  dataset: 'data', eval_set: 'data', prompt: 'data', vector_store: 'data', tool: 'application', library: 'library' };
const bomRef = (c) => c.type + '/' + c.name + (c.version ? '@' + c.version : '');
const isSpdxId = (l) => typeof l === 'string' && !/\s/.test(l.trim()) && /^[A-Za-z0-9][A-Za-z0-9.+\-]*$/.test(l.trim());
const licenseObj = (l) => (isSpdxId(l) ? { license: { id: l } } : { license: { name: l } });
function hashesOf(c) {
  const out = [];
  const add = (h) => { if (isHex(h, 32)) out.push({ alg: 'SHA-256', content: h }); else if (isHex(h, 64)) out.push({ alg: 'SHA-512', content: h }); };
  add(c.weights_sha256); add(c.hash); add(c.corpus_hash); add(c.schema_hash); add(c.manifest_hash);
  return out.length ? out : undefined;
}
function pedigreeOf(c) {
  const anc = [];
  if (c.base_model) anc.push({ type: 'machine-learning-model', name: String(c.base_model) });
  for (const p of (Array.isArray(c.parent_models) ? c.parent_models : [])) anc.push({ type: 'machine-learning-model', name: String(p) });
  return anc.length ? { ancestors: anc } : undefined;
}
export function toCycloneDX(bom) {
  const uuid = (() => { const h = hashHex(canon(bom)); return h.slice(0, 8) + '-' + h.slice(8, 12) + '-4' + h.slice(13, 16) + '-8' + h.slice(17, 20) + '-' + h.slice(20, 32); })();
  const comp = (c) => {
    const base = { type: CDX_TYPE[c.type] || 'library', 'bom-ref': bomRef(c), name: c.name, version: c.version || undefined };
    if (c.license) base.licenses = [licenseObj(c.license)];
    const h = hashesOf(c); if (h) base.hashes = h;
    const ped = pedigreeOf(c); if (ped) base.pedigree = ped;
    if (CDX_TYPE[c.type] === 'machine-learning-model') base.modelCard = { modelParameters: { task: c.task || undefined }, properties: propsOf(c) };
    else { const p = propsOf(c); if (p) base.properties = p; }
    if (CDX_TYPE[c.type] === 'data') base.data = [{ type: 'dataset', name: c.name, classification: DATA_CLASS.has(c.data_classification) ? c.data_classification : 'unknown' }];
    return base;
  };
  const deps = bom.components.filter((c) => c.base_model || (Array.isArray(c.parent_models) && c.parent_models.length))
    .map((c) => ({ ref: bomRef(c), dependsOn: [c.base_model, ...(c.parent_models || [])].filter(Boolean).map(String) }));
  return {
    bomFormat: 'CycloneDX', specVersion: CDX_SPEC, serialNumber: 'urn:uuid:' + uuid, version: 1,
    metadata: {
      timestamp: Number.isFinite(bom.generated_ts) ? new Date(bom.generated_ts).toISOString() : undefined,
      component: { type: 'application', 'bom-ref': 'subject/' + (bom.subject || 'ai-system'), name: bom.subject || 'ai-system' },
      authors: bom.declarant ? [{ name: String(bom.declarant) }] : undefined,
      supplier: bom.declarant ? { name: String(bom.declarant) } : undefined,
      properties: [
        { name: 'trelyan:assurance_level', value: bom.assurance_name },
        { name: 'trelyan:grade', value: bom.grade.label },
        { name: 'trelyan:claim_scope', value: bom.claim_scope },
        { name: 'trelyan:runtime_binding_sha512', value: bom.runtime_binding },
      ],
    },
    components: bom.components.map(comp),
    dependencies: deps.length ? deps : undefined,
  };
}
function propsOf(c) {
  const p = [];
  for (const [k, v] of Object.entries(c)) {
    if (['type', 'name', 'version', 'license', 'weights_sha256', 'hash', 'corpus_hash', 'schema_hash', 'manifest_hash', 'base_model', 'parent_models', 'data_classification'].includes(k) || v === null || v === undefined) continue;
    p.push({ name: 'trelyan:' + k, value: typeof v === 'object' ? JSON.stringify(v) : String(v) });
  }
  return p.length ? p : undefined;
}

/* ---------- runtime binding (BOM-reality-drift bridge to pqtrace) ----------
 * Binds each component's IDENTITY + RUNTIME-POLICY fields (apex review + fix-verification round): identity
 * (type/name/version/primary-hash) plus the deploy-relevant policy attributes (licence, tool
 * sandbox/egress/side-effects/auth, dataset classification/consent). So drift detects a runtime that drops
 * a tool's sandbox, enables egress, or swaps a licence / classification / consent — WITHOUT false-
 * positiving on COSMETIC metadata (task, model_card_url, quantization, source/provenance) that the runtime
 * does not "load". NOTE (honest limit): a component with NO hash (see `unpinned`) is bound by declared
 * fields only — a byte-level swap of a same-name/attributes hashless artifact is NOT drift-detectable. */
function runtimeProjection(c) {
  return { type: c.type, name: c.name, version: c.version ?? null, hash: primaryHash(c), license: c.license ?? null,
    network_egress: c.network_egress ?? null, sandboxed: c.sandboxed ?? null, side_effects: c.side_effects ?? null,
    auth_required: c.auth_required ?? null, data_classification: c.data_classification ?? null, consent_mechanism: c.consent_mechanism ?? null };
}
export function runtimeBindingHash(bom) {
  return hashHex(canon({ v: V, subject: bom.subject ?? null, assurance_level: bom.assurance_level, components: (bom.components || []).map(runtimeProjection) }));
}
export function checkBomRealityDrift(bom, observedComponents) {
  const observed = { ...bom, components: normalizeComponents(observedComponents) };
  const expected = bom.runtime_binding || runtimeBindingHash(bom);
  const got = runtimeBindingHash(observed);
  // components with no declared hash cannot be byte-pinned — surface them so a caller never treats a
  // drift:false as "every artifact byte-verified" (apex review — the library/tool-swap blind spot).
  const unpinned = (bom.components || []).filter((c) => !primaryHash(c)).map((c) => c.type + '/' + c.name);
  const extra = unpinned.length ? { unpinned } : {};
  return got === expected ? { drift: false, ...extra } : { drift: true, alert: 'BOM-REALITY DRIFT: loaded components do not match the signed AIBOM', expected, got, ...extra };
}

/* ---------- sign / anchor / verify ---------- */
export function signAibom(bom, signers) {
  if (!bom || bom.v !== V) throw new Error('not a pqaibom-1 object');
  return { bom, envelope: seal(utf8ToBytes(canon(bom)), signers) };
}
export function appendAibom(log, signed) { return log.append({ kind: 'pqaibom-anchor', bom: signed.bom, envelope: signed.envelope }); }

/** verifyAibom({bom, envelope}, opts) — TOTAL/fail-closed. Recomputes the grade deterministically,
 *  verifies the seal (PIN the declarant via opts.sealOpts.trusted — else fail closed), checks the
 *  mandatory claim_scope + assurance level + grade cap + runtime binding; optional RFC-6962. */
export function verifyAibom({ bom, envelope } = {}, opts = {}) {
  const FAIL = (why) => ({ verified: false, why, sealOk: false, gradeOk: false, scopeOk: false, capOk: false, bindingOk: false, runnerAnchored: false, anchorOk: null });
  try {
    if (!bom || bom.v !== V || !envelope) return FAIL('malformed input');
    const sealOpts = opts.sealOpts || {};
    const hasPin = sealOpts.trusted && typeof sealOpts.trusted === 'object' && Object.keys(sealOpts.trusted).length > 0;
    if (!hasPin && !opts.allowUnpinnedSeal) return FAIL('sealOpts.trusted (declarant pubkey pins) required, or set allowUnpinnedSeal:true');
    const scopeOk = bom.claim_scope === 'self-attested-declaration' && Number.isInteger(bom.assurance_level) && bom.assurance_level >= 0 && bom.assurance_level <= 2;
    if (!scopeOk) return FAIL('missing/invalid claim_scope or assurance_level');
    // (apex CRITICAL) re-normalize + FIXPOINT: the signed components must ALREADY be normalized+deduped;
    // a hand-crafted BOM that strips the mislabel flag, pads with junk-type components, injects non-
    // whitelisted fields, or duplicates entries would otherwise bypass every normalization-based defense
    // because grade/binding both recompute over the same attacker-shaped array. Reject the mismatch.
    const norm = normalizeComponents(bom.components || []);
    if (canon(norm) !== canon(bom.components || [])) return { ...FAIL('components not normalized/deduped — hand-crafted BOM rejected'), scopeOk };
    const g = gradeAibom(bom.components || [], bom.assurance_level);
    // (apex) compare the FULL recomputed grade (letter, label, score, graded_dims, findings) — not just
    // letter+label — so a forged score:100 / all-'pass' findings breakdown cannot ride through verified.
    const gsub = (x) => canon({ letter: x.letter, label: x.label, score: x.score, graded_dims: x.graded_dims, findings: x.findings });
    const gradeOk = !!(bom.grade && gsub(bom.grade) === gsub(g));
    const capOk = !(g.letter === 'A' && bom.assurance_level < ASSURANCE.bound);   // A requires a DECLARED level >= bound
    const bindingOk = bom.runtime_binding === runtimeBindingHash(bom);
    const sealRes = openSeal(utf8ToBytes(canon(bom)), envelope, sealOpts);
    const sealOk = !!sealRes.verified;
    const base = { sealOk, gradeOk, scopeOk, capOk, bindingOk, runnerAnchored: !!sealRes.fullyAnchored };
    if (!sealOk) return { verified: false, why: 'seal failed', ...base, anchorOk: null };
    if (!gradeOk) return { verified: false, why: 'grade does not reproduce from components', ...base, anchorOk: null };
    if (!capOk) return { verified: false, why: 'grade cap violated (A requires a declared level >= bound)', ...base, anchorOk: null };
    if (!bindingOk) return { verified: false, why: 'runtime_binding does not match components', ...base, anchorOk: null };
    let anchorOk = null;
    if (opts.logView) {
      const { entry, inclusion, sth, logPub } = opts.logView;
      anchorOk = false;
      if (entry && entry.kind === 'pqaibom-anchor' && entry.bom && canon(entry.bom) === canon(bom) && inclusion && sth) {
        const leaf = entryLeafHash(entry);
        anchorOk = verifySTH(sth, logPub) && bytesToHex(leaf) === bytesToHex(inclusion.leaf) && inclusion.tree_size === sth.tree_size
          && verifyInclusionRFC(leaf, inclusion.index, sth.tree_size, (inclusion.proof || []).map((p) => p.sibling), hexToBytes(sth.root_hex));
      }
      if (!anchorOk) return { verified: false, why: 'log anchor failed', ...base, anchorOk };
    }
    // return the RECOMPUTED grade (not the caller's fields) so a consumer never renders unverified values.
    return { verified: true, why: null, ...base, anchorOk, grade: g.label, gradeDetail: { letter: g.letter, score: g.score, findings: g.findings } };
  } catch { return FAIL('exception (fail-closed)'); }
}

/* ---------- self-test: node pqaibom.mjs ---------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const A = (() => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(11)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; })();
  const C = (() => { const sk = new Uint8Array(32).fill(13); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })();
  const signers = [A, C];
  const sealOpts = { requireKinds: ['lattice', 'classical'], trusted: { 'ML-DSA-87': A.publicKey, 'Ed25519': C.publicKey } };
  const H = 'a'.repeat(64);

  const manifest = { components: [
    { type: 'model', name: 'acme-llm', version: '1.0', weights_sha256: H, source_url: 'https://hf.co/acme/llm', provider: 'Acme', license: 'Apache-2.0', task: 'text-generation', base_model: 'llama-3', model_card_url: 'https://hf.co/acme/llm/card', quantization: { method: 'AWQ', bits: 4 } },
    // the base model is itself declared as a component — a COMPLETE AIBOM's lineage resolves internally
    { type: 'model', name: 'llama-3', version: '3', weights_sha256: H, source_url: 'https://llama.meta.com', provider: 'Meta', license: 'Apache-2.0', task: 'text-generation', model_card_url: 'https://llama.meta.com/card' },
    { type: 'dataset', name: 'acme-corpus', hash: H, source: 'internal', provenance: 'curated 2025', license: 'CC-BY-4.0', data_classification: 'internal', consent_mechanism: 'licensed', split: 'train' },
    { type: 'tool', name: 'web_search', schema_hash: H, side_effects: true, network_egress: true, sandboxed: true, auth_required: true, source_uri: 'mcp://tools/web' },
    { type: 'guardrail', name: 'safety-v1', policy_id: 'pol-1', hash: H },
    { type: 'library', name: '@noble/post-quantum', version: '0.5.0', license: 'MIT' },
  ] };

  // 1. the ASSURANCE CAP is the headline
  const l0 = buildAibom(manifest, { assuranceLevel: ASSURANCE.declared, subject: 'acme-system', generated_ts: 1000 });
  ok(l0.grade.letter === 'B' && /Declared/.test(l0.grade.label), 'L0 all-green declaration caps at "B (Declared)"');
  const l1 = buildAibom(manifest, { assuranceLevel: ASSURANCE.bound, subject: 'acme-system', declarant: 'Acme Inc', generated_ts: 1000 });
  ok(l1.grade.letter === 'A' && /Bound/.test(l1.grade.label), 'L1 (hash-bound) same manifest earns "A (Bound)"');

  // 2. VACUOUS-BOM fix: an empty / AI-component-free BOM must NOT grade A
  ok(buildAibom({ components: [] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 }).grade.letter === 'F', 'empty BOM -> F (no vacuous A)');
  ok(buildAibom({ components: [{ type: 'library', name: 'x', version: '1', license: 'MIT' }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 }).grade.letter !== 'A', 'library-only BOM cannot reach A (no model/dataset to grade)');

  // 3. MISLABEL fix: a model declared as a library is flagged + capped
  const mis = buildAibom({ components: [{ type: 'library', name: 'sneaky', weights_sha256: H, base_model: 'llama-3', license: 'MIT' }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 });
  ok(mis.grade.findings.find((f) => f.dim === 'known_risk').status === 'fail' && LETTERS.indexOf(mis.grade.letter) >= LETTERS.indexOf('C'), 'mislabeled model (fields on a library) -> known_risk FAIL + grade capped');

  // 4. sandbox FAIL-CLOSED: an egress tool with sandboxed OMITTED is now risky
  const eg = buildAibom({ components: [{ type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c' }, { type: 'tool', name: 't', network_egress: true }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 });
  ok(eg.grade.findings.find((f) => f.dim === 'known_risk').status === 'fail', 'egress tool without sandboxed:true -> known_risk FAIL (no fail-open)');

  // 5. data-governance 'unknown' is NOT a pass
  const gov = buildAibom({ components: [{ type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c' }, { type: 'dataset', name: 'd', hash: H, provenance: 'p', license: 'MIT', data_classification: 'unknown', consent_mechanism: 'unknown' }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 });
  ok(gov.grade.findings.find((f) => f.dim === 'data_governance').status !== 'pass', "data_classification/consent 'unknown' -> data_governance NOT pass");

  // 6. partial needs a MAJORITY (1-of-3 hashed models is a fail, not a partial)
  const part = gradeAibom(normalizeComponents({ components: [
    { type: 'model', name: 'a', weights_sha256: H, provider: 'X', source_url: 'u', model_card_url: 'c', license: 'MIT' },
    { type: 'model', name: 'b', provider: 'X', source_url: 'u', model_card_url: 'c', license: 'MIT' },
    { type: 'model', name: 'cc', provider: 'X', source_url: 'u', model_card_url: 'c', license: 'MIT' },
  ] }), ASSURANCE.bound);
  ok(part.findings.find((f) => f.dim === 'integrity').status === 'fail', '1-of-3 models hashed -> integrity FAIL (partial needs a majority)');

  // 6b. COUNCIL FIX-VERIFICATION regression (both seats): the data-hiding + lineage-bypass exploits
  // DATASET-DODGE: a fully-declared model with ZERO datasets cannot reach A/B — training data is hidden
  const dodge = buildAibom({ components: [{ type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c', base_model: 'llama-3' }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 });
  ok(LETTERS.indexOf(dodge.grade.letter) >= LETTERS.indexOf('C') && dodge.grade.findings.find((f) => f.dim === 'data_governance').status === 'fail', 'model-only BOM (no dataset) -> data_governance FAIL + capped at C (dataset-dodge closed)');
  // AVGFRAC null-drop is subsumed: the same model-only BOM cannot inflate to A via a dropped dataset half
  ok(dodge.grade.letter !== 'A' && dodge.grade.letter !== 'B', 'a hidden-dataset BOM cannot reach A or B (avgFrac null-drop inflation closed)');
  // LINEAGE bypass: a merge that omits merge_method but declares parents is STILL graded (not dodged to N/A)
  const byp = gradeAibom(normalizeComponents({ components: [
    { type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c', parent_models: ['a', 'b'] },
    { type: 'dataset', name: 'd', hash: H, provenance: 'p', license: 'MIT', data_classification: 'public', consent_mechanism: 'public-domain' },
  ] }), ASSURANCE.bound);
  ok(byp.findings.find((f) => f.dim === 'lineage').status !== 'na', 'a model with parent_models but no merge_method is STILL graded for lineage (bypass closed)');
  // INTEGRITY cap: a partially-hashed BOM (with a dataset, so no completeness floor) cannot reach A
  const ph = gradeAibom(normalizeComponents({ components: [
    { type: 'model', name: 'a', weights_sha256: H, provider: 'X', source_url: 'u', model_card_url: 'c', license: 'MIT' },
    { type: 'model', name: 'b', provider: 'X', source_url: 'u', model_card_url: 'c', license: 'MIT' },
    { type: 'dataset', name: 'd', hash: H, provenance: 'p', license: 'MIT', data_classification: 'public', consent_mechanism: 'public-domain' },
  ] }), ASSURANCE.bound);
  ok(ph.findings.find((f) => f.dim === 'integrity').status === 'partial' && ph.letter !== 'A', 'a partially-hashed BOM (integrity partial) cannot reach A');
  // KNOWN_RISK cap: an egress tool not affirmatively sandboxed caps at C
  const eg2 = buildAibom({ components: [{ type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c' }, { type: 'dataset', name: 'd', hash: H, provenance: 'p', license: 'MIT', data_classification: 'public', consent_mechanism: 'public-domain' }, { type: 'tool', name: 't', network_egress: true }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 });
  ok(LETTERS.indexOf(eg2.grade.letter) >= LETTERS.indexOf('C'), 'egress tool not affirmatively sandboxed (known_risk fail) caps grade at C');

  // 7. bindManifest EARNS L1 honestly; a wrong hash stays L0
  const bytes = utf8ToBytes('the real weights');
  const realHash = bytesToHex(sha256(bytes));
  const bindMan = { components: [{ type: 'model', name: 'm', weights_sha256: realHash, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c' }] };
  ok(bindManifest(bindMan, () => bytes).level === ASSURANCE.bound, 'bindManifest with matching bytes EARNS L1 (bound)');
  ok(bindManifest(bindMan, () => utf8ToBytes('tampered')).level === ASSURANCE.declared, 'bindManifest with wrong bytes stays L0 (declared) + records mismatch');
  ok(bindManifest(bindMan, () => null).level === ASSURANCE.declared, 'bindManifest with unresolved bytes stays L0 (not silently bound)');

  // 8. deterministic + sign/verify + forged-grade rejection
  ok(canon(l0) === canon(buildAibom(manifest, { assuranceLevel: ASSURANCE.declared, subject: 'acme-system', generated_ts: 1000 })), 'BOM deterministic');
  const signed = signAibom(l1, signers);
  const v = verifyAibom(signed, { sealOpts });
  ok(v.verified && v.gradeOk && v.capOk && v.scopeOk && v.bindingOk && v.runnerAnchored, 'signed L1 AIBOM verifies (grade reproduces, cap+scope+binding+pin)');
  const forged = JSON.parse(JSON.stringify(l0)); forged.grade.letter = 'A'; forged.grade.label = 'A (Declared)';
  ok(verifyAibom(signAibom(forged, signers), { sealOpts }).verified === false, 'forged "A (Declared)" -> REJECTED (cap / recompute)');

  // 9. tamper after signing + attacker-key + fail-closed
  const tampered = JSON.parse(JSON.stringify(signed.bom)); tampered.components[0].license = 'GPL-3.0';
  ok(verifyAibom({ bom: tampered, envelope: signed.envelope }, { sealOpts }).verified === false, 'component edited after signing -> seal REJECTED');
  ok(gradeAibom(tampered.components, ASSURANCE.bound).letter === 'B', 'copyleft licence caps grade at B even at L1');
  const atk = [(() => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(200)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; })(), (() => { const sk = new Uint8Array(32).fill(201); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })()];
  ok(verifyAibom(signAibom(l1, atk), { sealOpts }).verified === false, 'AIBOM sealed with ATTACKER keys -> REJECTED under declarant pins');
  ok(verifyAibom(signed, {}).verified === false, 'unpinned verify FAILS CLOSED');

  // 10. CycloneDX 1.6 fidelity: serialNumber, timestamp, metadata.component, bom-ref, hashes, dependencies, license.id
  const cdx = toCycloneDX(l1);
  ok(cdx.bomFormat === 'CycloneDX' && cdx.specVersion === '1.6' && /^urn:uuid:/.test(cdx.serialNumber), 'CDX 1.6 with a urn:uuid serialNumber');
  ok(typeof cdx.metadata.timestamp === 'string' && cdx.metadata.component && cdx.metadata.component.name === 'acme-system', 'CDX metadata.timestamp + metadata.component (subject) present');
  ok(cdx.components.every((c) => c['bom-ref']) && cdx.components.some((c) => c.type === 'machine-learning-model') && cdx.components.some((c) => c.type === 'data') && cdx.components.some((c) => c.type === 'application'), 'CDX components carry bom-ref + faithful types (mlmodel/data/application)');
  ok(cdx.components.find((c) => c.name === 'acme-corpus').hashes && cdx.components.find((c) => c.name === 'acme-llm').licenses[0].license.id === 'Apache-2.0', 'dataset hashes emitted + SPDX license.id used');
  ok(Array.isArray(cdx.dependencies) && cdx.dependencies.some((d) => d.dependsOn.includes('llama-3')), 'CDX dependencies[] edge from the derived model to its base');
  ok(cdx.components.find((c) => c.name === 'acme-llm').pedigree.ancestors.some((a) => a.name === 'llama-3'), 'model pedigree.ancestors carries lineage');

  // 11. BOM-reality drift + transparency anchor
  ok(checkBomRealityDrift(l1, manifest.components).drift === false, 'loaded components match -> no drift');
  const swapped = JSON.parse(JSON.stringify(manifest.components)); swapped[0].weights_sha256 = 'b'.repeat(64);
  ok(checkBomRealityDrift(l1, swapped).drift === true, 'a different loaded weight hash -> BOM-REALITY DRIFT');
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(9));
  const log = new PQTransparencyLog();
  const idx = appendAibom(log, signed);
  const sth = log.signedTreeHead(logKey.secretKey, { ts: 5000 });
  ok(verifyAibom(signed, { sealOpts, logView: { entry: log.entries[idx], inclusion: log.inclusion(idx), sth, logPub: logKey.publicKey } }).verified === true, 'anchored AIBOM verifies incl. RFC-6962 inclusion');

  // 12. APEX-REVIEW regression lock (13 confirmed findings)
  // (#1 CRITICAL) hand-crafted BOM strips the mislabel flag / injects junk-type padding -> verify REJECTS (fixpoint)
  const hand = JSON.parse(JSON.stringify(signed.bom));
  hand.components.push({ type: 'library', name: 'sneaky', version: null, license: 'MIT', weights_sha256: H, base_model: 'llama-3' }); // model fields on a library, NO mislabel flag
  ok(verifyAibom(signAibom(hand, signers), { sealOpts }).verified === false, '#1 hand-crafted BOM (un-normalized: stripped mislabel + non-whitelisted fields) -> REJECTED (re-normalize fixpoint)');
  const junk = JSON.parse(JSON.stringify(signed.bom));
  for (let i = 0; i < 20; i++) junk.components.push({ type: 'junk', name: 'pad' + i, license: 'MIT' });
  ok(verifyAibom(signAibom(junk, signers), { sealOpts }).verified === false, '#1 junk-type padding (dropped by normalize) -> REJECTED (fixpoint)');
  // (#5) duplicate-component padding is deduped by normalize
  ok(normalizeComponents({ components: [{ type: 'dataset', name: 'd', version: '1' }, { type: 'dataset', name: 'd', version: '1' }] }).length === 1, '#5 duplicate (type/name@version) components deduped');
  // (#4) forged score/findings (letter unchanged) -> REJECTED by full-grade recompute
  const fg = JSON.parse(JSON.stringify(l0)); fg.grade.score = 100; fg.grade.findings = fg.grade.findings.map((f) => ({ ...f, status: 'pass' }));
  ok(verifyAibom(signAibom(fg, signers), { sealOpts }).verified === false, '#4 forged score:100 / all-pass findings (same letter) -> REJECTED (full-grade recompute)');
  // (#2) dataset-dodge-redux: a token eval_set does NOT satisfy the training-data floor
  const evalOnly = buildAibom({ components: [{ type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c' }, { type: 'eval_set', name: 'tiny', hash: H, provenance: 'p', license: 'MIT', data_classification: 'public', consent_mechanism: 'synthetic' }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 });
  ok(LETTERS.indexOf(evalOnly.grade.letter) >= LETTERS.indexOf('C') && evalOnly.grade.findings.find((f) => f.dim === 'data_governance').status === 'fail', '#2 model + eval_set-only (no training data) -> data_governance FAIL + capped C');
  const testSplit = buildAibom({ components: [{ type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c' }, { type: 'dataset', name: 'd', hash: H, provenance: 'p', license: 'MIT', data_classification: 'public', consent_mechanism: 'synthetic', split: 'test' }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 });
  ok(LETTERS.indexOf(testSplit.grade.letter) >= LETTERS.indexOf('C'), '#2 model + test-split dataset (no training split) -> capped C');
  // (#3) license regex: GPLv3 / OpenRAIL / whitespace-only
  ok(COPYLEFT.test('GPLv3') && COPYLEFT.test('AGPLv3'), '#3 COPYLEFT catches GPLv3 / AGPLv3 (v-suffix)');
  ok(NONCOMMERCIAL.test('OpenRAIL-M') && NONCOMMERCIAL.test('Llama 2 Community License'), '#3 NONCOMMERCIAL catches OpenRAIL / community-license');
  ok(UNKNOWN_LICENSE(' ') === true, '#3 a whitespace-only licence counts as UNKNOWN');
  // (#6) lineage tautology: a fabricated undeclared base_model no longer passes lineage
  const fakeBase = gradeAibom(normalizeComponents({ components: [{ type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c', base_model: 'totally-made-up' }, { type: 'dataset', name: 'd', hash: H, provenance: 'p', license: 'MIT', data_classification: 'public', consent_mechanism: 'synthetic', split: 'train' }] }), ASSURANCE.bound);
  ok(fakeBase.findings.find((f) => f.dim === 'lineage').status === 'fail', '#6 fabricated undeclared base_model -> lineage FAIL (no free-pass tautology)');
  // (#7) runtime_binding now covers safety/policy attributes: a dropped sandbox / swapped licence -> DRIFT
  const dropSandbox = JSON.parse(JSON.stringify(manifest.components)); dropSandbox.find((c) => c.name === 'web_search').sandboxed = false;
  ok(checkBomRealityDrift(l1, dropSandbox).drift === true, '#7 runtime drops a tool sandbox -> BOM-REALITY DRIFT (attribute now bound)');
  const swapLic = JSON.parse(JSON.stringify(manifest.components)); swapLic[0].license = 'GPL-3.0';
  ok(checkBomRealityDrift(l1, swapLic).drift === true, '#7 runtime swaps a component licence -> BOM-REALITY DRIFT');
  // (#8) hashless components are surfaced as `unpinned`
  const upBom = buildAibom({ components: [{ type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c' }, { type: 'dataset', name: 'd', hash: H, provenance: 'p', license: 'MIT', data_classification: 'public', consent_mechanism: 'synthetic', split: 'train' }, { type: 'library', name: 'lib', version: '1' }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 });
  ok((checkBomRealityDrift(upBom, upBom.components).unpinned || []).includes('library/lib'), '#8 a hashless component is surfaced as unpinned (byte-swap not drift-covered)');
  // (#4) verify returns the RECOMPUTED grade, not the caller's fields
  ok(v.gradeDetail && v.gradeDetail.letter === 'A' && typeof v.gradeDetail.score === 'number', '#4 verify returns the recomputed gradeDetail');
  // (#1 SAFETY INVARIANT) normalizeComponents MUST be idempotent — else the verify fixpoint would reject
  // every honestly-BUILT BOM (a catastrophic regression). Assert idempotency across all component shapes.
  const shapes = { components: [
    { type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c', base_model: 'b', parent_models: ['b'], quantization: { bits: 4 } },
    { type: 'model', name: 'b', weights_sha256: H, provider: 'Y', source_url: 'u', license: 'MIT', model_card_url: 'c' },
    { type: 'dataset', name: 'd', hash: H, provenance: 'p', license: 'MIT', data_classification: 'pii', consent_mechanism: 'opt-in', split: 'train' },
    { type: 'eval_set', name: 'e', hash: H }, { type: 'adapter', name: 'a', hash: H, base_model: 'b' },
    { type: 'prompt', name: 'p', hash: H, role: 'system' }, { type: 'tool', name: 't', schema_hash: H, network_egress: true, sandboxed: true },
    { type: 'vector_store', name: 'vs', embedding_model: 'emb', corpus_hash: H }, { type: 'guardrail', name: 'g', policy_id: 'x', hash: H },
    { type: 'library', name: 'lib', version: '1', license: 'MIT', hash: H },
    { type: 'library', name: 'mislabeled', weights_sha256: H, base_model: 'b' },   // model fields on a library -> mislabel flag (idempotence-critical)
    { type: 'junk', name: 'drop' }, { name: 'noType' },
  ] };
  const n1 = normalizeComponents(shapes); const n2 = normalizeComponents(n1);
  ok(canon(n1) === canon(n2), '#1 normalizeComponents is IDEMPOTENT across every shape INCL. a mislabeled component (the fixpoint safety invariant — an honest BOM never self-rejects)');
  ok(n1.find((c) => c.name === 'mislabeled').mislabel === true && n2.find((c) => c.name === 'mislabeled').mislabel === true, '#1 the mislabel flag SURVIVES re-normalization (idempotent — the fix-verification-round regression)');
  ok(verifyAibom(signAibom(buildAibom(shapes, { assuranceLevel: ASSURANCE.bound, subject: 's', generated_ts: 1 }), signers), { sealOpts }).gradeOk === true, '#1 a BOM built from every shape (incl. a flagged component) passes the verify fixpoint (no honest-path regression)');
  // FIX-VERIFICATION ROUND regressions:
  // dedupe removes EXACT clones but preserves same-name components differing by split (train vs test)
  const splits = normalizeComponents({ components: [{ type: 'dataset', name: 'c', hash: H, split: 'train' }, { type: 'dataset', name: 'c', hash: H, split: 'test' }, { type: 'dataset', name: 'c', hash: H, split: 'train' }] });
  ok(splits.length === 2, 'dedupe drops the EXACT clone but KEEPS the distinct train/test splits (no over-merge regression)');
  // COPYLEFT no longer false-positives on a permissive GNU licence; still catches the GPL family
  ok(COPYLEFT.test('LGPL-3.0') && !COPYLEFT.test('GNU All-Permissive License') && !COPYLEFT.test('Academic Free License 3.0'), 'COPYLEFT/NONCOMMERCIAL do not over-cap permissive GNU/AFL licences');
  // a RAG / retrieval system (model + vector_store, no training dataset) is NOT wrongly floor-capped
  const rag = buildAibom({ components: [{ type: 'model', name: 'm', weights_sha256: H, provider: 'X', source_url: 'u', license: 'MIT', model_card_url: 'c' }, { type: 'vector_store', name: 'kb', embedding_model: 'e', corpus_hash: H }] }, { assuranceLevel: ASSURANCE.bound, generated_ts: 1 });
  ok(rag.grade.findings.find((f) => f.dim === 'data_governance').status !== 'fail', 'RAG system (model + vector_store, no training set) is NOT floor-failed (no false regression)');
  // runtime binding: a COSMETIC change does NOT drift, but a POLICY change (sandbox) DOES
  const cosmetic = JSON.parse(JSON.stringify(manifest.components)); cosmetic[0].model_card_url = 'https://different/card';
  ok(checkBomRealityDrift(l1, cosmetic).drift === false, 'runtime binding: a cosmetic metadata change (model_card_url) does NOT false-positive drift');

  console.log('pqaibom self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqaibom\.mjs$/.test(process.argv[1] || '')) selfTest();
