/*!
 * pqtrace — PQ-attested AI EXECUTION & PROVENANCE TRACES (runner-attested, reference, standalone).
 *
 * TRUST BOUNDARY — READ FIRST (council design + apex-team adversarial round, 10 Jul 2026): a
 * pqtrace proves that the RUNNER's PINNED keys sealed this exact hash-chained log; it does NOT prove
 * the AI model actually behaved this way. The runner could lie at recording time — trust in a trace
 * is exactly trust in the runner's honesty when it wrote the log. v1 is LOG provenance ("execution
 * trace"), not model provenance and not a "reasoning trace" (no chain-of-thought/internals are
 * attested). Per-actor signatures / TEE attestation are the v2 path. A 'verdict' step RECORDS the
 * claim-gate's output; it does not itself reduce hallucinations. TWO absence gaps are inherent to
 * v1 and NOT detectable without pre-registration (a v2 feature): (i) a runner can record a trace,
 * abandon it UNSEALED, and re-record a sanitized version under a fresh trace_id; (ii) selective
 * disclosure — the salt-holder may open only favorable steps. Auditors must treat a runner-attested
 * trace as the runner's signed account, corroborated only where content is disclosed.
 *
 * WHAT IT GUARANTEES (each caveat is load-bearing — apex-team review closed the earlier overclaims):
 *  - INTEGRITY (relative to a sealed HEAD): every step is hash-chained (prev_hash) with strict seq +
 *    non-decreasing integer ts; any edit/insert/delete/reorder/truncation of a trace RELATIVE TO ITS
 *    SEALED HEAD is detectable by any verifier who HOLDS THAT HEAD and PINS the runner's keys
 *    (sealOpts.trusted). A wholesale re-record under different keys is NOT caught by chain checks
 *    alone — key pinning + transparency anchoring are what bind identity. (Z3: pqtrace_chain_z3.py.)
 *  - AUTHENTICITY: the HEAD is pqseal'd with the runner's signer set. The N-leg AND composition (e.g.
 *    ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519 at Cat-5) is a VERIFIER-SIDE POLICY: it holds only if the
 *    verifier passes sealOpts.trusted (per-alg runner pubkeys) + requireKinds/requireSuite. With no
 *    pins, openSeal proves only SELF-CONSISTENCY of the presented legs — so verifyTrace FAILS CLOSED
 *    unless sealOpts.trusted is set (or you explicitly pass allowUnpinnedSeal:true). The result
 *    surfaces runnerAnchored/suiteMatch/sealKinds so callers can't mistake self-consistency for trust.
 *  - TRANSPARENCY (detection, not prevention): appendTraceHead REFUSES a duplicate trace_id, and
 *    detectTraceEquivocation FLAGS two heads with one trace_id + different final hashes — so
 *    equivocation is DETECTABLE within a log view IF the verifier obtains that view's complete,
 *    honestly-reported anchor set; completeness is NOT cryptographically enforced in v1 (a
 *    withholding view defeats detection). Split-view across log views = the pqkt witness/gossip layer.
 *  - PRIVACY: content enters steps as SALTED HMAC commitments by default — commit = HMAC-SHA512(salt,
 *    data), 32-byte salt held by the trace owner — so low-entropy prompts cannot be dictionary-
 *    attacked, and (unlike a raw salt||data hash) the salt/content boundary is BOUND, so a discloser
 *    cannot open a step to a mere suffix of the real content (prefix-hiding is closed). Raw-hash mode
 *    is explicit + marked. NOTE: metadata fields (kind, actor, model_id, tokens, ts) and the
 *    step-kind sequence remain PLAINTEXT and may enable linkage — put content only in the committed
 *    content parameter, never in meta. See PRIVACY.md for GDPR/FADP deployment guidance.
 *
 * SCHEMA (audit-first): first-class model_id/model_config_hash/tokens{input,output}/tool_name/
 * policy_id; ts = integer Unix-epoch MILLISECONDS (UTC); step kinds include guardrail, human_edit,
 * error, plus a sealed head.status ∈ {complete, aborted} so a graceful abort is distinguishable from
 * a completed run (a hard crash leaves NO seal — absence is undetectable in v1, per above). Every
 * step's canon is capped (STEP_CANON_MAX) so no field can DoS verifiers. "Supports, not certifies"
 * regulatory alignment; self-attested, not certified. FIPS 203/204/205 final; FIPS 206 draft.
 *  Self-test: node pqtrace.mjs
 */
import { sha512 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes, concatBytes } from '@noble/hashes/utils.js';
import { seal, openSeal } from './pqseal.mjs';
import { PQTransparencyLog, verifySTH, entryLeafHash, verifyInclusionRFC } from './pqsign.mjs';

const V = 'pqtrace-1';
export const STEP_KINDS = ['prompt', 'system', 'context', 'model_output', 'tool_call', 'tool_result',
  'verdict', 'source', 'guardrail', 'human_edit', 'error', 'config'];
const ACTOR_REQUIRED = new Set(['model_output', 'tool_call', 'tool_result', 'human_edit', 'guardrail', 'verdict']);
const TOOL_KINDS = new Set(['tool_call', 'tool_result']);
const POLICY_KINDS = new Set(['guardrail', 'verdict']);
const STEP_CANON_MAX = 8192;   // whole-step verification-DoS cap (subsumes the old meta-only cap)
const SALT_LEN = 32;

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const hashHex = (bytes) => bytesToHex(sha512(bytes));
const isNonNegInt = (n) => Number.isInteger(n) && n >= 0;
function validTokens(t) {
  if (t === null || t === undefined) return true;
  if (typeof t !== 'object' || Array.isArray(t)) return false;
  return Object.keys(t).every((k) => (k === 'input' || k === 'output') && Number.isInteger(t[k]) && t[k] >= 0);
}

/** Salted content commitment (DEFAULT): commit = HMAC-SHA512(salt, content). HMAC binds the salt as
 * the KEY, so no bytes can migrate across the salt/content boundary — a discloser cannot open a step
 * to a suffix of the real content (the prefix-hiding attack the apex team found on salt||data). Salt
 * MUST be exactly 32 bytes; it stays with the trace owner. Raw mode ({rawHash:true}) is explicit. */
export function commitContent(content, opts = {}) {
  const data = content instanceof Uint8Array ? content : utf8ToBytes(String(content));
  if (opts.rawHash) return { commit_hex: hashHex(data), salt_hex: null, scheme: 'sha512-raw' };
  const salt = opts.salt instanceof Uint8Array ? opts.salt : randomBytes(SALT_LEN);
  if (salt.length !== SALT_LEN) throw new Error('salt must be exactly ' + SALT_LEN + ' bytes');
  return { commit_hex: bytesToHex(hmac(sha512, salt, data)), salt_hex: bytesToHex(salt), scheme: 'hmac-sha512' };
}
export function verifyContentCommitment(step, content, saltHex) {
  try {
    const data = content instanceof Uint8Array ? content : utf8ToBytes(String(content));
    if (!step || typeof step.content_commit !== 'string') return false;
    if (step.commit_scheme === 'sha512-raw') return hashHex(data) === step.content_commit;
    if (step.commit_scheme !== 'hmac-sha512' || typeof saltHex !== 'string') return false;
    const salt = hexToBytes(saltHex);
    if (salt.length !== SALT_LEN) return false;                 // bind the salt length (closes prefix-hiding)
    return bytesToHex(hmac(sha512, salt, data)) === step.content_commit;
  } catch { return false; }
}

const stepHash = (core) => hashHex(utf8ToBytes(canon(core)));

/** TraceWriter — the runner-side recorder. Manages seq / prev_hash / ts monotonicity / salts. */
export class TraceWriter {
  constructor({ trace_id = null, session_id = null, runner = null } = {}) {
    this.trace_id = trace_id || bytesToHex(randomBytes(16));
    this.session_id = session_id; this.runner = runner;
    this.steps = []; this.salts = {}; this.started_ts = null; this.lastTs = -1; this.finished = false;
  }
  /** addStep({kind, actor, content|content_commit, ts, model_id?, model_config_hash?, tokens?,
   *          tool_name?, policy_id?, meta?, rawHash?, salt?}) — ts = integer Unix-epoch ms. */
  addStep(s) {
    if (this.finished) throw new Error('trace already finished');
    if (!STEP_KINDS.includes(s.kind)) throw new Error('unknown step kind: ' + s.kind);
    if (!isNonNegInt(s.ts)) throw new Error('step ts must be a non-negative integer (Unix-epoch ms)');
    if (s.ts < this.lastTs) throw new Error('step ts must be non-decreasing');
    if (ACTOR_REQUIRED.has(s.kind) && (s.actor === null || s.actor === undefined || s.actor === '')) throw new Error('actor is required for kind ' + s.kind);
    if (TOOL_KINDS.has(s.kind) && !s.tool_name) throw new Error('tool_name is required for kind ' + s.kind);
    if (POLICY_KINDS.has(s.kind) && !s.policy_id) throw new Error('policy_id is required for kind ' + s.kind);
    if (!validTokens(s.tokens)) throw new Error('tokens must be null or {input?:int>=0, output?:int>=0}');
    const meta = s.meta ?? null;
    let commit_hex, salt_hex = null, scheme;
    if (s.content_commit) { commit_hex = s.content_commit; scheme = s.commit_scheme || 'hmac-sha512'; }
    else { const c = commitContent(s.content ?? '', { rawHash: !!s.rawHash, salt: s.salt }); commit_hex = c.commit_hex; salt_hex = c.salt_hex; scheme = c.scheme; }
    const seq = this.steps.length;
    const core = {
      v: V, trace_id: this.trace_id, seq, ts: s.ts, kind: s.kind, actor: s.actor ?? null,
      model_id: s.model_id ?? null, model_config_hash: s.model_config_hash ?? null,
      tokens: s.tokens ?? null, tool_name: s.tool_name ?? null, policy_id: s.policy_id ?? null,
      content_commit: commit_hex, commit_scheme: scheme, meta,
      prev_hash: seq === 0 ? null : this.steps[seq - 1].step_hash,
    };
    if (canon(core).length > STEP_CANON_MAX) throw new Error('step exceeds ' + STEP_CANON_MAX + ' canon bytes');
    const step = { ...core, step_hash: stepHash(core) };
    this.steps.push(step);
    if (salt_hex) this.salts[seq] = salt_hex;                   // held by the owner, NOT in the trace
    if (this.started_ts === null) this.started_ts = s.ts;
    this.lastTs = s.ts;
    return { step, salt_hex };
  }
  _seal(signers, { ended_ts, status }) {
    if (this.finished) throw new Error('trace already finished');
    if (!this.steps.length) throw new Error('cannot seal an empty trace');
    const end = ended_ts ?? this.lastTs;
    if (!isNonNegInt(end) || end < this.lastTs) throw new Error('ended_ts must be an integer >= the last step ts');
    this.finished = true;
    const head = {
      v: 'pqtrace-head-1', trace_id: this.trace_id, session_id: this.session_id, runner: this.runner,
      status, count: this.steps.length, final_hash: this.steps[this.steps.length - 1].step_hash,
      started_ts: this.started_ts, ended_ts: end,
    };
    const envelope = seal(utf8ToBytes(canon(head)), signers);
    return { head, envelope, steps: this.steps, salts: this.salts };
  }
  /** finish + pqseal the HEAD with the runner's signers ([{alg, secretKey, publicKey}, ...]). */
  finish(signers, opts = {}) { return this._seal(signers, { ended_ts: opts.ended_ts, status: 'complete' }); }
  /** abort — append a first-class error step, then seal with status 'aborted' (a dying run can
   * honestly close itself; distinguishes a graceful abort from a completed run). */
  abort(signers, { reason = 'aborted', ts } = {}) {
    const at = isNonNegInt(ts) ? ts : this.lastTs;
    this.addStep({ kind: 'error', actor: this.runner || 'runner', content: String(reason), ts: at, meta: { reason: String(reason) } });
    return this._seal(signers, { ended_ts: at, status: 'aborted' });
  }
}

/* ---------- transparency anchoring (equivocation-resistant at the log view) ---------- */
/** Append a sealed head; REFUSES a second head with the same trace_id (best-effort — see header). */
export function appendTraceHead(log, head, envelope) {
  const dup = log.entries.find((e) => e && e.kind === 'pqtrace-anchor' && e.head && e.head.trace_id === head.trace_id);
  if (dup) throw new Error('trace_id already anchored in this log (equivocation refused)');
  return log.append({ kind: 'pqtrace-anchor', head, envelope });
}
export function detectTraceEquivocation(anchors) {
  const seen = new Map();
  for (const a of Array.isArray(anchors) ? anchors : []) {
    const h = a && a.head; if (!h || !h.trace_id || typeof h.final_hash !== 'string') continue;
    const prior = seen.get(h.trace_id);
    if (prior !== undefined && prior !== h.final_hash) return { equivocation: true, trace_id: h.trace_id, reason: 'one trace_id sealed with two different final hashes' };
    if (prior === undefined) seen.set(h.trace_id, h.final_hash);
  }
  return { equivocation: false };
}

/* ---------- the VERIFIER (TOTAL: fail-closed on any malformed input) ---------- */
/** verifyTrace({steps, head, envelope}, opts)
 *  opts: { sealOpts (passed to openSeal — PIN the runner via sealOpts.trusted = {ALG: pubkey,...},
 *            optionally + requireKinds/requireSuite/requirePinned; see pqseal.mjs),
 *          allowUnpinnedSeal (bool — accept a self-consistent, UNPINNED seal; default false = fail
 *            closed, because an unpinned pass proves only self-consistency, NOT runner authenticity),
 *          logView: {entry, inclusion, sth, logPub (MUST be a pinned/trusted log key), anchors?},
 *          disclosures: { [seq]: {content, salt_hex} } }. */
export function verifyTrace({ steps, head, envelope } = {}, opts = {}) {
  const FAIL = (why) => ({ verified: false, why, chainOk: false, headOk: false, sealOk: false, runnerAnchored: false, suiteMatch: false, sealKinds: [], anchorOk: null, contentOk: null, equivocation: null });
  try {
    if (!Array.isArray(steps) || !steps.length || !head || !envelope) return FAIL('malformed input');
    const sealOpts = opts.sealOpts || {};
    const hasPin = sealOpts.trusted && typeof sealOpts.trusted === 'object' && Object.keys(sealOpts.trusted).length > 0;
    if (!hasPin && !opts.allowUnpinnedSeal) return FAIL('sealOpts.trusted (runner pubkey pins) required, or pass allowUnpinnedSeal:true to accept a self-consistent seal without authenticating the runner');
    // 1. per-step recompute + chain + seq + ts + trace_id uniformity + per-step canon cap
    let lastTs = -1;
    for (let i = 0; i < steps.length; i++) {
      const s = steps[i];
      if (!s || s.v !== V || s.trace_id !== head.trace_id || s.seq !== i) return FAIL('step ' + i + ': bad v/trace_id/seq');
      if (!isNonNegInt(s.ts) || s.ts < lastTs) return FAIL('step ' + i + ': ts not a non-decreasing non-negative integer');
      if (!STEP_KINDS.includes(s.kind)) return FAIL('step ' + i + ': unknown kind');
      if (ACTOR_REQUIRED.has(s.kind) && (s.actor === null || s.actor === undefined || s.actor === '')) return FAIL('step ' + i + ': actor required for ' + s.kind);
      if (TOOL_KINDS.has(s.kind) && !s.tool_name) return FAIL('step ' + i + ': tool_name required for ' + s.kind);
      if (POLICY_KINDS.has(s.kind) && !s.policy_id) return FAIL('step ' + i + ': policy_id required for ' + s.kind);
      if (!validTokens(s.tokens)) return FAIL('step ' + i + ': bad tokens shape');
      const expectPrev = i === 0 ? null : steps[i - 1].step_hash;
      if (s.prev_hash !== expectPrev) return FAIL('step ' + i + ': prev_hash broken');
      const { step_hash, ...core } = s;
      if (canon(core).length > STEP_CANON_MAX) return FAIL('step ' + i + ': over canon cap');
      if (stepHash(core) !== step_hash) return FAIL('step ' + i + ': step_hash mismatch');
      lastTs = s.ts;
    }
    const chainOk = true;
    // 2. head recompute (status + count + final hash + time bounds)
    const headOk = head.v === 'pqtrace-head-1' && (head.status === 'complete' || head.status === 'aborted')
      && head.count === steps.length && head.final_hash === steps[steps.length - 1].step_hash
      && head.started_ts === steps[0].ts && isNonNegInt(head.ended_ts) && head.ended_ts >= lastTs;
    if (!headOk) return { ...FAIL('head does not match steps'), chainOk };
    // 3. the pqseal AND-composition over the head bytes (authenticity, per the caller's pins)
    const sealRes = openSeal(utf8ToBytes(canon(head)), envelope, sealOpts);
    const sealOk = !!sealRes.verified;
    const base = { chainOk, headOk, sealOk, runnerAnchored: !!sealRes.fullyAnchored, suiteMatch: !!sealRes.suiteMatch, sealKinds: sealRes.kinds || [] };
    if (!sealOk) return { verified: false, why: 'seal failed', ...base, anchorOk: null, contentOk: null, equivocation: null };
    // 4. optional transparency anchor: inclusion of the anchor entry + no same-id different-hash head
    let anchorOk = null, equivocation = null;
    if (opts.logView) {
      const { entry, inclusion, sth, logPub, anchors } = opts.logView;
      anchorOk = false;
      if (entry && entry.kind === 'pqtrace-anchor' && entry.head && canon(entry.head) === canon(head) && inclusion && sth) {
        const sthOk = verifySTH(sth, logPub);
        const leaf = entryLeafHash(entry);
        const leafBound = bytesToHex(leaf) === bytesToHex(inclusion.leaf);
        const sizeOk = inclusion.tree_size === sth.tree_size;
        anchorOk = sthOk && leafBound && sizeOk
          && verifyInclusionRFC(leaf, inclusion.index, sth.tree_size, (inclusion.proof || []).map((p) => p.sibling), hexToBytes(sth.root_hex));
      }
      if (anchors) { equivocation = detectTraceEquivocation(anchors); if (equivocation.equivocation) return { verified: false, why: 'trace equivocation in log view', ...base, anchorOk, contentOk: null, equivocation }; }
      if (!anchorOk) return { verified: false, why: 'log anchor failed', ...base, anchorOk, contentOk: null, equivocation };
    }
    // 5. optional per-step content disclosures
    let contentOk = null;
    if (opts.disclosures) {
      contentOk = Object.entries(opts.disclosures).every(([seq, d]) => {
        const idx = Number(seq); if (!Number.isInteger(idx) || idx < 0 || idx >= steps.length) return false;
        return d && verifyContentCommitment(steps[idx], d.content, d.salt_hex);
      });
      if (!contentOk) return { verified: false, why: 'content disclosure mismatch', ...base, anchorOk, contentOk, equivocation };
    }
    return { verified: true, why: null, ...base, anchorOk, contentOk, equivocation };
  } catch { return FAIL('exception (fail-closed)'); }
}

/* ---------- self-test: node pqtrace.mjs ---------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { slh_dsa_sha2_256f } = await import('@noble/post-quantum/slh-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => ({ alg: 'ML-DSA-87', ... (() => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { secretKey: k.secretKey, publicKey: k.publicKey }; })() });
  const mkSlh = (n) => { const k = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(n)); return { alg: 'SLH-DSA-256f', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  const A = mk(1), B = mkSlh(2), C = mkEd(3);
  const signers = [A, B, C];                                   // full Cat-5 3-family composition (SLH leg now exercised)
  // PIN the runner correctly: openSeal reads opts.trusted (NOT trustedAnchors — the apex-team fix).
  const sealOpts = { requireKinds: ['lattice', 'hash-based', 'classical'], trusted: { 'ML-DSA-87': A.publicKey, 'SLH-DSA-256f': B.publicKey, 'Ed25519': C.publicKey } };

  // 1. record a realistic trace (integer ms ts; typed tool/policy fields)
  const w = new TraceWriter({ session_id: 'sess-1', runner: 'apex-council-runner' });
  w.addStep({ kind: 'config', actor: 'runner', content: '{"temp":0.2}', ts: 1000, model_config_hash: 'cfg1', meta: { note: 'run start' } });
  w.addStep({ kind: 'prompt', actor: 'user', content: 'What is the capital of France?', ts: 1001 });
  const mo = w.addStep({ kind: 'model_output', actor: 'seat:fable-5', content: 'Paris.', ts: 1002, model_id: 'claude-fable-5', tokens: { input: 12, output: 3 } });
  w.addStep({ kind: 'verdict', actor: 'claim-gate', policy_id: 'claimgate-v1', content: '{"claim":"Paris is the capital of France","status":"verified"}', ts: 1003 });
  const { head, envelope, steps, salts } = w.finish(signers, { ended_ts: 1004 });
  const good = verifyTrace({ steps, head, envelope }, { sealOpts });
  ok(good.verified === true, 'honest 3-family trace verifies (chain+head+seal)');
  ok(good.runnerAnchored === true && good.suiteMatch === true, 'result surfaces runnerAnchored + suiteMatch (pins actually bit)');

  // 2. AUTHENTICITY: a trace forged with ATTACKER keys must be REJECTED under the honest pins (the
  //    critical apex-team finding — with the old trustedAnchors typo this passed).
  const atk = [mk(200), mkSlh(201), mkEd(202)];
  const wf = new TraceWriter({ trace_id: head.trace_id });
  wf.addStep({ kind: 'prompt', actor: 'user', content: 'What is the capital of France?', ts: 1001 });
  wf.addStep({ kind: 'model_output', actor: 'seat:evil', content: 'Berlin.', ts: 1002 });
  const forged = wf.finish(atk, { ended_ts: 1002 });
  ok(verifyTrace({ steps: forged.steps, head: forged.head, envelope: forged.envelope }, { sealOpts }).verified === false, 'trace forged with ATTACKER keys -> REJECTED under honest pins');
  // 3. FAIL-CLOSED: no pins and no opt-out -> refuse to vouch (self-consistency is not authenticity)
  const unp = verifyTrace({ steps: forged.steps, head: forged.head, envelope: forged.envelope }, {});
  ok(unp.verified === false && /trusted/.test(unp.why), 'unpinned verify (no sealOpts) FAILS CLOSED with a clear reason');
  const optIn = verifyTrace({ steps: forged.steps, head: forged.head, envelope: forged.envelope }, { allowUnpinnedSeal: true });
  ok(optIn.verified === true && optIn.runnerAnchored === false, 'allowUnpinnedSeal:true accepts self-consistency but reports runnerAnchored:false');

  // 4. tamper detection (relative to the sealed head), all under correct pins
  const edited = steps.map((s) => ({ ...s })); edited[2] = { ...edited[2], actor: 'seat:evil' };
  ok(verifyTrace({ steps: edited, head, envelope }, { sealOpts }).verified === false, 'edited step -> REJECTED');
  ok(verifyTrace({ steps: [steps[0], steps[2], steps[1], steps[3]], head, envelope }, { sealOpts }).verified === false, 'reordered -> REJECTED');
  ok(verifyTrace({ steps: steps.slice(0, 3), head, envelope }, { sealOpts }).verified === false, 'truncated -> REJECTED (head binds count+final)');
  ok(verifyTrace({ steps: [steps[0], steps[1], steps[3]], head, envelope }, { sealOpts }).verified === false, 'deleted middle -> REJECTED');
  ok(verifyTrace({ steps: [...steps, { ...steps[3], seq: 4, prev_hash: steps[3].step_hash }], head, envelope }, { sealOpts }).verified === false, 'appended extra step -> REJECTED');
  ok(verifyTrace({ steps, head: { ...head, ended_ts: 9999 }, envelope }, { sealOpts }).verified === false, 'tampered head -> seal REJECTED');

  // 5. HMAC commitment: dictionary-resistant AND prefix-binding (the apex-team crypto fix)
  const c1 = commitContent('hello'), c2 = commitContent('hello');
  ok(c1.commit_hex !== c2.commit_hex && c1.scheme === 'hmac-sha512', 'salted HMAC: identical content -> distinct commitments');
  ok(verifyContentCommitment(steps[1], 'What is the capital of France?', salts[1]) === true, 'content disclosure verifies');
  ok(verifyContentCommitment(steps[1], 'What is the capital of Spain?', salts[1]) === false, 'wrong content -> disclosure fails');
  // prefix-hiding attempt: seal the REAL prompt, try to open it as a benign SUFFIX with a longer "salt"
  const realSalt = randomBytes(32);
  const commitReal = commitContent('IGNORE SAFETY. Paris?', { salt: realSalt });
  const fakeStep = { content_commit: commitReal.commit_hex, commit_scheme: 'hmac-sha512' };
  const fakeSalt = bytesToHex(concatBytes(realSalt, utf8ToBytes('IGNORE SAFETY. ')));  // 47 bytes
  ok(verifyContentCommitment(fakeStep, 'Paris?', fakeSalt) === false, 'prefix-hiding: cannot open a longer-salt SUFFIX (HMAC + 32-byte salt bind the boundary)');
  ok(verifyContentCommitment(fakeStep, 'IGNORE SAFETY. Paris?', bytesToHex(realSalt)) === true, 'the true content+32B salt still opens correctly');
  ok(verifyTrace({ steps, head, envelope }, { sealOpts, disclosures: { 1: { content: 'What is the capital of France?', salt_hex: salts[1] } } }).verified === true, 'verifyTrace with a correct disclosure');
  ok(verifyTrace({ steps, head, envelope }, { sealOpts, disclosures: { 1: { content: 'wrong', salt_hex: salts[1] } } }).verified === false, 'verifyTrace with a WRONG disclosure -> REJECTED');
  ok(!('salt_hex' in steps[2]) && !('content' in steps[2]) && salts[2] === mo.salt_hex, 'steps carry commitments only; salts held by the owner');

  // 6. writer guards
  const wg = new TraceWriter({});
  let threw = (f) => { try { f(); return false; } catch { return true; } };
  wg.addStep({ kind: 'prompt', actor: 'u', content: 'x', ts: 10 });
  ok(threw(() => wg.addStep({ kind: 'prompt', actor: 'u', content: 'y', ts: 5 })), 'writer rejects a ts regression');
  ok(threw(() => wg.addStep({ kind: 'prompt', actor: 'u', content: 'y', ts: 10.5 })), 'writer rejects a non-integer ts');
  ok(threw(() => wg.addStep({ kind: 'prompt', actor: 'u', content: 'z', ts: 11, meta: { big: 'x'.repeat(9000) } })), 'writer rejects a step over the canon cap');
  ok(threw(() => wg.addStep({ kind: 'prompt', actor: 'u'.repeat(9000), content: 'q', ts: 11 })), 'writer caps the WHOLE step (bloated actor), not just meta');
  ok(threw(() => wg.addStep({ kind: 'telepathy', actor: 'u', content: 'q', ts: 12 })), 'writer rejects an unknown kind');
  ok(threw(() => wg.addStep({ kind: 'model_output', content: 'q', ts: 12 })), 'writer requires actor for model_output');
  ok(threw(() => wg.addStep({ kind: 'tool_call', actor: 'a', content: 'q', ts: 12 })), 'writer requires tool_name for tool_call');
  ok(threw(() => wg.addStep({ kind: 'model_output', actor: 'a', content: 'q', ts: 12, tokens: { input: -1 } })), 'writer rejects a bad tokens shape');
  ok(threw(() => new TraceWriter({}).finish(signers)), 'cannot seal an empty trace');
  const wend = new TraceWriter({}); wend.addStep({ kind: 'prompt', actor: 'u', content: 'x', ts: 5 });
  ok(threw(() => wend.finish(signers, { ended_ts: 2 })), 'finish rejects ended_ts < last step ts');

  // 7. abort semantics: head.status distinguishes a graceful abort from a completed run
  const wa = new TraceWriter({ runner: 'r' });
  wa.addStep({ kind: 'prompt', actor: 'u', content: 'do X', ts: 100 });
  const ab = wa.abort(signers, { reason: 'model timeout', ts: 101 });
  ok(ab.head.status === 'aborted', 'abort seals head.status = aborted');
  ok(ab.steps[ab.steps.length - 1].kind === 'error', 'abort appends a first-class error step');
  ok(verifyTrace({ steps: ab.steps, head: ab.head, envelope: ab.envelope }, { sealOpts }).verified === true, 'aborted trace verifies (status is under the seal)');
  ok(verifyTrace({ steps: ab.steps, head: { ...ab.head, status: 'complete' }, envelope: ab.envelope }, { sealOpts }).verified === false, 'flipping status complete<->aborted breaks the seal');

  // 8. transparency anchoring + equivocation
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(9));
  const log = new PQTransparencyLog();
  const idx = appendTraceHead(log, head, envelope);
  const sth = log.signedTreeHead(logKey.secretKey, { ts: 5000 });
  const view = { entry: log.entries[idx], inclusion: log.inclusion(idx), sth, logPub: logKey.publicKey, anchors: log.entries.filter((e) => e.kind === 'pqtrace-anchor') };
  ok(verifyTrace({ steps, head, envelope }, { sealOpts, logView: view }).verified === true, 'anchored trace verifies incl. RFC-6962 inclusion');
  ok(threw(() => appendTraceHead(log, { ...head, final_hash: 'ff' }, envelope)), 'appendTraceHead REFUSES a second head with the same trace_id');
  const forgedAnchors = [...view.anchors, { kind: 'pqtrace-anchor', head: { ...head, final_hash: 'ff'.repeat(64) } }];
  ok(detectTraceEquivocation(forgedAnchors).equivocation === true, 'detectTraceEquivocation flags one trace_id with two final hashes');
  ok(verifyTrace({ steps, head, envelope }, { sealOpts, logView: { ...view, anchors: forgedAnchors } }).verified === false, 'verifyTrace REJECTS when the log view shows equivocation');

  // 9. cross-trace splice
  const wo = new TraceWriter({}); wo.addStep({ kind: 'prompt', actor: 'u', content: 'other', ts: 1 });
  const other = wo.finish(signers);
  ok(verifyTrace({ steps: other.steps, head, envelope }, { sealOpts }).verified === false, 'steps from a different trace_id -> REJECTED (splice blocked)');

  console.log('pqtrace self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqtrace\.mjs$/.test(process.argv[1] || '')) selfTest();
