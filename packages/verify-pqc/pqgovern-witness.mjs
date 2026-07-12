/*!
 * pqgovern-witness — multi-party WITNESS / GOSSIP quorum for the AI-governance transparency log (reference, DRAFT).
 *
 * pqgovern-monitor is fork-refusing but SINGLE-PARTY: it holds the log append-only across the STHs IT observes.
 * Its own honest-scope names the residual gap — a malicious log can present a SPLIT VIEW: to monitor A one
 * internally-consistent history, to monitor B a DIFFERENT internally-consistent history, never showing either
 * head to the other. Each monitor's own consistency check passes forever; neither can detect the equivocation.
 *
 * This is the rung above: independent WITNESSES each co-sign the head they accepted, and a RECONCILER
 * cross-checks their signed tree heads. The detections are:
 *   - EXACT-SIZE FORK  — two trusted witnesses hold DIFFERENT roots at the SAME tree_size (no proof needed).
 *   - PREFIX VIOLATION — witness@m and witness@n (n>m), and the log CANNOT supply a valid m->n consistency
 *                        proof binding root_m as a prefix of root_n (RFC-6962 verifyConsistency = false).
 * Because every counted observation carries the LOG's own STH signature (re-verified under the pinned log key),
 * a detected disagreement is UNDENIABLE: the log signed two conflicting heads — not a witness fabricating one.
 *
 * HONEST SCOPE (claim-hygiene LAW): a quorum proves a SAFETY property (the log EQUIVOCATED) — never LIVENESS
 * or COMPLETENESS (that the log shows everyone everything). It detects a split view ONLY among witnesses that
 * actually GOSSIP into the SAME reconcile call; a witness kept in a partition and never reconciled adds nothing.
 * A different-size pair can only be RESOLVED with a consistency proof — from roots alone the reconciler abstains
 * (reported as unresolved, `consistent` stays FALSE, never asserted). This is NOT a majority-VOTE system: because
 * every counted observation re-verifies the log's STH signature, a witness cannot forge a head, so a SINGLE honest
 * witness suffices for safety (no false equivocation is possible from any number of malicious witnesses — they can
 * only present REAL log heads), and DETECTION needs only that BOTH conflicting heads reach the same reconcile call
 * via some trusted witness — not an honest majority. Witness co-signatures are ML-DSA-87 (matching the log's STH
 * key alg) and domain-separated from STH signatures (WITNESS_CTX != STH_CTX). The
 * RFC-6962 consistency ALGORITHM is machine-checked (formal/rfc6962_consistency_algo_z3) — that proves the
 * algorithm, not this JS binding, which remains pre-audit. Every function is TOTAL / fail-closed.
 *  Self-test: node pqgovern-witness.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { sthCoreBytes, verifySTH, verifyConsistency } from './pqsign.mjs';
import { GovernLogMonitor } from './pqgovern-monitor.mjs';

// Domain separation: a witness co-signature MUST NOT be confusable with a log STH signature (STH_CTX) nor any
// other artifact signature. A witness signs "witness W observed head H under the pinned log key at time T".
const WITNESS_CTX = utf8ToBytes('trelyan-pqgovern-witness-v1');

const isInt = (n) => Number.isInteger(n);
// magnitude-carrying fields (tree_size / timestamps) must be SAFE integers: JSON.stringify rounds integers > 2^53,
// so an unsafe-int tree_size could canon-collide with a different size and let a witness sig be replayed across
// sizes (council/DeepSeek). Unreachable given pqsign's 2^32 array-length + verifyConsistency caps, but fail-closed
// here so the witness module is self-defensively robust regardless of the log's caps.
const isSafeInt = (n) => Number.isSafeInteger(n);
const isHex = (s) => typeof s === 'string' && s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
const eqHex = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
// consistency-proof elements are raw hashes (Uint8Array) from pqsign log.consistency().proof; tolerate {sibling}.
const rawProof = (p) => (Array.isArray(p) ? p.map((x) => (x && x.sibling) ? x.sibling : x) : []);
// local canonical (sorted-key, minimal-separator) serializer — matches pqsign's canon for cross-impl determinism.
const canon = (v) => {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
};
// THE witness signed-bytes format — the ONE place it lives, so observe + verify can't drift out of sync.
const witnessCore = (o) => utf8ToBytes(canon({ observed_ts: o.observed_ts, root: o.root_hex, sth_ts: o.sth_ts, tree_size: o.tree_size, witness: o.witness }));

/** witnessObserve(sth, logPub, witnessSecret, witnessPub, opts?) -> a signed witness observation.
 *  REFUSES (throws) to co-sign an STH that does not verify under the pinned log key — a witness never vouches
 *  for a head it did not itself verify. Carries the log's STH sig so a reconciler re-verifies it trustlessly. */
export function witnessObserve(sth, logPub, witnessSecret, witnessPub, opts = {}) {
  if (!sth || !isSafeInt(sth.tree_size) || sth.tree_size < 0 || !isHex(sth.root_hex) || !isSafeInt(sth.ts)) throw new Error('witnessObserve: malformed STH (safe-int tree_size>=0, hex root, safe-int ts required)');
  if (!logPub || !witnessSecret || !witnessPub) throw new Error('witnessObserve: requires logPub, witnessSecret, witnessPub');
  if (!verifySTH(sth, logPub)) throw new Error('witnessObserve: refusing to co-sign an STH that does not verify under the pinned log key');
  const observed_ts = isSafeInt(opts.observed_ts) ? opts.observed_ts : sth.ts;
  const obs = { tree_size: sth.tree_size, root_hex: sth.root_hex.toLowerCase(), sth_ts: sth.ts, observed_ts, witness: bytesToHex(witnessPub), log_sig: sth.sig };
  obs.sig = bytesToHex(ml_dsa87.sign(witnessCore(obs), witnessSecret, { context: WITNESS_CTX }));
  return obs;
}

/** verifyWitnessObservation(obs, logPub, witnessPub) -> { ok, why?, tree_size?, root_hex? }. TOTAL.
 *  Confirms: (1) witnessPub matches obs.witness (anti-reattribution), (2) the witness signature is valid over
 *  the canonical core, (3) the carried log STH signature is valid under the PINNED log key. All three or ok:false. */
export function verifyWitnessObservation(obs, logPub, witnessPub) {
  try {
    if (!obs || !isSafeInt(obs.tree_size) || obs.tree_size < 0 || !isHex(obs.root_hex) || !isSafeInt(obs.sth_ts) || !isSafeInt(obs.observed_ts)) return { ok: false, why: 'malformed observation (safe-int tree_size/sth_ts/observed_ts + hex root required)' };
    if (!isHex(obs.witness) || !isHex(obs.sig) || !isHex(obs.log_sig)) return { ok: false, why: 'missing/invalid witness identity, signature, or log_sig' };
    if (!witnessPub || !logPub) return { ok: false, why: 'requires logPub and witnessPub' };
    if (!eqHex(obs.witness, bytesToHex(witnessPub))) return { ok: false, why: 'witnessPub does not match obs.witness (reattribution)' };
    if (!ml_dsa87.verify(hexToBytes(obs.sig), witnessCore(obs), witnessPub, { context: WITNESS_CTX })) return { ok: false, why: 'witness signature invalid' };
    // trustless: the vouched head must ALSO be an authentic log head — so a detected disagreement is the LOG's
    // equivocation, not a witness fabricating a head to frame the log.
    if (!verifySTH({ tree_size: obs.tree_size, root_hex: obs.root_hex, ts: obs.sth_ts, sig: obs.log_sig }, logPub)) return { ok: false, why: 'log STH signature invalid under the pinned log key' };
    return { ok: true, tree_size: obs.tree_size, root_hex: obs.root_hex.toLowerCase() };
  } catch { return { ok: false, why: 'exception (fail-closed)' }; }
}

/** gossipReconcile(observations, logPub, opts?) -> reconciliation result. TOTAL.
 *  opts.trustedWitnesses = array of witness public keys (Uint8Array) — ONLY observations from these are counted.
 *  opts.proofs = { "<m>:<n>": rawProofArray } RFC-6962 consistency proofs for differing size pairs (in-memory;
 *                raw hashes do not survive JSON — this is a programmatic API, like pqgovern-anchor).
 *  Returns { consistent, equivocation, equivocations[], unresolvedPairs[], fullyResolved, witnessesCounted,
 *            trustedCount, skipped[], agreedHead }. THREE distinct states: `consistent:true` = PROVEN append-only
 *            across all counted witnesses (no equivocation AND every different-size pair resolved by a valid proof);
 *            `equivocation:true` = a fork PROVEN (exact-size or prefix-violation); neither = UNRESOLVED (a size pair
 *            lacked a proof — go fetch it). agreedHead is non-null ONLY when consistent. The different-size guarantee
 *            is conditional on the caller supplying consistency proofs; from roots alone the reconciler abstains. */
export function gossipReconcile(observations, logPub, opts = {}) {
  const base = { consistent: false, equivocation: false, equivocations: [], unresolvedPairs: [], fullyResolved: false, witnessesCounted: 0, trustedCount: 0, skipped: [], agreedHead: null };
  try {
    if (!Array.isArray(observations) || !logPub) return { ...base, skipped: [{ why: 'observations must be an array and logPub required' }] };
    const trustedList = Array.isArray(opts.trustedWitnesses) ? opts.trustedWitnesses.filter(Boolean) : [];
    const trustedByHex = new Map(); for (const pk of trustedList) { try { trustedByHex.set(bytesToHex(pk).toLowerCase(), pk); } catch { /* skip bad key */ } }
    const proofs = (opts.proofs && typeof opts.proofs === 'object') ? opts.proofs : {};

    const valid = []; const skipped = [];
    for (const obs of observations) {
      const whex = obs && typeof obs.witness === 'string' ? obs.witness.toLowerCase() : null;
      const wpub = whex ? trustedByHex.get(whex) : null;
      if (!wpub) { skipped.push({ witness: whex, why: 'witness not in the trusted set' }); continue; }
      const v = verifyWitnessObservation(obs, logPub, wpub);
      if (!v.ok) { skipped.push({ witness: whex, why: v.why }); continue; }
      valid.push({ witness: whex, tree_size: v.tree_size, root_hex: v.root_hex });
    }

    const equivocations = []; const unresolvedPairs = [];
    for (let i = 0; i < valid.length; i++) {
      for (let j = i + 1; j < valid.length; j++) {
        const a = valid[i], b = valid[j];
        if (a.tree_size === b.tree_size) {
          if (!eqHex(a.root_hex, b.root_hex)) equivocations.push({ type: 'exact-size-fork', tree_size: a.tree_size, witnessA: a.witness, witnessB: b.witness, rootA: a.root_hex, rootB: b.root_hex });
          continue;
        }
        const [sm, lg] = a.tree_size < b.tree_size ? [a, b] : [b, a];
        const proof = proofs[sm.tree_size + ':' + lg.tree_size];
        if (proof === undefined) { unresolvedPairs.push({ small: sm.tree_size, large: lg.tree_size, witnessSmall: sm.witness, witnessLarge: lg.witness, why: 'no consistency proof supplied for this size pair — reconciler abstains' }); continue; }
        const consistent = verifyConsistency(sm.tree_size, lg.tree_size, hexToBytes(sm.root_hex), hexToBytes(lg.root_hex), rawProof(proof));
        if (!consistent) equivocations.push({ type: 'prefix-violation', small: sm.tree_size, large: lg.tree_size, witnessSmall: sm.witness, witnessLarge: lg.witness });
      }
    }

    const fullyResolved = equivocations.length === 0 && unresolvedPairs.length === 0;
    let agreedHead = null;
    if (fullyResolved && valid.length > 0) { const top = valid.reduce((m, v) => (v.tree_size > m.tree_size ? v : m), valid[0]); agreedHead = { tree_size: top.tree_size, root_hex: top.root_hex }; }
    // `consistent` is a POSITIVE PROVEN verdict — the counted witnesses are provably append-only-consistent: NO
    // equivocation AND NO unresolved pair. A missing consistency proof for a size pair leaves it UNRESOLVED, so
    // `consistent` stays FALSE (council CRITICAL: never let "no fork PROVEN yet" read as "safe" — the caller must
    // gate on `consistent`, treat `unresolvedPairs` as "go fetch proofs", and only `equivocation` is "proven guilty").
    return { consistent: fullyResolved, equivocation: equivocations.length > 0, equivocations, unresolvedPairs, fullyResolved, witnessesCounted: valid.length, trustedCount: trustedByHex.size, skipped, agreedHead };
  } catch { return base; }
}

/** GovernWitness — a witness IS a fork-refusing monitor that co-signs the heads it accepts. It NEVER emits an
 *  observation for a head its own monitor rejects as a fork, so an honest witness's observations are always for
 *  heads it has consistency-verified on its own thread. */
export class GovernWitness {
  constructor({ logPub, witnessSecret, witnessPub, checkpoint = null, maxHistory = 1024 } = {}) {
    if (!logPub || !witnessSecret || !witnessPub) throw new Error('GovernWitness requires { logPub, witnessSecret, witnessPub }');
    this.logPub = logPub; this.witnessSecret = witnessSecret; this.witnessPub = witnessPub;
    this.witnessHex = bytesToHex(witnessPub);
    this.monitor = new GovernLogMonitor({ logPub, checkpoint, maxHistory });
  }
  size() { return this.monitor.size(); }
  get alerts() { return this.monitor.alerts; }
  /** observe(sth, consistencyProof?, opts?) — ingest into the fork-refusing monitor; ONLY on accept emit a signed
   *  observation for the accepted head. On a fork the witness REFUSES: { observed:false, alert, reason }. */
  observe(sth, consistencyProof = [], opts = {}) {
    const r = this.monitor.ingestSTH(sth, consistencyProof);
    if (!r.accepted) return { observed: false, alert: r.alert, reason: r.reason, observation: null };
    const head = this.monitor.currentSTH;
    const observation = witnessObserve(head, this.logPub, this.witnessSecret, this.witnessPub, { observed_ts: opts.observed_ts });
    return { observed: true, reason: r.reason, observation };
  }
}

/* ---------- self-test: node pqgovern-witness.mjs ---------- */
async function selfTest() {
  const { PQTransparencyLog } = await import('./pqsign.mjs');
  const gov = await import('./pqgovernance-record.mjs');
  const aibom = await import('./pqaibom.mjs');
  const pqeval = await import('./pqeval.mjs');
  const policy = await import('./pqgovern-policy.mjs');
  const evidence = await import('./pqgovern-evidence.mjs');
  const anchor = await import('./pqgovern-anchor.mjs');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const mk = (n) => { const k = ml_dsa87.keygen(new Uint8Array(32).fill(n)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; };
  const mkEd = (n) => { const sk = new Uint8Array(32).fill(n); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; };
  const declarant = [mk(11), mkEd(12)], evaluator = [mk(13), mkEd(14)], runner = [mk(15), mkEd(16)], owner = [mk(17), mkEd(18)];
  const rk = ['lattice', 'classical'];
  const pins = (s) => ({ requireKinds: rk, trusted: { 'ML-DSA-87': s[0].publicKey, 'Ed25519': s[1].publicKey } });
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
  const mkPack = (ts) => { const record = gov.buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-llm-prod', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry }); const signedPolicy = policy.signPolicy(policy.buildPolicy({ policy_id: 'acme-ai-release', version: 3, effective_ts: 500, expiry_ts: 5000, issuer: 'Acme Compliance', criteria: { minAibomGrade: 'B', minEvalPosture: 'C', requireDistinctSigners: true, requireDriftChecked: true } }), owner); return evidence.buildEvidencePack({ record, signedPolicy }, { created_ts: ts }); };

  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(9));
  const W1 = ml_dsa87.keygen(new Uint8Array(32).fill(21));
  const W2 = ml_dsa87.keygen(new Uint8Array(32).fill(22));
  const W3 = ml_dsa87.keygen(new Uint8Array(32).fill(23));
  const trusted = [W1.publicKey, W2.publicKey, W3.publicKey];

  // Build a growing honest log.
  const log = new PQTransparencyLog();
  anchor.anchorAdmission(mkPack(2000), log, {}); anchor.anchorAdmission(mkPack(2001), log, {});
  const sth2 = log.signedTreeHead(logKey.secretKey, { ts: 7000 });          // size 2
  anchor.anchorAdmission(mkPack(2002), log, {}); anchor.anchorAdmission(mkPack(2003), log, {});
  const sth4 = log.signedTreeHead(logKey.secretKey, { ts: 7100 });          // size 4

  // 1. witnessObserve + verifyWitnessObservation round-trip
  const o1 = witnessObserve(sth4, logKey.publicKey, W1.secretKey, W1.publicKey, { observed_ts: 7150 });
  ok(verifyWitnessObservation(o1, logKey.publicKey, W1.publicKey).ok === true, 'a witness observation of an authentic head verifies (witness sig + log sig)');

  // 2. REFUSE to co-sign a head that is not the log's
  const badLog = new PQTransparencyLog(); anchor.anchorAdmission(mkPack(9000), badLog, {});
  const foreignSth = badLog.signedTreeHead(ml_dsa87.keygen(new Uint8Array(32).fill(8)).secretKey, { ts: 1 }); // signed by a DIFFERENT key
  let threw = false; try { witnessObserve(foreignSth, logKey.publicKey, W1.secretKey, W1.publicKey); } catch { threw = true; }
  ok(threw, 'witnessObserve REFUSES a head not signed by the pinned log key (never vouches for what it did not verify)');

  // 3. HONEST QUORUM: three witnesses all observe the SAME size-4 head -> consistent, agreedHead@4
  const a1 = witnessObserve(sth4, logKey.publicKey, W1.secretKey, W1.publicKey, { observed_ts: 1 });
  const a2 = witnessObserve(sth4, logKey.publicKey, W2.secretKey, W2.publicKey, { observed_ts: 1 });
  const a3 = witnessObserve(sth4, logKey.publicKey, W3.secretKey, W3.publicKey, { observed_ts: 1 });
  const rq = gossipReconcile([a1, a2, a3], logKey.publicKey, { trustedWitnesses: trusted });
  ok(rq.consistent === true && rq.equivocation === false && rq.witnessesCounted === 3, 'honest quorum: three witnesses on the same head -> consistent, 3 counted');
  ok(rq.fullyResolved === true && rq.agreedHead && rq.agreedHead.tree_size === 4, 'honest quorum -> fully resolved, agreedHead at size 4');

  // 4. EXACT-SIZE FORK: a SPLIT-VIEW log signs a DIFFERENT size-4 root; witness B observes it -> EQUIVOCATION,
  //    and BOTH heads carry valid log signatures (undeniable: the log signed two roots at size 4).
  const log2 = new PQTransparencyLog();
  anchor.anchorAdmission(mkPack(3000), log2, {}); anchor.anchorAdmission(mkPack(3001), log2, {});
  anchor.anchorAdmission(mkPack(3002), log2, {}); anchor.anchorAdmission(mkPack(3003), log2, {});
  const fork4 = log2.signedTreeHead(logKey.secretKey, { ts: 7200 });        // size 4, DIFFERENT root, SAME log key
  const b1 = witnessObserve(sth4, logKey.publicKey, W1.secretKey, W1.publicKey, { observed_ts: 1 });
  const b2 = witnessObserve(fork4, logKey.publicKey, W2.secretKey, W2.publicKey, { observed_ts: 1 });
  const rf = gossipReconcile([b1, b2], logKey.publicKey, { trustedWitnesses: trusted });
  ok(rf.equivocation === true && rf.equivocations[0].type === 'exact-size-fork' && rf.equivocations[0].tree_size === 4, 'split-view: two trusted witnesses, different roots at size 4 -> EXACT-SIZE-FORK equivocation');
  ok(rf.consistent === false && rf.agreedHead === null, 'a proven fork -> consistent:false, no agreedHead');

  // 5. PREFIX VIOLATION with a proof: witness@2 (log) vs witness@4 (DIVERGENT log2) + a proof that cannot bind.
  const c2 = witnessObserve(sth2, logKey.publicKey, W1.secretKey, W1.publicKey, { observed_ts: 1 });     // log @2
  const c4 = witnessObserve(fork4, logKey.publicKey, W2.secretKey, W2.publicKey, { observed_ts: 1 });    // log2 @4 (divergent)
  const badProof = log2.consistency(2).proof;   // a real 2->4 proof for log2 — but c2's root is log's size-2 root, not log2's
  const rp = gossipReconcile([c2, c4], logKey.publicKey, { trustedWitnesses: trusted, proofs: { '2:4': badProof } });
  ok(rp.equivocation === true && rp.equivocations[0].type === 'prefix-violation', 'different sizes across divergent histories + a non-binding proof -> PREFIX-VIOLATION equivocation');

  // 6. CONSISTENT different sizes WITH a valid proof: witness@2 and witness@4 of the SAME log -> not a fork.
  const d2 = witnessObserve(sth2, logKey.publicKey, W1.secretKey, W1.publicKey, { observed_ts: 1 });
  const d4 = witnessObserve(sth4, logKey.publicKey, W2.secretKey, W2.publicKey, { observed_ts: 1 });
  const goodProof = log.consistency(2).proof;   // genuine 2->4 proof for THIS log
  const rc = gossipReconcile([d2, d4], logKey.publicKey, { trustedWitnesses: trusted, proofs: { '2:4': goodProof } });
  ok(rc.consistent === true && rc.equivocation === false && rc.fullyResolved === true && rc.agreedHead.tree_size === 4, 'same-log different sizes + valid consistency proof -> consistent, agreedHead@4');

  // 7. UNRESOLVED: different sizes, NO proof -> reconciler abstains. `consistent` is FALSE (council CRITICAL:
  //    a missing proof must NOT read as "safe"); it is neither proven-consistent nor proven-forked.
  const ru = gossipReconcile([d2, d4], logKey.publicKey, { trustedWitnesses: trusted });
  ok(ru.consistent === false && ru.equivocation === false && ru.unresolvedPairs.length === 1 && ru.fullyResolved === false && ru.agreedHead === null, 'different sizes with NO proof -> consistent:FALSE, unresolved pair, abstain (missing proof is not "safe")');

  // 8. UNTRUSTED witness ignored; 9. REATTRIBUTION rejected; 10. TAMPER rejected
  const Wx = ml_dsa87.keygen(new Uint8Array(32).fill(99));
  const ox = witnessObserve(sth4, logKey.publicKey, Wx.secretKey, Wx.publicKey, { observed_ts: 1 });
  const rx = gossipReconcile([a1, ox], logKey.publicKey, { trustedWitnesses: trusted });
  ok(rx.witnessesCounted === 1 && rx.skipped.some((s) => /not in the trusted set/.test(s.why)), 'an observation from an untrusted witness is SKIPPED, not counted');
  ok(verifyWitnessObservation({ ...o1, witness: W2.publicKey ? bytesToHex(W2.publicKey) : '' }, logKey.publicKey, W1.publicKey).ok === false, 'reattribution: obs.witness claims W2 but verified against W1 -> rejected');
  const tampered = { ...o1, root_hex: 'b'.repeat(64) };
  ok(verifyWitnessObservation(tampered, logKey.publicKey, W1.publicKey).ok === false, 'a tampered root (witness sig + log sig no longer bind) -> rejected');

  // 11. GovernWitness class: a witness REFUSES to observe a fork (never co-signs it)
  const gw = new GovernWitness({ logPub: logKey.publicKey, witnessSecret: W1.secretKey, witnessPub: W1.publicKey });
  const g0 = gw.observe(sth2, [], { observed_ts: 1 });
  ok(g0.observed === true && g0.observation && verifyWitnessObservation(g0.observation, logKey.publicKey, W1.publicKey).ok === true, 'GovernWitness observes an accepted head and emits a valid observation');
  const gForked = gw.observe(fork4, [], { observed_ts: 1 });   // divergent same-size-family head with no consistency proof
  ok(gForked.observed === false && gForked.observation === null, 'GovernWitness REFUSES to observe a head its fork-refusing monitor rejects (no attestation for a fork)');

  // 12. SAME trusted witness co-signs TWO conflicting size-4 roots (council-confirmed: this proves the LOG
  //     equivocated — the witness is only the messenger; both heads carry valid log sigs). Detected as a fork.
  const s1 = witnessObserve(sth4, logKey.publicKey, W1.secretKey, W1.publicKey, { observed_ts: 1 });
  const s2 = witnessObserve(fork4, logKey.publicKey, W1.secretKey, W1.publicKey, { observed_ts: 2 });   // SAME witness W1
  const rs = gossipReconcile([s1, s2], logKey.publicKey, { trustedWitnesses: trusted });
  ok(rs.equivocation === true && rs.equivocations[0].type === 'exact-size-fork' && rs.equivocations[0].witnessA === rs.equivocations[0].witnessB, 'one trusted witness signing two conflicting size-4 roots -> exact-size-fork (the LOG equivocated)');

  // 13. SAFE-INTEGER guard: an observation with an unsafe-integer tree_size (> 2^53) -> rejected (canon-collision defense)
  ok(verifyWitnessObservation({ ...o1, tree_size: Number.MAX_SAFE_INTEGER + 2 }, logKey.publicKey, W1.publicKey).ok === false, 'an unsafe-integer tree_size (> 2^53) -> rejected (JSON canon rounding / replay defense)');

  // 14. fail-closed on garbage
  ok(gossipReconcile(null, logKey.publicKey).equivocation === false && gossipReconcile([{}], logKey.publicKey, { trustedWitnesses: trusted }).witnessesCounted === 0, 'malformed inputs -> fail-closed, nothing counted');
  ok(verifyWitnessObservation(null, logKey.publicKey, W1.publicKey).ok === false && verifyWitnessObservation({}, logKey.publicKey, W1.publicKey).ok === false, 'malformed observation -> verify fail-closed');

  console.log('pqgovern-witness self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgovern-witness\.mjs$/.test(process.argv[1] || '')) selfTest();
