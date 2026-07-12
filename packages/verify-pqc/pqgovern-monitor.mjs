/*!
 * pqgovern-monitor — a stateful transparency MONITOR for the AI-governance admission log (reference, DRAFT).
 *
 * pqgovern-anchor lets you PROVE a single admission was recorded (inclusion under a pinned STH). This is
 * the operational complement: a running watcher that ingests successive signed tree heads (STHs) from the
 * log, verifies each is a **consistent append-only extension** of the last (RFC-6962 consistency proofs),
 * and is **fork-refusing** — on an equivocation or history rewrite it RAISES AN ALERT and REFUSES the new
 * head, keeping the last consistency-verified one (fail-closed, never follows a fork). A relying party can
 * then check an admission is anchored in a head the monitor has actually verified (`onMonitoredChain`).
 *
 * HONEST SCOPE (claim-hygiene LAW): the monitor holds the log **append-only ACROSS THE STHs IT OBSERVES**,
 * under a log key the operator PINS — it does NOT prove the log is COMPLETE, nor that the log shows the
 * SAME head to everyone (a split-view / withholding log is only caught by a WITNESS/GOSSIP quorum — see
 * pqkt). Bootstrap the first head from a trusted out-of-band `checkpoint`; WITHOUT one it is trust-on-
 * first-use on the pinned key (a documented weakness — a fabricated genesis head could desync it). The
 * RFC-6962 consistency ALGORITHM it relies on is machine-checked (formal/rfc6962_consistency_algo_z3) —
 * that proves the algorithm, not this JS binding, which remains pre-audit. It records existence + order,
 * never a verdict; admissions are re-derived by pqgovern-anchor. Every method is TOTAL/fail-closed.
 *  Self-test: node pqgovern-monitor.mjs
 */
import { hexToBytes } from '@noble/hashes/utils.js';
import { verifySTH, verifyConsistency } from './pqsign.mjs';
import { verifyLogConsistency, verifyAnchoredAdmission } from './pqgovern-anchor.mjs';

const isInt = (n) => Number.isInteger(n);
const isHex = (s) => typeof s === 'string' && s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
const eqHex = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
const rawProof = (p) => (Array.isArray(p) ? p.map((x) => (x && x.sibling) ? x.sibling : x) : []);

export class GovernLogMonitor {
  /** new GovernLogMonitor({ logPub, checkpoint?, maxHistory? }) — logPub is the PINNED log public key. Supply
   *  an out-of-band trusted `checkpoint` = {tree_size, root_hex} to bootstrap WITHOUT blind trust-on-first-use
   *  (a malicious log can otherwise serve a fabricated huge-size genesis head and desync the monitor). */
  constructor({ logPub, checkpoint = null, maxHistory = 1024 } = {}) {
    if (!logPub) throw new Error('GovernLogMonitor requires a pinned log public key (logPub)');
    if (checkpoint != null) {
      if (!isInt(checkpoint.tree_size) || checkpoint.tree_size < 0 || !isHex(checkpoint.root_hex)) throw new Error('checkpoint must be { tree_size: int>=0, root_hex: hex }');
      this.checkpoint = { tree_size: checkpoint.tree_size, root_hex: checkpoint.root_hex };
    } else this.checkpoint = null;
    this.logPub = logPub;
    this.currentSTH = null;      // last consistency-verified head
    this.history = [];           // accepted STHs, in order (bounded to maxHistory — the memory hog)
    this.acceptedRoots = new Set(); // "tree_size:root_hex" of every accepted head (small strings; kept complete for isOnChain)
    this.alerts = [];            // equivocation / rewrite alerts (fail-closed: monitor keeps last-good)
    this.maxHistory = isInt(maxHistory) && maxHistory > 0 ? maxHistory : 1024;
  }

  size() { return this.currentSTH ? this.currentSTH.tree_size : 0; }
  isOnChain(sth) { return !!(sth && isInt(sth.tree_size) && isHex(sth.root_hex) && this.acceptedRoots.has(sth.tree_size + ':' + sth.root_hex.toLowerCase())); }

  _accept(sth) {
    // atomic-ish: record the (complete, small) root key BEFORE mutating the head, so a throw can't leave the
    // head advanced without its root recorded. history (full STH objects) is bounded to cap memory.
    this.acceptedRoots.add(sth.tree_size + ':' + sth.root_hex.toLowerCase());
    this.currentSTH = sth;
    this.history.push(sth);
    if (this.history.length > this.maxHistory) this.history.shift();
    return { accepted: true, alert: null, reason: 'accepted (consistent append-only)', size: this.size() };
  }
  _reject(reason) { return { accepted: false, alert: null, reason, size: this.size() }; }
  _flag(sth, reason) { this.alerts.push({ kind: 'equivocation', tree_size: isInt(sth && sth.tree_size) ? sth.tree_size : null, reason }); return { accepted: false, alert: 'EQUIVOCATION', reason, size: this.size() }; }

  /** ingestSTH(sth, consistencyProof?) — verify + append-only-extend the monitored chain. TOTAL.
   *  Returns { accepted, alert, reason, size }. A fork/rewrite -> accepted:false + alert:'EQUIVOCATION',
   *  and the monitor KEEPS its last-good head (fork-refusing). consistencyProof = pqsign log.consistency
   *  proof from currentSize -> the new size (required when the tree grows). */
  ingestSTH(sth, consistencyProof = []) {
    try {
      if (!sth || !isInt(sth.tree_size) || sth.tree_size < 0 || !isHex(sth.root_hex)) return this._reject('malformed STH (tree_size int>=0 + hex root required)');
      if (!verifySTH(sth, this.logPub)) return this._reject('STH is not authentic under the pinned log key');
      // BOOTSTRAP: with a trusted out-of-band checkpoint, the first head must MATCH or consistently EXTEND it
      // (no blind TOFU — council: a fabricated genesis head would otherwise desync the monitor).
      if (this.currentSTH === null) {
        const cp = this.checkpoint;
        if (!cp || cp.tree_size < 1) return this._accept(sth);   // no (usable) checkpoint -> TOFU on the pinned key (documented weakness)
        if (sth.tree_size === cp.tree_size) return eqHex(sth.root_hex, cp.root_hex) ? this._accept(sth) : this._flag(sth, 'first STH root does not match the trusted checkpoint at size ' + cp.tree_size + ' (fabricated bootstrap)');
        if (sth.tree_size < cp.tree_size) return this._reject('first STH is older than the trusted checkpoint — rejected');
        return verifyConsistency(cp.tree_size, sth.tree_size, hexToBytes(cp.root_hex), hexToBytes(sth.root_hex), rawProof(consistencyProof))
          ? this._accept(sth) : this._flag(sth, 'first STH is not a consistent extension of the trusted checkpoint (fabricated bootstrap)');
      }
      if (sth.tree_size === this.currentSTH.tree_size) {
        return eqHex(sth.root_hex, this.currentSTH.root_hex)
          ? { accepted: true, alert: null, reason: 'same head (no-op)', size: this.size() }
          : this._flag(sth, 'the log served TWO roots for tree size ' + sth.tree_size + ' (exact-size fork)');
      }
      if (sth.tree_size < this.currentSTH.tree_size) return this._reject('non-monotonic STH (older than the current head) — ignored');
      // freshness: a well-behaved log never BACKDATES a newer head (the ts is signed) — a regression is refused.
      if (isInt(sth.ts) && isInt(this.currentSTH.ts) && sth.ts < this.currentSTH.ts) return this._reject('STH timestamp regressed vs the current head (freshness violation) — refused');
      const c = verifyLogConsistency(this.currentSTH, sth, Array.isArray(consistencyProof) ? consistencyProof : [], this.logPub);
      return c.consistent ? this._accept(sth) : this._flag(sth, 'append-only consistency FAILED (history rewrite / prefix mutation): ' + c.why);
    } catch { return this._reject('exception (fail-closed)'); }
  }

  /** verifyAdmission(anchor, opts) — re-derive the admission (pqgovern-anchor) AND confirm its STH is a
   *  head this monitor has consistency-verified. `admit` stays the sole verdict; `onMonitoredChain` says
   *  the inclusion is against a head on the monitored append-only chain. TOTAL. */
  verifyAdmission(anchor, opts = {}) {
    try {
      const av = verifyAnchoredAdmission(anchor, { ...opts, logPub: this.logPub });
      const onMonitoredChain = !!(anchor && anchor.sth && this.isOnChain(anchor.sth));
      return { ...av, onMonitoredChain };
    } catch { return { admit: false, anchored: false, integrityOk: false, artifactsVerified: false, onMonitoredChain: false, why: 'exception (fail-closed)', evidence: null, anchoredAt: null }; }
  }
}

/* ---------- self-test: node pqgovern-monitor.mjs ---------- */
async function selfTest() {
  const { PQTransparencyLog } = await import('./pqsign.mjs');
  const gov = await import('./pqgovernance-record.mjs');
  const aibom = await import('./pqaibom.mjs');
  const pqeval = await import('./pqeval.mjs');
  const policy = await import('./pqgovern-policy.mjs');
  const evidence = await import('./pqgovern-evidence.mjs');
  const anchor = await import('./pqgovern-anchor.mjs');
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
  const mkPack = (ts) => { const record = gov.buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-llm-prod', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry }); const signedPolicy = policy.signPolicy(policy.buildPolicy({ policy_id: 'acme-ai-release', version: 3, effective_ts: 500, expiry_ts: 5000, issuer: 'Acme Compliance', criteria: { minAibomGrade: 'B', minEvalPosture: 'C', requireDistinctSigners: true, requireDriftChecked: true } }), owner); return { record, pack: evidence.buildEvidencePack({ record, signedPolicy }, { created_ts: ts }) }; };
  const vopts = { aibomSealOpts, evalSealOpts, traceSealOpts, policySealOpts: ownerSealOpts, suiteRegistry: registry, loadedComponents: manifest.components, atTs: 1000, minVersion: 3, requireWindow: true, requireDistinctSigners: true };

  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(9));
  const log = new PQTransparencyLog();
  const mon = new GovernLogMonitor({ logPub: logKey.publicKey });

  // 1. ingest a growing, consistent chain of STHs -> all accepted, size tracks
  anchor.anchorAdmission(mkPack(2000).pack, log, {});
  const sth1 = log.signedTreeHead(logKey.secretKey, { ts: 7000 });
  ok(mon.ingestSTH(sth1).accepted === true && mon.size() === 1, 'first STH accepted (TOFU on pinned key), size 1');
  anchor.anchorAdmission(mkPack(2001).pack, log, {});
  anchor.anchorAdmission(mkPack(2002).pack, log, {});
  const sth3 = log.signedTreeHead(logKey.secretKey, { ts: 7100 });
  ok(mon.ingestSTH(sth3, log.consistency(1).proof).accepted === true && mon.size() === 3, 'a consistent append-only extension (1 -> 3) accepted, size 3');
  ok(mon.ingestSTH(sth3, []).accepted === true, 'the same current head re-ingested -> no-op accept');

  // 2. EXACT-SIZE FORK: a validly-signed STH at a size we already have, different root -> ALERT + refuse
  //    (build a second, DIVERGENT log with different content, sign at size 3 with the SAME log key)
  const log2 = new PQTransparencyLog();
  anchor.anchorAdmission(mkPack(3000).pack, log2, {}); anchor.anchorAdmission(mkPack(3001).pack, log2, {}); anchor.anchorAdmission(mkPack(3002).pack, log2, {});
  const forkSth3 = log2.signedTreeHead(logKey.secretKey, { ts: 7200 });   // size 3, DIFFERENT root
  const fr = mon.ingestSTH(forkSth3, []);
  ok(fr.accepted === false && fr.alert === 'EQUIVOCATION' && mon.alerts.length === 1, 'a divergent same-size head -> EQUIVOCATION alert, REFUSED');
  ok(mon.size() === 3 && mon.currentSTH.root_hex === sth3.root_hex, 'fork-refusing: the monitor KEEPS its last consistency-verified head');

  // 3. NON-CONSISTENT growth (empty proof for a real extension) -> ALERT + refuse
  anchor.anchorAdmission(mkPack(2003).pack, log, {});
  const sth4 = log.signedTreeHead(logKey.secretKey, { ts: 7300 });        // size 4, genuine
  ok(mon.ingestSTH(sth4, []).accepted === false, 'a grown STH with NO consistency proof -> REFUSED (append-only not proven)');
  ok(mon.ingestSTH(sth4, log.consistency(3).proof).accepted === true && mon.size() === 4, 'the same STH WITH a valid consistency proof -> accepted, size 4');

  // 4. wrong log key / non-monotonic / garbage -> fail-closed
  const wrong = new GovernLogMonitor({ logPub: ml_dsa87.keygen(new Uint8Array(32).fill(8)).publicKey });
  ok(wrong.ingestSTH(sth1).accepted === false, 'an STH not signed by the pinned key -> REFUSED');
  ok(mon.ingestSTH(sth1, []).accepted === false, 'an older (non-monotonic) STH -> ignored (kept current)');
  ok(mon.ingestSTH(null).accepted === false && mon.ingestSTH({}).accepted === false, 'malformed STH -> fail-closed');
  let threw = (f) => { try { f(); return false; } catch { return true; } };
  ok(threw(() => new GovernLogMonitor({})), 'a monitor with no pinned log key -> constructor throws');

  // 5. verifyAdmission against the MONITORED chain: an admission anchored in an accepted head is onMonitoredChain
  const log3 = new PQTransparencyLog();
  const mon3 = new GovernLogMonitor({ logPub: logKey.publicKey });
  const { pack } = mkPack(5000);
  const { index } = anchor.anchorAdmission(pack, log3, { anchored_ts: 5100 });
  const sthA = log3.signedTreeHead(logKey.secretKey, { ts: 8000 });
  mon3.ingestSTH(sthA);
  const av = mon3.verifyAdmission({ pack, entry: log3.entries[index], inclusion: log3.inclusion(index), sth: sthA }, vopts);
  ok(av.admit === true && av.anchored === true && av.onMonitoredChain === true, 'an admission anchored in a MONITORED head -> admit + anchored + onMonitoredChain');
  const offChain = mon3.verifyAdmission({ pack, entry: log3.entries[index], inclusion: log3.inclusion(index), sth: forkSth3 }, vopts);
  ok(offChain.onMonitoredChain === false, "an admission whose STH the monitor never accepted -> onMonitoredChain false");

  // 6. CHECKPOINT bootstrap (council): the first head must match / consistently extend a trusted checkpoint.
  const clog = new PQTransparencyLog();
  anchor.anchorAdmission(mkPack(6000).pack, clog, {}); const csth1 = clog.signedTreeHead(logKey.secretKey, { ts: 9000 });   // size 1
  anchor.anchorAdmission(mkPack(6001).pack, clog, {}); anchor.anchorAdmission(mkPack(6002).pack, clog, {});
  const csth3 = clog.signedTreeHead(logKey.secretKey, { ts: 9100 });                                                       // size 3
  const monA = new GovernLogMonitor({ logPub: logKey.publicKey, checkpoint: { tree_size: 1, root_hex: csth1.root_hex } });
  ok(monA.ingestSTH(csth3, clog.consistency(1).proof).accepted === true, 'checkpoint: a first STH consistently extending the trusted checkpoint (1 -> 3) is accepted');
  const monB = new GovernLogMonitor({ logPub: logKey.publicKey, checkpoint: { tree_size: 3, root_hex: csth3.root_hex } });
  ok(monB.ingestSTH(forkSth3, []).accepted === false && monB.alerts.length === 1, 'checkpoint: a fabricated genesis head (wrong root at the checkpoint size) -> REFUSED + alert (no blind TOFU)');
  ok(new GovernLogMonitor({ logPub: logKey.publicKey, checkpoint: { tree_size: 3, root_hex: csth3.root_hex } }).ingestSTH(csth1, []).accepted === false, 'checkpoint: a first STH older than the trusted checkpoint -> REFUSED');

  // 7. strict hex root_hex; 8. timestamp freshness; 9. bounded history with correct isOnChain
  ok(mon3.ingestSTH({ tree_size: 99, root_hex: 'not-hex!', ts: 1 }).accepted === false, 'a non-hex root_hex -> REJECTED (strict crypto-material validation)');
  const tlog = new PQTransparencyLog(); const tmon = new GovernLogMonitor({ logPub: logKey.publicKey });
  anchor.anchorAdmission(mkPack(7000).pack, tlog, {}); tmon.ingestSTH(tlog.signedTreeHead(logKey.secretKey, { ts: 5000 }));
  anchor.anchorAdmission(mkPack(7001).pack, tlog, {});
  ok(tmon.ingestSTH(tlog.signedTreeHead(logKey.secretKey, { ts: 4000 }), tlog.consistency(1).proof).accepted === false, 'a consistent extension with a REGRESSED timestamp -> REFUSED (freshness)');
  const blog = new PQTransparencyLog(); const bmon = new GovernLogMonitor({ logPub: logKey.publicKey, maxHistory: 2 });
  anchor.anchorAdmission(mkPack(8000).pack, blog, {}); const bs1 = blog.signedTreeHead(logKey.secretKey, { ts: 1 }); bmon.ingestSTH(bs1);
  for (let i = 1; i <= 4; i++) { anchor.anchorAdmission(mkPack(8000 + i).pack, blog, {}); bmon.ingestSTH(blog.signedTreeHead(logKey.secretKey, { ts: 1 + i }), blog.consistency(bmon.size()).proof); }
  ok(bmon.history.length <= 2 && bmon.size() === 5, 'history array bounded to maxHistory (memory), head advanced to size 5');
  ok(bmon.isOnChain(bs1) === true, 'isOnChain still TRUE for an OLD accepted head (acceptedRoots kept complete despite the bounded history array)');

  console.log('pqgovern-monitor self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgovern-monitor\.mjs$/.test(process.argv[1] || '')) selfTest();
