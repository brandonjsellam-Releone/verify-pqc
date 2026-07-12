/*!
 * pqgovern-witness-service — runnable GOVERNANCE-log WITNESS node + gossip reconciler (reference, DRAFT).
 *
 * Makes the pqgovern-witness quorum DEPLOY-ready: the owner runs >=1 INDEPENDENT witness instance on independent
 * hosts (the trust root is that they are genuinely separate operators), and a relying party runs a reconciler that
 * cross-checks the witnesses' signed observations to catch a log presenting a SPLIT VIEW (equivocation) — the attack
 * a single fork-refusing monitor is structurally blind to. NO autonomous deploy — see the DEPLOY notes at the bottom.
 *
 * A GovernWitnessNode wraps pqgovern-witness.GovernWitness (itself a fork-refusing GovernLogMonitor that co-signs the
 * heads it accepts) with a DURABLE state store: `currentSTH`/`acceptedRoots`/`history` MUST survive restarts — a
 * witness that FORGETS its last-good head reverts to trust-on-first-use and could be tricked into co-signing a fork
 * after a restart (the durability lesson carried over from witness-service). State is persisted after every accepted
 * observation and reloaded on construction; a store whose set() throws (or is async) makes observe() FAIL CLOSED
 * rather than return an unpersisted co-signature.
 *
 * Honest scope (claim-hygiene LAW): still a REFERENCE. The trust comes from INDEPENDENT witnesses actually gossiping
 * into the SAME reconcile; the reconciler proves SAFETY (the log equivocated) — never LIVENESS/COMPLETENESS. The
 * store here is pluggable (default in-memory); the owner supplies a durable file/DB store. RFC-6962 consistency
 * proofs are raw hashes that do NOT survive JSON, so the HTTP boundary hex-decodes them (the programmatic classes
 * stay on raw bytes). The request core is hardened for open exposure — TOTAL handler (bad input -> 400, never a
 * process crash), bounded+deduped reconciler (no memory/CPU DoS), a body-size cap (413), atomic persist (rollback
 * on failure), and a signature-verified state restore (a corrupt store can't poison the head). PRODUCTION still
 * needs the owner to add: auth + TLS (endpoints are unauthenticated by design — a proxy concern), and a store whose
 * durability model fits their deployment (this reference uses a SYNCHRONOUS store so a sync observe() can confirm
 * durability; a high-throughput deployment needs an async store + serialized head updates — out of scope here).
 * GET /state exposes only PUBLIC transparency data (STH/roots) by design. Self-test: node pqgovern-witness-service.mjs
 */
import { GovernWitness, gossipReconcile, verifyWitnessObservation } from './pqgovern-witness.mjs';
import { verifySTH } from './pqsign.mjs';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// dump the fork-refusing monitor's durable state (last-good head + accepted roots + bounded history). Arrays are
// COPIED so a snapshot can't be mutated by a subsequent observe (atomic-rollback correctness).
const dumpState = (node) => { const m = node.witness.monitor; return { currentSTH: m.currentSTH, history: [...m.history], acceptedRoots: [...m.acceptedRoots], alerts: [...m.alerts] }; };
// restoreState: UNCONDITIONAL reset to OUR OWN trusted snapshot (used for atomic rollback on a persist failure).
const restoreState = (node, s) => { const m = node.witness.monitor; m.currentSTH = (s && s.currentSTH) || null; m.history = (s && Array.isArray(s.history)) ? [...s.history] : []; m.acceptedRoots = new Set((s && Array.isArray(s.acceptedRoots)) ? s.acceptedRoots : []); m.alerts = (s && Array.isArray(s.alerts)) ? [...s.alerts] : []; };
// loadState: restore from the (UNtrusted) durable store on (re)start — but NEVER blind-trust a restored head. Verify
// its log-STH signature under the pinned log key (council/Qwen: a corrupted/tampered store could otherwise poison
// currentSTH and make the node co-sign a fork on restart). An invalid restored head -> leave the monitor at its
// constructor state (checkpoint/TOFU), never load a bad head. history entries are likewise sig-filtered.
const loadState = (node, s) => {
  if (!s || !s.currentSTH) return;
  const m = node.witness.monitor, logPub = node.witness.logPub;
  if (!verifySTH(s.currentSTH, logPub)) return;   // corrupt/tampered restored head -> refuse it (stay at constructor state)
  m.currentSTH = s.currentSTH;
  m.history = (Array.isArray(s.history) ? s.history : []).filter((h) => verifySTH(h, logPub));
  m.acceptedRoots = new Set((Array.isArray(s.acceptedRoots) ? s.acceptedRoots : []).filter((k) => typeof k === 'string'));
  m.alerts = Array.isArray(s.alerts) ? s.alerts : [];
};
const memStore = () => { let s = null; return { get: () => s, set: (v) => { s = v; } }; }; // owner replaces with a durable file/DB store
// HTTP boundary: a consistency proof arrives as an array of hex strings (raw bytes don't survive JSON) -> decode to
// Uint8Array for the byte-native monitor/verifyConsistency. Tolerates already-decoded bytes. May throw on bad hex —
// serviceHandle wraps this in try/catch (an uncaught throw in the http callback would KILL the Node process).
const decodeProof = (p) => (Array.isArray(p) ? p.map((h) => (typeof h === 'string' ? hexToBytes(h) : h)) : []);
const MAX_BODY_BYTES = 256 * 1024;   // http adapter body cap (council/Qwen: an unbounded body OOM-kills before parse)

export class GovernWitnessNode {
  // store: { get(): state|null, set(state): void } — MUST be durable in production (the no-fork guarantee depends on it).
  constructor({ secretKey, publicKey, logPub, store, checkpoint = null, maxHistory = 1024 }) {
    if (!secretKey || !publicKey || !logPub) throw new Error('GovernWitnessNode requires { secretKey, publicKey, logPub }');
    this.witness = new GovernWitness({ logPub, witnessSecret: secretKey, witnessPub: publicKey, checkpoint, maxHistory });
    this.store = store || memStore();
    loadState(this, this.store.get()); // restore durable state on (re)start so a restarted node keeps refusing forks
  }
  /** observe(sth, consistencyProof?, opts?) — ATOMIC: ingest into the fork-refusing witness; ONLY on accept emit a
   *  signed observation AND durably persist. If persistence throws or is async, ROLL BACK the in-memory monitor to
   *  the pre-observe snapshot so in-memory state never diverges from durable state (council/DeepSeek: otherwise a
   *  failed persist leaves the monitor advanced in memory but not on disk → a restart forgets the head → a fork
   *  could be accepted). Either { advanced AND persisted } or { neither } — never a half state. */
  observe(sth, consistencyProof = [], opts = {}) {
    const snapshot = dumpState(this);   // OUR trusted pre-observe state (arrays copied)
    const r = this.witness.observe(sth, consistencyProof, opts);
    if (r.observed) {
      try {
        const p = this.store.set(dumpState(this));
        if (p && typeof p.then === 'function') { restoreState(this, snapshot); return { observed: false, reason: 'async store unsupported by sync observe() — durability not confirmed (rolled back)', observation: null }; }
      } catch (e) { restoreState(this, snapshot); return { observed: false, reason: 'observation not durably persisted (rolled back): ' + ((e && e.message) || e), observation: null }; }
    }
    return r;
  }
  size() { return this.witness.size(); }
  state() { return dumpState(this); }
}

/** GovernGossipReconciler — a relying party accumulates witness observations (from the CONFIGURED trusted set) and
 *  re-runs gossipReconcile on each submit. Trusted witness PUBLIC KEYS (bytes) are server-side config, not caller
 *  input. Proofs (raw bytes) accumulate for different-size pairs. */
export class GovernGossipReconciler {
  constructor(logPub, trustedWitnessPubs, { maxObservations = 4096 } = {}) {
    if (!logPub) throw new Error('GovernGossipReconciler requires a pinned log public key');
    this.logPub = logPub;
    this.trusted = Array.isArray(trustedWitnessPubs) ? trustedWitnessPubs.filter(Boolean) : [];
    this.trustedByHex = new Map();
    for (const pk of this.trusted) { try { this.trustedByHex.set(bytesToHex(pk).toLowerCase(), pk); } catch { /* skip bad key */ } }
    this.observations = [];
    this.seen = new Set();          // "witness:size:root" dedup — a witness re-submitting the same head can't inflate state
    this.proofs = {};
    this.maxObservations = maxObservations > 0 ? maxObservations : 4096;
  }
  /** submit(observation, proofs?) — add an observation (+ optional {"m:n": rawProof} consistency proofs) and return
   *  the running reconciliation. HARDENED (council/DeepSeek+Qwen, DoS): only a TRUSTED + cryptographically VALID
   *  observation is stored, deduped by (witness,size,root), and capped at maxObservations — so an open endpoint
   *  cannot be memory/CPU-exhausted by spam or duplicates. Proofs are FIRST-WRITE-WINS (a later caller cannot clobber
   *  an accepted proof). proofs values are RAW byte arrays (programmatic); the HTTP layer decodes hex first. */
  submit(observation, proofs) {
    if (proofs && typeof proofs === 'object') for (const [k, v] of Object.entries(proofs)) if (!(k in this.proofs)) this.proofs[k] = v;
    if (observation && typeof observation.witness === 'string') {
      const wpub = this.trustedByHex.get(observation.witness.toLowerCase());
      if (wpub && verifyWitnessObservation(observation, this.logPub, wpub).ok) {   // trusted AND valid — else DROPPED (not stored)
        const key = observation.witness.toLowerCase() + ':' + observation.tree_size + ':' + String(observation.root_hex).toLowerCase();
        if (!this.seen.has(key) && this.observations.length < this.maxObservations) { this.seen.add(key); this.observations.push(observation); }
      }
    }
    return this.scan();
  }
  scan() { return gossipReconcile(this.observations, this.logPub, { trustedWitnesses: this.trusted, proofs: this.proofs }); }
}

/** serviceHandle(node, reconciler, method, path, body) — framework-free request core (testable without a server).
 *  Witness-node routes: GET /healthz, GET /state, POST /observe. Reconciler routes: POST /reconcile, GET /reconcile.
 *  body is an already-parsed object; consistency proofs arrive hex-encoded and are decoded here. */
export function serviceHandle(node, reconciler, method, path, body) {
  try {   // TOTAL: malformed hex proofs (decodeProof -> hexToBytes) throw; an uncaught throw in the http callback would
          // KILL the Node process (council/Qwen). Catch everything and return 400 rather than crash.
    if (method === 'GET' && path === '/healthz')
      return { status: 200, body: { ok: true, witness_pub: bytesToHex(node.witness.witnessPub), size: node.size(), last: node.witness.monitor.currentSTH } };
    if (method === 'GET' && path === '/state')
      return { status: 200, body: node.state() };
    if (method === 'POST' && path === '/observe') {
      if (!body || !body.sth) return { status: 400, body: { error: 'missing sth' } };
      const r = node.observe(body.sth, decodeProof(body.consistencyProof), { observed_ts: body.observed_ts });
      return r.observed ? { status: 200, body: r.observation } : { status: 409, body: { error: r.reason, alert: r.alert || null } };
    }
    if (reconciler && method === 'POST' && path === '/reconcile') {
      if (!body || !body.observation) return { status: 400, body: { error: 'missing observation' } };
      const proofs = body.proofs && typeof body.proofs === 'object'
        ? Object.fromEntries(Object.entries(body.proofs).map(([k, v]) => [k, decodeProof(v)])) : undefined;
      return { status: 200, body: reconciler.submit(body.observation, proofs) };
    }
    if (reconciler && method === 'GET' && path === '/reconcile')
      return { status: 200, body: reconciler.scan() };
    return { status: 404, body: { error: 'not found' } };
  } catch (e) { return { status: 400, body: { error: 'bad request: ' + ((e && e.message) || 'malformed input') } }; }
}

// thin Node http adapter — owner wires into http.createServer(serviceHandler(node, reconciler)).listen(PORT).
export function serviceHandler(node, reconciler = null) {
  return (req, res) => {
    let data = '', tooBig = false;
    req.on('data', (c) => {
      if (tooBig) return;
      data += c;
      if (data.length > MAX_BODY_BYTES) {   // cap the body BEFORE it grows unbounded (council/Qwen: OOM-kill vector)
        tooBig = true; res.writeHead(413, { 'content-type': 'application/json' }); res.end('{"error":"payload too large"}'); try { req.destroy(); } catch { /* ignore */ }
      }
    });
    req.on('end', () => {
      if (tooBig) return;
      let body = null; try { body = data ? JSON.parse(data) : null; } catch { res.writeHead(400, { 'content-type': 'application/json' }); return res.end('{"error":"bad json"}'); }
      const out = serviceHandle(node, reconciler, req.method, (req.url || '').split('?')[0], body);
      res.writeHead(out.status, { 'content-type': 'application/json' }); res.end(JSON.stringify(out.body));
    });
  };
}

/* ---------- self-test: node pqgovern-witness-service.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { PQTransparencyLog } = await import('./pqsign.mjs');
  const gov = await import('./pqgovernance-record.mjs');
  const aibom = await import('./pqaibom.mjs');
  const pqeval = await import('./pqeval.mjs');
  const policy = await import('./pqgovern-policy.mjs');
  const evidence = await import('./pqgovern-evidence.mjs');
  const anchor = await import('./pqgovern-anchor.mjs');

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
  const run = { steps: [{ kind: 'prompt', actor: 'user', content: 'q' }, { kind: 'model_output', actor: 'acme-llm', model_id: 'acme-llm', content: 'a', tokens: { input: 1, output: 1 } }] };
  const registry = new Set([pqeval.suiteHash(pqeval.normalizeEval({ eval_suite: evalRec.eval_suite }).eval_suite)]);
  const mkPack = (ts) => { const record = gov.buildGovernanceRecord({ manifest, evalRec, run }, { aibomSigners: declarant, evalSigners: evaluator, traceSigners: runner, assuranceLevel: aibom.ASSURANCE.bound, subject: 'acme-llm-prod', declarant: 'Acme Inc', evaluator: 'EvalLab', runner: 'acme-runtime', generated_ts: 1000, suiteRegistry: registry }); const signedPolicy = policy.signPolicy(policy.buildPolicy({ policy_id: 'acme', version: 3, effective_ts: 500, expiry_ts: 5000, issuer: 'Acme Compliance', criteria: { minAibomGrade: 'B', minEvalPosture: 'C', requireDistinctSigners: true, requireDriftChecked: true } }), owner); return evidence.buildEvidencePack({ record, signedPolicy }, { created_ts: ts }); };

  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(9));
  const W1 = ml_dsa87.keygen(new Uint8Array(32).fill(21));
  const W2 = ml_dsa87.keygen(new Uint8Array(32).fill(22));

  // build a growing honest log
  const log = new PQTransparencyLog();
  anchor.anchorAdmission(mkPack(2000), log, {}); anchor.anchorAdmission(mkPack(2001), log, {});
  const sth2 = log.signedTreeHead(logKey.secretKey, { ts: 7000 });          // size 2
  anchor.anchorAdmission(mkPack(2002), log, {}); anchor.anchorAdmission(mkPack(2003), log, {});
  const sth4 = log.signedTreeHead(logKey.secretKey, { ts: 7100 });          // size 4
  const consHex = log.consistency(2).proof.map(bytesToHex);                 // 2->4 proof, HEX for the wire

  // 1. a witness node observes an STH via POST /observe (hex proof decoded at the boundary)
  const store = memStore();
  const node = new GovernWitnessNode({ secretKey: W1.secretKey, publicKey: W1.publicKey, logPub: logKey.publicKey, store });
  const r1 = serviceHandle(node, null, 'POST', '/observe', { sth: sth2, observed_ts: 7050 });
  ok(r1.status === 200 && verifyWitnessObservation(r1.body, logKey.publicKey, W1.publicKey).ok === true, 'witness node emits a valid observation via POST /observe');
  const r2 = serviceHandle(node, null, 'POST', '/observe', { sth: sth4, consistencyProof: consHex });
  ok(r2.status === 200 && node.size() === 4, 'node observes a consistent extension (hex consistency proof decoded), size 4');

  // 2. DURABILITY: a RESTARTED node (new instance, SAME store) keeps its head -> refuses a fork
  const restarted = new GovernWitnessNode({ secretKey: W1.secretKey, publicKey: W1.publicKey, logPub: logKey.publicKey, store });
  ok(restarted.size() === 4, 'restarted node reloaded durable state (last head survived)');
  const log2 = new PQTransparencyLog();
  for (let i = 0; i < 4; i++) anchor.anchorAdmission(mkPack(3000 + i), log2, {});
  const fork4 = log2.signedTreeHead(logKey.secretKey, { ts: 7200 });        // size 4, DIFFERENT root, same log key
  const rf = serviceHandle(restarted, null, 'POST', '/observe', { sth: fork4, consistencyProof: [] });
  ok(rf.status === 409, 'restarted node REFUSES a divergent same-size head (durable state honored the guarantee)');

  // 3. fail-closed + ATOMIC on a throwing store: observe fails AND the in-memory monitor is rolled back (not advanced),
  //    so in-memory never diverges from durable (council/DeepSeek).
  const throwStore = { get: () => null, set: () => { throw new Error('disk full'); } };
  const nThrow = new GovernWitnessNode({ secretKey: W1.secretKey, publicKey: W1.publicKey, logPub: logKey.publicKey, store: throwStore });
  ok(nThrow.observe(sth2).observed === false && nThrow.size() === 0, 'a throwing store -> observe fails closed AND rolls back (monitor stays at size 0, no in-memory/durable divergence)');

  // 4. GOSSIP RECONCILER flags a SPLIT VIEW: two trusted witnesses co-sign DIFFERENT roots at size 4
  const nodeA = new GovernWitnessNode({ secretKey: W1.secretKey, publicKey: W1.publicKey, logPub: logKey.publicKey, store: memStore() });
  const nodeB = new GovernWitnessNode({ secretKey: W2.secretKey, publicKey: W2.publicKey, logPub: logKey.publicKey, store: memStore() });
  const obsA = serviceHandle(nodeA, null, 'POST', '/observe', { sth: sth4, consistencyProof: [] }).body;        // real view @4... wait: nodeA fresh, sth4 size4 first head -> TOFU accept
  const obsB = serviceHandle(nodeB, null, 'POST', '/observe', { sth: fork4, consistencyProof: [] }).body;       // fork view @4
  const reconciler = new GovernGossipReconciler(logKey.publicKey, [W1.publicKey, W2.publicKey]);
  const sub1 = serviceHandle(nodeA, reconciler, 'POST', '/reconcile', { observation: obsA });
  ok(sub1.body.equivocation === false, 'reconciler: first observation alone -> no equivocation yet');
  const sub2 = serviceHandle(nodeB, reconciler, 'POST', '/reconcile', { observation: obsB });
  ok(sub2.body.equivocation === true && sub2.body.equivocations[0].type === 'exact-size-fork', 'reconciler flags the SPLIT VIEW (two trusted witnesses, different roots at size 4)');
  ok(serviceHandle(node, reconciler, 'GET', '/reconcile', null).body.equivocation === true, 'GET /reconcile returns the running (equivocation) verdict');

  // 5. routing / fail-closed
  ok(serviceHandle(node, null, 'GET', '/healthz', null).body.ok === true, 'GET /healthz ok');
  ok(serviceHandle(node, null, 'POST', '/observe', {}).status === 400, 'POST /observe without an sth -> 400');
  ok(serviceHandle(node, reconciler, 'POST', '/reconcile', {}).status === 400, 'POST /reconcile without an observation -> 400');
  ok(serviceHandle(node, null, 'GET', '/nope', null).status === 404, 'unknown route -> 404');

  // 6. malformed hex consistency proof -> 400 (handler is TOTAL; an uncaught throw would kill the process)
  ok(serviceHandle(node, null, 'POST', '/observe', { sth: sth4, consistencyProof: ['nothex!!'] }).status === 400, 'a malformed hex consistency proof -> 400 (total handler, no process crash)');

  // 7. reconciler DEDUP + DROP-invalid (DoS bound): a duplicate trusted obs doesn't grow state; an untrusted obs is dropped
  const rc2 = new GovernGossipReconciler(logKey.publicKey, [W1.publicKey, W2.publicKey]);
  rc2.submit(obsA); rc2.submit(obsA); rc2.submit(obsA);
  ok(rc2.observations.length === 1, 'reconciler dedups a re-submitted observation (bounded state, no spam inflation)');
  const { witnessObserve } = await import('./pqgovern-witness.mjs');
  const Wx = ml_dsa87.keygen(new Uint8Array(32).fill(77));
  rc2.submit(witnessObserve(sth4, logKey.publicKey, Wx.secretKey, Wx.publicKey, { observed_ts: 1 }));
  ok(rc2.observations.length === 1, 'reconciler DROPS an untrusted-witness observation (not stored)');

  // 8. loadState REFUSES a corrupted restored head (bad log-STH signature) -> monitor stays at constructor state
  const corruptStore = { get: () => ({ currentSTH: { tree_size: 99, root_hex: 'a'.repeat(64), ts: 1, sig: 'de' }, history: [], acceptedRoots: [], alerts: [] }), set: () => {} };
  const nCorrupt = new GovernWitnessNode({ secretKey: W1.secretKey, publicKey: W1.publicKey, logPub: logKey.publicKey, store: corruptStore });
  ok(nCorrupt.size() === 0, 'a corrupted/tampered restored head (bad sig) is REFUSED on load (monitor at constructor state)');

  // 9. HTTP body cap: the adapter 413s an over-large body before parsing (OOM guard)
  const { EventEmitter } = await import('events');
  let code = 0; const req = new EventEmitter(); req.method = 'POST'; req.url = '/observe'; req.destroy = () => {};
  const res = { writeHead: (c) => { code = c; }, end: () => {} };
  serviceHandler(node)(req, res);
  req.emit('data', 'x'.repeat(300 * 1024));  // > 256KB cap
  ok(code === 413, 'the http adapter 413s an over-large body (OOM guard) before parsing');

  console.log('pqgovern-witness-service self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgovern-witness-service\.mjs$/.test(process.argv[1] || '')) selfTest();

/* ---------- DEPLOY (owner-gated — NOT done autonomously) ----------
 * 1. Generate an ML-DSA-87 witness keypair per host; keep the secret in the host's KMS/HSM (never in the repo).
 * 2. Provide a DURABLE store (file/DB) implementing { get(), set(state) } — required for the no-fork guarantee.
 * 3. Bootstrap each witness from a trusted recent STH ({checkpoint}) so it never blind-TOFUs its genesis.
 * 4. Run >=1 instance on INDEPENDENT infrastructure/operators (the trust root): http.createServer(serviceHandler(node)).listen(PORT).
 * 5. A relying party runs a GovernGossipReconciler over the CONFIGURED trusted witness pubkeys and feeds it each
 *    witness's observations; supply RFC-6962 consistency proofs (hex over the wire) for different-size pairs so the
 *    reconciler can resolve them rather than abstain.
 */
