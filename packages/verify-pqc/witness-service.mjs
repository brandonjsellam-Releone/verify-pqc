/*!
 * witness-service — runnable KT WITNESS node + gossip pool (reference, DRAFT). Makes the pqkt witness layer
 * deploy-ready: the owner runs ≥1 INDEPENDENT instance on independent hosts; this code is the node + the gossip
 * aggregator. NO autonomous deploy — see DEPLOY notes at the bottom.
 *
 * A WitnessNode wraps pqkt.Witness with a DURABLE STATE store (DeepSeek: `seen`/`last` must survive restarts — a
 * witness that forgets reverts to TOFU). State is persisted after every successful co-sign; on construction it is
 * reloaded, so a restarted node keeps refusing forks. A GossipPool collects co-signatures from multiple
 * witnesses/relying parties and runs gossipDetectEquivocation to surface a log that partitioned witnesses.
 *
 * Honest scope: still a reference. The TRUST comes from running witnesses that are genuinely INDEPENDENT operators
 * (a deployment/governance fact); the store here is pluggable (default in-memory) — owner supplies a file/DB store.
 * Self-test: node witness-service.mjs
 */
import { Witness, gossipDetectEquivocation } from './pqkt.mjs';
import { sthCoreBytes } from './pqsign.mjs';
import { bytesToHex } from '@noble/hashes/utils.js';

const dumpState = (w) => ({ seen: [...w.seen.entries()], last: w.last });
const loadState = (w, s) => { if (!s) return; w.seen = new Map(s.seen || []); w.last = s.last || null; };
const memStore = () => { let s = null; return { get: () => s, set: (v) => { s = v; } }; }; // owner replaces with file/DB

export class WitnessNode {
  // store: { get(): state|null, set(state): void } — MUST be durable in production.
  constructor({ secretKey, publicKey, logPub, store, requireAnchor = false, anchor = null }) {
    this.witness = new Witness(secretKey, publicKey, { requireAnchor, anchor });
    this.logPub = logPub;
    this.store = store || memStore();
    loadState(this.witness, this.store.get()); // restore durable state on (re)start
  }
  cosign(sth, consistencyProof) {
    const r = this.witness.cosign(sth, this.logPub, consistencyProof);
    if (r.ok) this.store.set(dumpState(this.witness)); // PERSIST after every successful co-sign (durability)
    return r;
  }
  state() { return dumpState(this.witness); }
}

// relying parties / monitors submit co-signatures here; the pool flags cross-witness equivocation (partition attack).
export class GossipPool {
  constructor(logPub, trustedWitnessPubs) { this.logPub = logPub; this.trusted = trustedWitnessPubs || []; this.cosigs = []; }
  submit(cosig) { this.cosigs.push(cosig); return gossipDetectEquivocation(this.cosigs, this.logPub, this.trusted); }
  scan() { return gossipDetectEquivocation(this.cosigs, this.logPub, this.trusted); }
}

// framework-free request core (testable without a server). body = already-parsed object.
export function handle(node, method, path, body) {
  if (method === 'GET' && path === '/healthz') return { status: 200, body: { ok: true, witness_pub: bytesToHex(node.witness.publicKey), last: node.witness.last } };
  if (method === 'GET' && path === '/state') return { status: 200, body: node.state() };
  if (method === 'POST' && path === '/cosign') {
    if (!body || !body.sth) return { status: 400, body: { error: 'missing sth' } };
    const r = node.cosign(body.sth, body.consistencyProof);
    return r.ok ? { status: 200, body: r.cosig } : { status: 409, body: { error: r.reason, equivocation: !!r.equivocation, fork: !!r.fork } };
  }
  return { status: 404, body: { error: 'not found' } };
}
// thin Node http adapter — owner wires into http.createServer(nodeHandler(node)).listen(...)
export function nodeHandler(node) {
  return (req, res) => {
    let data = ''; req.on('data', (c) => (data += c)); req.on('end', () => {
      let body = null; try { body = data ? JSON.parse(data) : null; } catch { res.writeHead(400, { 'content-type': 'application/json' }); return res.end('{"error":"bad json"}'); }
      const out = handle(node, req.method, (req.url || '').split('?')[0], body);
      res.writeHead(out.status, { 'content-type': 'application/json' }); res.end(JSON.stringify(out.body));
    });
  };
}

/* ---------- self-test: node witness-service.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { PQTransparencyLog } = await import('./pqsign.mjs');
  const { sha256 } = await import('@noble/hashes/sha2.js');
  const { bytesToHex: hex, utf8ToBytes } = await import('@noble/hashes/utils.js');

  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(60));
  const wKey = ml_dsa87.keygen(new Uint8Array(32).fill(61));
  const log = new PQTransparencyLog();
  [0, 1, 2].forEach((i) => log.append({ i }));
  const sth1 = log.signedTreeHead(logKey.secretKey, { ts: 1 });
  log.append({ i: 9 });
  const sth2 = log.signedTreeHead(logKey.secretKey, { ts: 2 });
  const cons = log.consistency(sth1.tree_size).proof.map(hex);

  // 1. node co-signs via the request handler
  const store = memStore();
  const node = new WitnessNode({ secretKey: wKey.secretKey, publicKey: wKey.publicKey, logPub: logKey.publicKey, store });
  const r1 = handle(node, 'POST', '/cosign', { sth: sth1 });
  ok(r1.status === 200 && r1.body.witness_pub === hex(wKey.publicKey), 'witness node co-signs an STH via POST /cosign');
  const r2 = handle(node, 'POST', '/cosign', { sth: sth2, consistencyProof: cons });
  ok(r2.status === 200, 'node co-signs a consistent extension (with consistency proof)');

  // 2. DURABILITY: a RESTARTED node (new instance, SAME store) keeps its state -> still refuses a fork
  const restarted = new WitnessNode({ secretKey: wKey.secretKey, publicKey: wKey.publicKey, logPub: logKey.publicKey, store });
  ok(restarted.witness.last && restarted.witness.last.size === sth2.tree_size, 'restarted node reloaded durable state (last head survived)');
  const forkBig = { tree_size: sth2.tree_size + 3, root_hex: bytesToHex(sha256(utf8ToBytes('fork'))), ts: 3 };
  forkBig.sig = bytesToHex(ml_dsa87.sign(sthCoreBytes(forkBig.tree_size, forkBig.root_hex, forkBig.ts), logKey.secretKey, { context: utf8ToBytes('trelyan-pqsign-sth-v1') }));
  const rf = handle(restarted, 'POST', '/cosign', { sth: forkBig, consistencyProof: [] });
  ok(rf.status === 409 && rf.body.fork === true, 'restarted node REFUSES a fork (durable state honored the guarantee)');

  // 3. gossip pool flags a partition (two witnesses, conflicting views at the same size)
  const w2key = ml_dsa87.keygen(new Uint8Array(32).fill(62));
  const w2 = new WitnessNode({ secretKey: w2key.secretKey, publicKey: w2key.publicKey, logPub: logKey.publicKey, store: memStore() });
  const forkAtS2 = { tree_size: sth2.tree_size, root_hex: bytesToHex(sha256(utf8ToBytes('other-view'))), ts: 2 };
  forkAtS2.sig = bytesToHex(ml_dsa87.sign(sthCoreBytes(forkAtS2.tree_size, forkAtS2.root_hex, forkAtS2.ts), logKey.secretKey, { context: utf8ToBytes('trelyan-pqsign-sth-v1') }));
  const realCosig = JSON.parse(JSON.stringify(r2.body)); // node already co-signed sth2 (the real view)
  const fakeCosig = w2.cosign(forkAtS2).cosig; // w2 (fresh) co-signs the fork view
  const pool = new GossipPool(logKey.publicKey, [wKey.publicKey, w2.witness.publicKey]);
  pool.submit(realCosig);
  ok(pool.submit(fakeCosig).equivocation === true, 'gossip pool flags the partition (same size co-signed with two roots)');

  // 4. routing
  ok(handle(node, 'GET', '/healthz', null).body.ok === true, 'GET /healthz ok');
  ok(handle(node, 'POST', '/cosign', {}).status === 400, 'POST /cosign without an sth -> 400');
  ok(handle(node, 'GET', '/nope', null).status === 404, 'unknown route -> 404');

  console.log('witness-service self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /witness-service\.mjs$/.test(process.argv[1] || '')) selfTest();

/* ---------- DEPLOY (owner-gated — NOT done autonomously) ----------
 * 1. Generate an ML-DSA-87 witness keypair per host; keep the secret in the host's KMS/HSM (never in the repo).
 * 2. Provide a DURABLE store (file/DB) implementing { get(), set(state) } — required for the no-fork guarantee.
 * 3. Anchor each witness to a trusted recent STH ({anchor}) or set {requireAnchor:true}.
 * 4. Run ≥1 instance on INDEPENDENT infrastructure/operators (the trust root): http.createServer(nodeHandler(node)).listen(PORT).
 * 5. Relying parties require k-of-n witnessed STHs (pqkt.verifyWitnessedSTH) + feed a GossipPool to catch partitions.
 */
