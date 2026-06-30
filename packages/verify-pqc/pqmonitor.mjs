/*!
 * pqmonitor — TRELYANShield continuous-posture monitor (reference, DRAFT). The SOC engine: track an estate's
 * cryptographic posture OVER TIME, prove the history is tamper-evident, and detect REGRESSIONS — the thing an MSSP
 * actually sells on top of a point-in-time pqshield report.
 *
 * Model: an append-only, hash-CHAINED ledger of posture SNAPSHOTS (one per pqshield report at ingest). Each ingested
 * report is VERIFIED under the pinned issuer BEFORE it is recorded (FAIL-DANGEROUS — you cannot track a posture you
 * cannot verify). The chain (entry binds prev_hash) makes the history tamper-evident: altering a past snapshot breaks
 * every hash after it. A signed posture DIGEST captures the current posture + the trend; verifyPostureDigest
 * RECOMPUTES the current grade + trend from the ledger (so a forged "improving" trend over a regressing history is
 * caught, exactly like pqshield recomputes the grade from assets) and supports an anti-rollback minSeq pin.
 *
 * HONEST SCOPE: the ledger proves "these snapshots were recorded in this order and are unaltered since"; snapshot
 * AUTHENTICITY rests on the recorder having verified each report at ingest (it does, fail-closed). This is a posture
 * trend SIGNAL under pqshield's declared model — NOT an audit, attestation, SLA, or guarantee. Unaudited reference.
 *
 * Self-test: node pqmonitor.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { verifyShieldReport, scoreAsset, band } from './pqshield.mjs';

const MON_CTX = utf8ToBytes('trelyan-shield-monitor-digest-v1');      // signing domain (Ed25519 + ML-DSA legs)
const MON_SLH_CTX = utf8ToBytes('trelyan-shield-monitor-digest-slh-v1'); // distinct domain for the optional SLH leg

function canon(v) {
  if (v === undefined) return 'null';
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
const h = (s) => bytesToHex(sha256(utf8ToBytes(s)));

// monitor id binds the COMPLETE hybrid key set.
export function makeMonitorId(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('monitor keys must be { ed, mldsa[, slh] }');
  return 'monitor:trelyan:' + bytesToHex(sha256(concatBytes(utf8ToBytes('monitor:trelyan:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}

// the deterministic posture summary extracted from a (verified) shield report. red_labels is the SORTED set of RED
// asset labels (re-derived from the carried assets via pqshield's exported scorer) — the basis for regression diffs.
export function snapshotOf(report) {
  const assets = Array.isArray(report.assets) ? report.assets : [];
  const red_labels = assets.filter((a) => band(scoreAsset(a)) === 'RED').map((a) => String(a.label || '')).sort();
  return { target: String(report.target || ''), grade: report.grade, risk_index: report.risk_index,
    red: report.red, amber: report.amber, green: report.green, asset_count: report.asset_count,
    assets_hash: report.assets_hash, generated_at: report.generated_at ?? null, anchor: report.anchor_commitment ?? null,
    issuer: report.issuer ?? null, red_labels };
}

export function createLedger() { return { v: '1', entries: [] }; }

// FAIL-DANGEROUS ingest: verify the report under the pinned issuer FIRST; only a verified report is recorded.
// Each entry binds prev_hash → tamper-evident chain. `at` is the ingest timestamp (caller-supplied; no wall-clock here).
export function appendSnapshot(ledger, report, trustedIssuer, { at = null } = {}) {
  const v = verifyShieldReport(report, trustedIssuer);
  if (!v.verified) throw new Error('refusing to record an UNVERIFIED report (fail-dangerous): ' + (v.reason || 'invalid'));
  const prev = ledger.entries[ledger.entries.length - 1];
  if (prev && snapshotOf(report).target !== prev.snapshot.target) throw new Error('target mismatch: this ledger tracks "' + prev.snapshot.target + '"');
  const seq = ledger.entries.length;
  const prev_hash = prev ? prev.entry_hash : null;
  const snapshot = snapshotOf(report);
  const entry = { seq, prev_hash, ts: at, snapshot };
  entry.entry_hash = h(canon({ seq, prev_hash, ts: at, snapshot }));
  ledger.entries.push(entry);
  return { ledger, entry };
}

// recompute the chain from genesis; assert contiguous seq + each prev_hash links the prior entry_hash. TOTAL.
export function verifyLedger(ledger) {
  try {
    if (!ledger || typeof ledger !== 'object' || !Array.isArray(ledger.entries)) return { intact: false, length: 0, head_hash: null };
    const e = ledger.entries;
    let prevHash = null;
    for (let i = 0; i < e.length; i++) {
      const x = e[i];
      if (x.seq !== i || x.prev_hash !== prevHash) return { intact: false, length: e.length, head_hash: null, at: i };
      const recomputed = h(canon({ seq: x.seq, prev_hash: x.prev_hash, ts: x.ts, snapshot: x.snapshot }));
      if (recomputed !== x.entry_hash) return { intact: false, length: e.length, head_hash: null, at: i };
      prevHash = x.entry_hash;
    }
    return { intact: true, length: e.length, head_hash: prevHash };
  } catch { return { intact: false, length: 0, head_hash: null }; }
}

// posture delta between two snapshots: regressions = labels newly RED, resolved = labels no longer RED.
export function diffSnapshots(prev, cur) {
  const prevRed = new Set(prev.red_labels || []);
  const curRed = new Set(cur.red_labels || []);
  const regressions = (cur.red_labels || []).filter((l) => !prevRed.has(l));
  const resolved = (prev.red_labels || []).filter((l) => !curRed.has(l));
  const risk_delta = (cur.risk_index || 0) - (prev.risk_index || 0);
  const direction = (regressions.length || risk_delta > 0) ? 'regressed' : (resolved.length || risk_delta < 0) ? 'improved' : 'flat';
  return { from_grade: prev.grade, to_grade: cur.grade, risk_delta, regressions, resolved, direction };
}

const currentOf = (s) => ({ grade: s.grade, risk_index: s.risk_index, red: s.red, amber: s.amber, green: s.green, asset_count: s.asset_count });
function digestCore(d) {
  return { v: '1', monitor: d.monitor, target: d.target, ledger_head: d.ledger_head, snapshot_count: d.snapshot_count,
    seq: d.seq, current: d.current, since: d.since, trend: d.trend, at: d.at };
}

// sign a posture digest = current posture + trend (last transition) + the ledger head, over the chain. monitorKeys =
// { ed, mldsa[, slh] }. Hybrid-signed (Ed25519 ∧ ML-DSA-87 ∧ optional SLH-DSA-256f; anti-downgrade via bound slh pub).
export function signPostureDigest({ ledger, monitorKeys, at = null }) {
  if (!monitorKeys || !monitorKeys.ed || !monitorKeys.mldsa) throw new Error('monitorKeys must be { ed, mldsa[, slh] }');
  const vl = verifyLedger(ledger);
  if (!vl.intact || vl.length === 0) throw new Error('cannot sign a digest over a broken/empty ledger');
  const e = ledger.entries;
  const head = e[e.length - 1].snapshot;
  const trend = e.length > 1 ? diffSnapshots(e[e.length - 2].snapshot, head) : null;
  const core = digestCore({ monitor: makeMonitorId(monitorKeys), target: head.target, ledger_head: vl.head_hash,
    snapshot_count: e.length, seq: e[e.length - 1].seq, current: currentOf(head), since: e[0].snapshot.generated_at ?? e[0].ts, trend, at });
  const coreBytes = utf8ToBytes(canon(core));
  const digest = { ...core, monitor_pub: { ed: bytesToHex(_pub(monitorKeys.ed)), mldsa: bytesToHex(_pub(monitorKeys.mldsa)) },
    slh_signer_pub_hex: monitorKeys.slh ? bytesToHex(_pub(monitorKeys.slh)) : null,
    ed_sig: bytesToHex(ed25519.sign(concatBytes(MON_CTX, coreBytes), monitorKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, monitorKeys.mldsa.secretKey, { context: MON_CTX })) };
  if (monitorKeys.slh) { digest.monitor_pub.slh = bytesToHex(_pub(monitorKeys.slh)); digest.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, monitorKeys.slh.secretKey, { context: MON_SLH_CTX })); }
  return digest;
}

// TOTAL / fail-closed. Verifies the hybrid signature under the pinned monitor key; if opts.ledger is supplied, also
// RECOMPUTES current+trend+head from it and rejects any mismatch (a forged trend/grade over a real ledger is caught).
// opts.minSeq → reject a stale digest (anti-rollback replay).
export function verifyPostureDigest(digest, trustedMonitor, opts = {}) {
  try {
    if (!digest || typeof digest !== 'object' || !trustedMonitor || !trustedMonitor.ed || !trustedMonitor.mldsa) return { verified: false };
    if (digest.monitor !== makeMonitorId(trustedMonitor)) return { verified: false, reason: 'monitor id != pinned monitor keys' };
    const coreBytes = utf8ToBytes(canon(digestCore(digest)));
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(digest.ed_sig), concatBytes(MON_CTX, coreBytes), trustedMonitor.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(digest.mldsa_sig), coreBytes, trustedMonitor.mldsa, { context: MON_CTX }); } catch { pqOk = false; }
    if (trustedMonitor.slh) { try { slhOk = !!(digest.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(digest.slh_sig), coreBytes, trustedMonitor.slh, { context: MON_SLH_CTX })); } catch { slhOk = false; } }
    if (!edOk || !pqOk || !slhOk) return { verified: false, reason: 'hybrid signature invalid (or required leg missing)' };
    if (opts.minSeq != null && (typeof digest.seq !== 'number' || digest.seq < opts.minSeq)) return { verified: false, reason: 'stale digest (seq < minSeq) — rollback refused' };
    // recompute-from-ledger: don't trust the signed current/trend/head if the caller can supply the ledger
    if (opts.ledger) {
      const vl = verifyLedger(opts.ledger);
      if (!vl.intact) return { verified: false, reason: 'supplied ledger is not intact' };
      if (vl.head_hash !== digest.ledger_head) return { verified: false, reason: 'digest ledger_head != supplied ledger head' };
      const e = opts.ledger.entries;
      if (e.length !== digest.snapshot_count) return { verified: false, reason: 'snapshot_count mismatch' };
      const recomputedCurrent = currentOf(e[e.length - 1].snapshot);
      const recomputedTrend = e.length > 1 ? diffSnapshots(e[e.length - 2].snapshot, e[e.length - 1].snapshot) : null;
      if (canon(recomputedCurrent) !== canon(digest.current)) return { verified: false, reason: 'recomputed current posture != signed digest' };
      if (canon(recomputedTrend) !== canon(digest.trend)) return { verified: false, reason: 'recomputed trend != signed digest (forged trend)' };
    }
    // recompute-signaling (council fix): a verdict without the ledger is signature-authentic but NOT freshness/
    // completeness-checked (it can be a stale/truncated view). Surface that, and let strict callers require it.
    if (opts.requireFresh && !opts.ledger) return { verified: false, reason: 'requireFresh: supply the ledger to recompute current+trend (a signature-only verdict is not freshness/completeness-checked)' };
    return { verified: true, freshness_checked: !!opts.ledger, target: digest.target, current: digest.current, trend: digest.trend, seq: digest.seq, snapshot_count: digest.snapshot_count, ledger_head: digest.ledger_head };
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqmonitor.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { createShieldReport } = await import('./pqshield.mjs');
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const issuer = { ed: ed(1), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)) };
  const tIssuer = { ed: issuer.ed.publicKey, mldsa: issuer.mldsa.publicKey };
  const monitor = { ed: ed(3), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(4)) };
  const tMonitor = { ed: monitor.ed.publicKey, mldsa: monitor.mldsa.publicKey };
  const T = 'acme/prod';
  const rep = (assets, at) => createShieldReport({ issuerKeys: issuer, target: T, assets, generatedAt: at });

  // t0: one RED asset; t1: a SECOND RED asset appears (regression); t2: both fixed to PQ (improvement)
  const a0 = [{ label: 'edge-tls', algorithm: 'RSA-2048', internet_facing: true }, { label: 'db', algorithm: 'AES-256' }];
  const a1 = [{ label: 'edge-tls', algorithm: 'RSA-2048', internet_facing: true }, { label: 'db', algorithm: 'AES-256' }, { label: 'vpn', algorithm: 'ECDH-P256', internet_facing: true }];
  const a2 = [{ label: 'edge-tls', algorithm: 'HYBRID-X25519-ML-KEM-1024', internet_facing: true }, { label: 'db', algorithm: 'AES-256' }, { label: 'vpn', algorithm: 'ML-KEM-1024' }];

  const L = createLedger();
  appendSnapshot(L, rep(a0, 100), tIssuer, { at: 100 });
  appendSnapshot(L, rep(a1, 200), tIssuer, { at: 200 });
  appendSnapshot(L, rep(a2, 300), tIssuer, { at: 300 });
  ok(L.entries.length === 3 && verifyLedger(L).intact === true, 'ingested 3 verified snapshots → intact hash-chained ledger');

  // fail-dangerous: an unverified report (wrong issuer) is REFUSED
  let refused = false; try { appendSnapshot(L, rep(a0, 400), { ed: ed(9).publicKey, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey }, { at: 400 }); } catch { refused = true; }
  ok(refused && L.entries.length === 3, 'fail-dangerous: an UNVERIFIED report is refused (ledger unchanged)');

  // trend detection
  const d01 = diffSnapshots(L.entries[0].snapshot, L.entries[1].snapshot);
  ok(d01.direction === 'regressed' && d01.regressions.includes('vpn'), 't0→t1: regression detected (new RED label "vpn")');
  const d12 = diffSnapshots(L.entries[1].snapshot, L.entries[2].snapshot);
  ok(d12.direction === 'improved' && d12.resolved.includes('edge-tls') && d12.resolved.includes('vpn'), 't1→t2: improvement detected (edge-tls + vpn resolved)');

  // tamper-evident: alter a PAST snapshot → chain breaks
  const tampered = JSON.parse(JSON.stringify(L)); tampered.entries[0].snapshot.grade = 'A';
  ok(verifyLedger(tampered).intact === false, 'altering a past snapshot → ledger NOT intact (tamper-evident)');

  // signed digest verifies under the pinned monitor; wrong monitor fails
  const dg = signPostureDigest({ ledger: L, monitorKeys: monitor, at: 300 });
  ok(verifyPostureDigest(dg, tMonitor).verified === true, 'posture digest verifies under the pinned monitor key');
  ok(verifyPostureDigest(dg, { ed: ed(9).publicKey, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(8)).publicKey }).verified === false, 'wrong pinned monitor key → FAILS');
  ok(dg.trend.direction === 'improved' && dg.current.grade === L.entries[2].snapshot.grade, 'digest carries the latest current+trend');

  // recompute-on-verify: forge the digest current grade over the real ledger → caught
  const fg = JSON.parse(JSON.stringify(dg)); fg.current.grade = fg.current.grade === 'F' ? 'A' : 'F'; // forge to a DIFFERENT grade
  ok(verifyPostureDigest(fg, tMonitor).verified === false, 'forged current grade (sig) → FAILS even without the ledger');
  ok(verifyPostureDigest(dg, tMonitor, { ledger: L }).verified === true, 'digest + matching ledger → verifies (recompute matches)');
  ok(verifyPostureDigest(dg, tMonitor).freshness_checked === false && verifyPostureDigest(dg, tMonitor, { ledger: L }).freshness_checked === true, 'freshness_checked flag reflects whether the ledger was recomputed (council fix: signature-only ≠ fresh)');
  ok(verifyPostureDigest(dg, tMonitor, { requireFresh: true }).verified === false, 'requireFresh without the ledger → NOT verified (no signature-only trust of a possibly-stale/truncated view)');
  // forge the trend direction but keep the sig valid by re-signing? no — verifier recomputes from the ledger:
  const dgWrongLedger = signPostureDigest({ ledger: (() => { const M = createLedger(); appendSnapshot(M, rep(a0, 100), tIssuer, { at: 100 }); return M; })(), monitorKeys: monitor, at: 100 });
  ok(verifyPostureDigest(dgWrongLedger, tMonitor, { ledger: L }).verified === false, 'a (validly-signed) digest checked against a DIFFERENT ledger → FAILS (head/recompute mismatch)');

  // anti-rollback: a stale digest (seq below the pin) is refused
  ok(verifyPostureDigest(dg, tMonitor, { minSeq: dg.seq + 1 }).verified === false, 'anti-rollback: seq < minSeq → stale digest refused');
  ok(verifyPostureDigest(dg, tMonitor, { minSeq: dg.seq }).verified === true, 'anti-rollback: seq == minSeq → accepted');

  // 3-leg hybrid
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5));
  const mon3 = { ed: monitor.ed, mldsa: monitor.mldsa, slh };
  const tMon3 = { ed: tMonitor.ed, mldsa: tMonitor.mldsa, slh: slh.publicKey };
  const dg3 = signPostureDigest({ ledger: L, monitorKeys: mon3, at: 300 });
  ok(typeof dg3.slh_sig === 'string' && verifyPostureDigest(dg3, tMon3).verified === true, '3-leg (Ed25519∧ML-DSA∧SLH-DSA) digest verifies');
  const dg3s = JSON.parse(JSON.stringify(dg3)); dg3s.slh_sig = '00';
  ok(verifyPostureDigest(dg3s, tMon3).verified === false, 'stripped/forged SLH leg fails when monitor.slh pinned (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { seq: 1 }, { ...dg, ed_sig: 'zz' }]) { try { if (verifyPostureDigest(bad, tMonitor).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed digests → verified:false, never throws');
  let totalL = true; for (const bad of [null, undefined, {}, 42, { entries: 'x' }, { entries: [{ seq: 5 }] }]) { try { if (verifyLedger(bad).intact !== false) totalL = false; } catch { totalL = false; } }
  ok(totalL, 'TOTAL: malformed ledgers → intact:false, never throws');

  console.log('pqmonitor self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqmonitor\.mjs$/.test(process.argv[1] || '')) selfTest();
