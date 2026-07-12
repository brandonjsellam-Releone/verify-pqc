/*!
 * omega-sentinel — TRELYAN OMEGA Layer 7 (Sentience) human-in-the-loop posture monitor (reference, DRAFT). The HONEST
 * version of the blueprint's "AI that auto-rotates keys": it maintains a tamper-evident, PQ-signed POSTURE LEDGER
 * (pqauditlog), ingests posture snapshots, detects a REGRESSION (more RED assets, or a risk-score increase over a
 * threshold), and raises an ALERT — but it NEVER takes an irreversible action on its own. Any response
 * (e.g. key rotation) requires EXPLICIT human approval through `authorizeResponse`; the autonomous path is machine-gated.
 *
 * HONEST (Dorit Dor test):
 *  - The signals are REACTIVE + FALSIFIABLE (regressed-asset count, risk delta) — NOT predictions. No "73.4% RSA break". // pqcbom-ignore: claim-hygiene / migration prose
 *  - The LEDGER is post-quantum-signed (Ed25519 ∧ ML-DSA-87 [∧ SLH-DSA]); the posture SIGNALS themselves are classical
 *    (RSA-migration status, CVE exposure). This is "hybrid-signed tamper-evident logging of a classical signal", not // pqcbom-ignore: claim-hygiene / migration prose
 *    "quantum-safe threat prediction".
 *  - The "agent" is a STUB (a deterministic detector), not a deployed LLM. Wiring an LLM to production key material +
 *    federated learning over real estates = GATED (data egress, autonomy). Self-test: node omega-sentinel.mjs
 */
import { createLog, append, exportLog, verifyLog, verifyResponse } from './pqauditlog.mjs';
import { reviewThreatSignal } from './omega.mjs';

/** openSentinel(signer) — signer = { ed:{secretKey,publicKey}, mldsa:{...}, slh?:{...} }. */
export function openSentinel(signer) {
  if (!signer || !signer.ed || !signer.mldsa) throw new Error('omega-sentinel: signer must be { ed, mldsa }');
  const pub = { ed: signer.ed.publicKey, mldsa: signer.mldsa.publicKey };
  if (signer.slh) pub.slh = signer.slh.publicKey;
  return { log: createLog(signer), signer, pub, postures: [] };
}

/** recordPosture(sentinel, { redAssets, riskScore, source, ts }) — append a signed posture snapshot to the ledger.
 *  The raw values are kept in sentinel.postures AND bound by the ledger entry's signed payload hash. */
export function recordPosture(sentinel, { redAssets, riskScore, source, ts }) {
  const payload = { redAssets: Number(redAssets) || 0, riskScore: Number(riskScore) || 0 };
  const entry = append(sentinel.log, { actor: source || 'monitor', action: 'posture', stage: 'signal', payload, ts });
  sentinel.postures.push({ seq: entry.seq, ...payload });
  return entry;
}

/**
 * detectRegression(sentinel, { redThreshold = 5, riskDeltaThreshold = 0.5, trusted }) — verify the ledger (chain + sigs),
 * verify the two latest posture PAYLOADS against their signed hashes, then compare. TOTAL / fail-closed on any tamper.
 * Returns { ok, regressed, newRed, riskDelta, alert, requiresHumanApproval } — requiresHumanApproval is ALWAYS true.
 */
export function detectRegression(sentinel, { redThreshold = 5, riskDeltaThreshold = 0.5, trusted } = {}) {
  const entries = exportLog(sentinel.log);
  const pins = trusted || sentinel.pub;
  const lv = verifyLog(entries, pins);
  if (!lv.verified) return { ok: false, reason: 'posture ledger does not verify (' + lv.reason + ')', requiresHumanApproval: true };
  const snaps = sentinel.postures;
  if (!snaps.length) return { ok: true, regressed: false, alert: null, reason: 'no posture data', requiresHumanApproval: true };
  const latest = snaps[snaps.length - 1];
  const prior = snaps.length >= 2 ? snaps[snaps.length - 2] : { redAssets: 0, riskScore: 0, seq: null };
  // verify each compared snapshot's raw payload binds to its signed ledger entry (defends against a doctored side-table)
  const bindOk = (snap) => snap.seq == null || verifyResponse(entries[snap.seq], { redAssets: snap.redAssets, riskScore: snap.riskScore }, pins).verified;
  if (!bindOk(latest) || !bindOk(prior)) return { ok: false, reason: 'posture snapshot does not bind to the signed ledger', requiresHumanApproval: true };
  const newRed = latest.redAssets - prior.redAssets;
  const riskDelta = latest.riskScore - prior.riskScore;
  // `regressed` + newRed + riskDelta are the LOAD-BEARING signals, computed DIRECTLY from values bound to the signed
  // ledger (verified above via verifyResponse). `alert.severity` is an advisory label from reviewThreatSignal, a PURE
  // deterministic function of those same verified values (no external state / no LLM) — a caller can recompute it.
  const regressed = latest.redAssets >= redThreshold || newRed > 0 || riskDelta >= riskDeltaThreshold;
  const alert = reviewThreatSignal({ redAssets: latest.redAssets, riskDelta });
  return { ok: true, regressed, newRed, riskDelta, alert, ledger_n: lv.n, requiresHumanApproval: true };
}

/**
 * authorizeResponse(alert, approval) — the ONLY path to a state-changing response. Requires an EXPLICIT human approval:
 * approval = { humanApproved:true, approver:'<id>', action:'rotate_keys'|... }. Without it → GATED (throws). Returns an
 * AUTHORIZATION record (still not an execution — execution is a separate, owner-run step through the real key custody).
 */
export function authorizeResponse(alert, approval) {
  if (!approval || approval.humanApproved !== true || !approval.approver) {
    throw new Error('OMEGA_AUTONOMOUS_ACTION_GATED: a sentinel alert cannot trigger a response on its own. Supply { humanApproved:true, approver, action } from an authenticated human to authorize (execution remains a separate owner-run step).');
  }
  return { authorized: true, approver: approval.approver, action: approval.action || 'review', on_alert_severity: alert && alert.severity, note: 'Authorization only — execution is performed by the owner through the real key-custody path, not by this module.' };
}

/* ---------------------------------------- self-test: node omega-sentinel.mjs ---------------------------------------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const s = (n) => new Uint8Array(32).fill(n);
  const signer = { ed: (() => { const sk = s(1); return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })(), mldsa: ml_dsa87.keygen(s(2)) };

  const sentinel = openSentinel(signer);
  recordPosture(sentinel, { redAssets: 1, riskScore: 0.10, ts: 1 });
  recordPosture(sentinel, { redAssets: 1, riskScore: 0.12, ts: 2 });
  let d = detectRegression(sentinel);
  ok(d.ok && !d.regressed && d.alert.severity !== 'high', 'detect: stable posture → no regression');

  recordPosture(sentinel, { redAssets: 7, riskScore: 0.80, ts: 3 });   // red 1→7, risk +0.68
  d = detectRegression(sentinel);
  ok(d.ok && d.regressed && d.newRed === 6 && d.alert.severity === 'high', 'detect: regression flagged high');
  ok(d.requiresHumanApproval === true, 'detect: always requires human approval');

  // response gate
  let gated = false; try { authorizeResponse(d.alert, {}); } catch (e) { gated = /AUTONOMOUS_ACTION_GATED/.test(e.message); }
  ok(gated, 'authorizeResponse: no human approval → gated');
  let gated2 = false; try { authorizeResponse(d.alert, { humanApproved: true }); } catch { gated2 = true; }
  ok(gated2, 'authorizeResponse: approval without an approver id → gated');
  const auth = authorizeResponse(d.alert, { humanApproved: true, approver: 'ciso@trelyan', action: 'rotate_keys' });
  ok(auth.authorized && auth.approver === 'ciso@trelyan', 'authorizeResponse: explicit human approval authorizes');

  // ledger tamper → fail-closed
  const t = openSentinel(signer);
  recordPosture(t, { redAssets: 1, riskScore: 0.1, ts: 1 });
  recordPosture(t, { redAssets: 2, riskScore: 0.2, ts: 2 });
  t.log.entries[1].actor = 'attacker';   // tamper the signed entry
  ok(!detectRegression(t).ok, 'detect: tampered ledger entry fails closed');

  // doctored side-table (raw value ≠ signed payload) → fails the binding check
  const t2 = openSentinel(signer);
  recordPosture(t2, { redAssets: 1, riskScore: 0.1, ts: 1 });
  recordPosture(t2, { redAssets: 2, riskScore: 0.2, ts: 2 });
  t2.postures[1].redAssets = 99;   // lie about the latest posture without re-signing
  ok(!detectRegression(t2).ok, 'detect: doctored snapshot (unsigned) rejected by payload binding');

  console.log(`\nomega-sentinel self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTest();
