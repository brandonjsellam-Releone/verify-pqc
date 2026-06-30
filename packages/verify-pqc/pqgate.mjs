/*!
 * pqgate — SovereignMarket admission-control engine (reference, DRAFT). The CI/CD supply-chain GATE: given a deploy
 * request (an app cert + the binary), decide ALLOW/DENY against an authority-SIGNED policy, emit a verifiable signed
 * DECISION, and append it to a tamper-evident admission LOG. The deployable admission controller (K8s webhook / CI
 * step) wraps this engine; the verifiable heart is here.
 *
 * Why a layer over pqadmit (which verifies ONE cert): (1) the gate's RULES are an authority-SIGNED policy object, so
 * an attacker can't silently weaken the floor (pqadmit takes minCertLevel/minVersion/revoked as untrusted caller
 * args — here they are signed); (2) the ALLOW/DENY decision is hybrid-signed AND RECOMPUTE-VERIFIABLE — verifyDecision
 * re-evaluates the admission from the cert + the signed policy and rejects a forged "allow"; (3) every decision
 * (allow AND deny) is hash-chained into a tamper-evident audit log. FAIL-DANGEROUS: admit() refuses to act under a
 * policy whose signature doesn't verify.
 *
 * HONEST SCOPE: a decision proves "this cert met this signed policy under pqadmit's model" — NOT that the build is
 * safe. Inherits pqadmit's revocation caveat (a withheld revocation can still admit; pair with short expiry + an
 * anchored online check). Unaudited reference. Self-test: node pqgate.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { verifyAdmission } from './pqadmit.mjs';

const POLICY_CTX = utf8ToBytes('trelyan-sovereign-admission-policy-v1');
const POLICY_SLH_CTX = utf8ToBytes('trelyan-sovereign-admission-policy-slh-v1');
const DEC_CTX = utf8ToBytes('trelyan-sovereign-admission-decision-v1');
const DEC_SLH_CTX = utf8ToBytes('trelyan-sovereign-admission-decision-slh-v1');

function canon(v) {
  if (v === undefined) return 'null';
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
const h = (s) => bytesToHex(sha256(utf8ToBytes(s)));
const setOf = (arr) => ({ has: (id) => Array.isArray(arr) && arr.includes(id) });

// gate/authority id binds the COMPLETE hybrid key set (a policy authority and a gate are both just keysets).
export function makeGateId(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('keys must be { ed, mldsa[, slh] }');
  return 'gate:trelyan:' + bytesToHex(sha256(concatBytes(utf8ToBytes('gate:trelyan:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}

const ruleFields = (p) => ({ authority: p.authority, app: p.app, min_cert_level: p.min_cert_level ?? null, min_version: p.min_version ?? null, require_artifact: !!p.require_artifact, require_all_checks: p.require_all_checks !== false, revoked: (p.revoked || []).slice().sort() });
const policyIdOf = (p) => h('trelyan-admission-policy-id-v1' + canon(ruleFields(p)));
const policyCore = (p) => ({ v: '1', ...ruleFields(p), policy_id: p.policy_id, at: p.at ?? null });

// sign the admission RULES for one app. authorityKeys = { ed, mldsa[, slh] }.
export function signPolicy({ authorityKeys, app, minCertLevel = null, minVersion = null, requireArtifact = true, requireAllChecks = true, revoked = [], at = null }) {
  if (!authorityKeys || !authorityKeys.ed || !authorityKeys.mldsa) throw new Error('authorityKeys must be { ed, mldsa[, slh] }');
  if (!app) throw new Error('app is required');
  const base = { authority: makeGateId(authorityKeys), app: String(app), min_cert_level: minCertLevel, min_version: minVersion, require_artifact: !!requireArtifact, require_all_checks: requireAllChecks !== false, revoked: (revoked || []).map(String) };
  const policy_id = policyIdOf(base);
  const core = policyCore({ ...base, policy_id, at });
  const coreBytes = utf8ToBytes(canon(core));
  const policy = { ...core, authority_pub: { ed: bytesToHex(_pub(authorityKeys.ed)), mldsa: bytesToHex(_pub(authorityKeys.mldsa)) },
    slh_signer_pub_hex: authorityKeys.slh ? bytesToHex(_pub(authorityKeys.slh)) : null,
    ed_sig: bytesToHex(ed25519.sign(concatBytes(POLICY_CTX, coreBytes), authorityKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, authorityKeys.mldsa.secretKey, { context: POLICY_CTX })) };
  if (authorityKeys.slh) { policy.authority_pub.slh = bytesToHex(_pub(authorityKeys.slh)); policy.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, authorityKeys.slh.secretKey, { context: POLICY_SLH_CTX })); }
  return policy;
}

// TOTAL / fail-closed. Verifies the policy is authentic under the pinned authority AND that policy_id binds the rules.
export function verifyPolicy(policy, trustedAuthority) {
  try {
    if (!policy || typeof policy !== 'object' || !trustedAuthority || !trustedAuthority.ed || !trustedAuthority.mldsa) return { verified: false };
    if (policy.authority !== makeGateId(trustedAuthority)) return { verified: false, reason: 'authority id != pinned authority keys' };
    if (policy.policy_id !== policyIdOf(policy)) return { verified: false, reason: 'policy_id does not bind the rules' };
    const coreBytes = utf8ToBytes(canon(policyCore(policy)));
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(policy.ed_sig), concatBytes(POLICY_CTX, coreBytes), trustedAuthority.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(policy.mldsa_sig), coreBytes, trustedAuthority.mldsa, { context: POLICY_CTX }); } catch { pqOk = false; }
    if (trustedAuthority.slh) { try { slhOk = !!(policy.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(policy.slh_sig), coreBytes, trustedAuthority.slh, { context: POLICY_SLH_CTX })); } catch { slhOk = false; } }
    if (!edOk || !pqOk || !slhOk) return { verified: false, reason: 'policy signature invalid (or required leg missing)' };
    return { verified: true, policy_id: policy.policy_id, app: policy.app };
  } catch { return { verified: false }; }
}

// the DETERMINISTIC admission verdict: apply the policy's rules to the cert via pqadmit. Pure (no signing) → the basis
// for both admit() and the recompute in verifyDecision(). certIssuer = pinned cert-authority { ed, mldsa[, slh] }.
export function evaluateAdmission({ cert, certIssuer, policy, artifactBytes, now = null }) {
  if (!cert || !policy) return { allow: false, reason: 'missing cert or policy', app: policy && policy.app, cert_id: null, version: null, cert_level: null, policy_id: policy && policy.policy_id };
  if (String(cert.app) !== String(policy.app)) return { allow: false, reason: 'cert app != policy app', app: policy.app, cert_id: cert.cert_id ?? null, version: cert.version ?? null, cert_level: cert.cert_level ?? null, policy_id: policy.policy_id };
  const v = verifyAdmission(cert, certIssuer, { artifactBytes, allowUnboundArtifact: !artifactBytes && !policy.require_artifact, now,
    minCertLevel: policy.min_cert_level ?? undefined, minVersion: policy.min_version ?? undefined, revoked: setOf(policy.revoked), requireAllChecks: policy.require_all_checks !== false });
  return { allow: v.verified === true, reason: v.verified ? 'ok' : (v.reason || 'denied'), app: policy.app, cert_id: cert.cert_id ?? null, version: cert.version ?? null, cert_level: cert.cert_level ?? null, policy_id: policy.policy_id };
}

const decisionCore = (d) => ({ v: '1', gate: d.gate, app: d.app, allow: d.allow, reason: d.reason, cert_id: d.cert_id, version: d.version, cert_level: d.cert_level, policy_id: d.policy_id, at: d.at ?? null });

// make + hybrid-sign an admission decision. FAIL-DANGEROUS: refuses to act under an unauthentic policy.
export function admit({ cert, certIssuer, policy, policyAuthority, artifactBytes, gateKeys, now = null, at = null }) {
  if (!gateKeys || !gateKeys.ed || !gateKeys.mldsa) throw new Error('gateKeys must be { ed, mldsa[, slh] }');
  if (!verifyPolicy(policy, policyAuthority).verified) throw new Error('refusing to admit under an UNVERIFIED policy (fail-dangerous)');
  const ev = evaluateAdmission({ cert, certIssuer, policy, artifactBytes, now });
  const core = decisionCore({ gate: makeGateId(gateKeys), app: ev.app, allow: ev.allow, reason: ev.reason, cert_id: ev.cert_id, version: ev.version, cert_level: ev.cert_level, policy_id: ev.policy_id, at });
  const coreBytes = utf8ToBytes(canon(core));
  const decision = { ...core, gate_pub: { ed: bytesToHex(_pub(gateKeys.ed)), mldsa: bytesToHex(_pub(gateKeys.mldsa)) },
    slh_signer_pub_hex: gateKeys.slh ? bytesToHex(_pub(gateKeys.slh)) : null,
    ed_sig: bytesToHex(ed25519.sign(concatBytes(DEC_CTX, coreBytes), gateKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, gateKeys.mldsa.secretKey, { context: DEC_CTX })) };
  if (gateKeys.slh) { decision.gate_pub.slh = bytesToHex(_pub(gateKeys.slh)); decision.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, gateKeys.slh.secretKey, { context: DEC_SLH_CTX })); }
  return decision;
}

// TOTAL / fail-closed. Verifies the decision is authentic under the pinned gate; if opts.{cert,certIssuer,policy,
// policyAuthority} are supplied, RE-EVALUATES and rejects a forged allow (recompute-on-verify) + binds the policy.
export function verifyDecision(decision, trustedGate, opts = {}) {
  try {
    if (!decision || typeof decision !== 'object' || !trustedGate || !trustedGate.ed || !trustedGate.mldsa) return { verified: false };
    if (decision.gate !== makeGateId(trustedGate)) return { verified: false, reason: 'gate id != pinned gate keys' };
    const coreBytes = utf8ToBytes(canon(decisionCore(decision)));
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(decision.ed_sig), concatBytes(DEC_CTX, coreBytes), trustedGate.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(decision.mldsa_sig), coreBytes, trustedGate.mldsa, { context: DEC_CTX }); } catch { pqOk = false; }
    if (trustedGate.slh) { try { slhOk = !!(decision.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(decision.slh_sig), coreBytes, trustedGate.slh, { context: DEC_SLH_CTX })); } catch { slhOk = false; } }
    if (!edOk || !pqOk || !slhOk) return { verified: false, reason: 'decision signature invalid (or required leg missing)' };
    if (opts.cert && opts.policy && opts.certIssuer && opts.policyAuthority) {
      if (!verifyPolicy(opts.policy, opts.policyAuthority).verified) return { verified: false, reason: 'supplied policy not authentic' };
      if (opts.policy.policy_id !== decision.policy_id) return { verified: false, reason: 'decision policy_id != supplied policy (policy swap)' };
      const re = evaluateAdmission({ cert: opts.cert, certIssuer: opts.certIssuer, policy: opts.policy, artifactBytes: opts.artifactBytes, now: opts.now });
      if (re.allow !== decision.allow || re.cert_id !== decision.cert_id) return { verified: false, reason: 'recomputed decision != signed decision (forged verdict)' };
    }
    return { verified: true, allow: decision.allow, app: decision.app, cert_id: decision.cert_id, version: decision.version, policy_id: decision.policy_id };
  } catch { return { verified: false }; }
}

/* ---------- tamper-evident admission LOG (hash-chained audit trail of every allow/deny) ---------- */
export function createAdmissionLog() { return { v: '1', entries: [] }; }
export function appendDecision(log, decision, { at = null } = {}) {
  const prev = log.entries[log.entries.length - 1];
  const seq = log.entries.length, prev_hash = prev ? prev.entry_hash : null;
  const rec = { seq, prev_hash, ts: at, allow: decision.allow, app: decision.app, cert_id: decision.cert_id, version: decision.version, policy_id: decision.policy_id };
  rec.entry_hash = h(canon(rec));
  log.entries.push(rec);
  return { log, entry: rec };
}
export function verifyAdmissionLog(log) {
  try {
    if (!log || typeof log !== 'object' || !Array.isArray(log.entries)) return { intact: false, length: 0, head_hash: null };
    let prevHash = null;
    for (let i = 0; i < log.entries.length; i++) {
      const x = log.entries[i];
      if (x.seq !== i || x.prev_hash !== prevHash) return { intact: false, length: log.entries.length, head_hash: null, at: i };
      const { entry_hash, ...core } = x;
      if (h(canon(core)) !== entry_hash) return { intact: false, length: log.entries.length, head_hash: null, at: i };
      prevHash = x.entry_hash;
    }
    return { intact: true, length: log.entries.length, head_hash: prevHash };
  } catch { return { intact: false, length: 0, head_hash: null }; }
}

/* ---------- self-test: node pqgate.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { issueAppCert } = await import('./pqadmit.mjs');
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const ks = (a, b) => ({ ed: ed(a), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(b)) });
  const certIss = ks(1, 2), polAuth = ks(3, 4), gate = ks(5, 6);
  const tCertIss = { ed: certIss.ed.publicKey, mldsa: certIss.mldsa.publicKey };
  const tPolAuth = { ed: polAuth.ed.publicKey, mldsa: polAuth.mldsa.publicKey };
  const tGate = { ed: gate.ed.publicKey, mldsa: gate.mldsa.publicKey };
  const fw = new Uint8Array(128).fill(0x42);
  const allChecks = { cbom_pass: true, cve_pass: true, opa_pass: true, pqc_pass: true };
  const cert = issueAppCert({ issuerKeys: certIss, app: 'acme/api', version: '2.0.0', artifactBytes: fw, certLevel: 'SOVEREIGN_GOLD', checks: allChecks });

  // policy: authentic, binds rules
  const policy = signPolicy({ authorityKeys: polAuth, app: 'acme/api', minCertLevel: 'SOVEREIGN_PLUS', minVersion: '1.0.0', requireArtifact: true, at: 1 });
  ok(verifyPolicy(policy, tPolAuth).verified === true, 'policy verifies under the pinned authority');
  ok(verifyPolicy(policy, tGate).verified === false, 'policy under a wrong authority → FAILS');
  const polT = JSON.parse(JSON.stringify(policy)); polT.min_cert_level = 'SOVEREIGN_READY';
  ok(verifyPolicy(polT, tPolAuth).verified === false, 'tampered policy rule (weakened floor) → FAILS (policy_id + sig bind the rules)');

  // admit a compliant build
  const dec = admit({ cert, certIssuer: tCertIss, policy, policyAuthority: tPolAuth, artifactBytes: fw, gateKeys: gate, now: 1, at: 1 });
  ok(dec.allow === true, 'compliant GOLD cert + bound artifact → ALLOW');
  ok(verifyDecision(dec, tGate).verified === true, 'signed decision verifies under the pinned gate');
  ok(verifyDecision(dec, tGate, { cert, certIssuer: tCertIss, policy, policyAuthority: tPolAuth, artifactBytes: fw, now: 1 }).verified === true, 'decision + cert + policy → recompute-verifies');
  ok(verifyDecision(dec, { ed: ed(9).publicKey, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey }).verified === false, 'wrong pinned gate → FAILS');

  // forged allow: flip the bit → signature breaks
  const fdec = JSON.parse(JSON.stringify(dec)); fdec.allow = false; // even flipping to a "safer" value breaks the sig (integrity)
  ok(verifyDecision(fdec, tGate).verified === false, 'tampered decision (allow flipped) → signature FAILS');
  // recompute catches an allow that does not match the cert+policy: check a TRUE-allow decision against a swapped artifact
  ok(verifyDecision(dec, tGate, { cert, certIssuer: tCertIss, policy, policyAuthority: tPolAuth, artifactBytes: new Uint8Array(128).fill(9), now: 1 }).verified === false, 'recompute: allow decision vs a swapped binary → re-derived DENY ≠ signed ALLOW → FAILS');

  // deny paths (deterministic): below-floor level, app mismatch, rollback, revoked
  const certReady = issueAppCert({ issuerKeys: certIss, app: 'acme/api', version: '2.0.0', artifactBytes: fw, certLevel: 'SOVEREIGN_READY', checks: allChecks });
  ok(admit({ cert: certReady, certIssuer: tCertIss, policy, policyAuthority: tPolAuth, artifactBytes: fw, gateKeys: gate, now: 1 }).allow === false, 'cert below the signed cert-level floor → DENY');
  const certOther = issueAppCert({ issuerKeys: certIss, app: 'evil/app', version: '2.0.0', artifactBytes: fw, certLevel: 'SOVEREIGN_GOLD', checks: allChecks });
  ok(admit({ cert: certOther, certIssuer: tCertIss, policy, policyAuthority: tPolAuth, artifactBytes: fw, gateKeys: gate, now: 1 }).allow === false, 'cert for a different app → DENY (per-app policy)');
  const polRollback = signPolicy({ authorityKeys: polAuth, app: 'acme/api', minCertLevel: 'SOVEREIGN_PLUS', minVersion: '3.0.0', at: 1 });
  ok(admit({ cert, certIssuer: tCertIss, policy: polRollback, policyAuthority: tPolAuth, artifactBytes: fw, gateKeys: gate, now: 1 }).allow === false, 'version below the signed minVersion floor → DENY (rollback refused)');
  const polRevoked = signPolicy({ authorityKeys: polAuth, app: 'acme/api', minCertLevel: 'SOVEREIGN_PLUS', revoked: [cert.cert_id], at: 1 });
  ok(admit({ cert, certIssuer: tCertIss, policy: polRevoked, policyAuthority: tPolAuth, artifactBytes: fw, gateKeys: gate, now: 1 }).allow === false, 'cert in the signed revoked-set → DENY');

  // fail-dangerous: admit refuses an unauthentic policy
  let refused = false; try { admit({ cert, certIssuer: tCertIss, policy: polT, policyAuthority: tPolAuth, artifactBytes: fw, gateKeys: gate, now: 1 }); } catch { refused = true; }
  ok(refused, 'fail-dangerous: admit() refuses to act under an UNVERIFIED (tampered) policy');

  // admission log (tamper-evident)
  const L = createAdmissionLog();
  appendDecision(L, dec, { at: 1 }); appendDecision(L, admit({ cert: certReady, certIssuer: tCertIss, policy, policyAuthority: tPolAuth, artifactBytes: fw, gateKeys: gate, now: 2 }), { at: 2 });
  ok(L.entries.length === 2 && verifyAdmissionLog(L).intact === true, 'admission log records allow+deny → intact hash-chain');
  const Lt = JSON.parse(JSON.stringify(L)); Lt.entries[0].allow = false;
  ok(verifyAdmissionLog(Lt).intact === false, 'altering a logged decision → log NOT intact (tamper-evident)');

  // 3-leg hybrid
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(7));
  const gate3 = { ed: gate.ed, mldsa: gate.mldsa, slh };
  const tGate3 = { ed: tGate.ed, mldsa: tGate.mldsa, slh: slh.publicKey };
  const dec3 = admit({ cert, certIssuer: tCertIss, policy, policyAuthority: tPolAuth, artifactBytes: fw, gateKeys: gate3, now: 1 });
  ok(typeof dec3.slh_sig === 'string' && verifyDecision(dec3, tGate3).verified === true, '3-leg (Ed25519∧ML-DSA∧SLH) decision verifies');
  const dec3s = JSON.parse(JSON.stringify(dec3)); dec3s.slh_sig = '00';
  ok(verifyDecision(dec3s, tGate3).verified === false, 'stripped SLH leg fails when gate.slh pinned (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { allow: true }, { ...dec, ed_sig: 'zz' }]) { try { if (verifyDecision(bad, tGate).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed decisions → verified:false, never throws');
  let totalP = true; for (const bad of [null, undefined, {}, 42, { policy_id: 'x' }]) { try { if (verifyPolicy(bad, tPolAuth).verified !== false) totalP = false; } catch { totalP = false; } }
  ok(totalP, 'TOTAL: malformed policies → verified:false, never throws');
  let totalL = true; for (const bad of [null, undefined, {}, 42, { entries: 'x' }, { entries: [{ seq: 3 }] }]) { try { if (verifyAdmissionLog(bad).intact !== false) totalL = false; } catch { totalL = false; } }
  ok(totalL, 'TOTAL: malformed logs → intact:false, never throws');

  console.log('pqgate self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgate\.mjs$/.test(process.argv[1] || '')) selfTest();
