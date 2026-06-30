/*!
 * pqadmit — SovereignMarket: signed app certificate + deployment ADMISSION control (reference, DRAFT).
 *
 * A marketplace / cert authority hybrid-signs an AppCertificate recording a deployable artifact's supply-chain checks
 * (CBOM, CVE, OPA policy, PQC) + a cert level (SOVEREIGN_READY < _PLUS < _GOLD), bound to the EXACT artifact digest.
 * An admission gate verifies — BEFORE deploy — that: the cert is from the pinned authority; the artifact about to run
 * hashes to the attested digest (no swap); the cert level meets the policy floor; it is unexpired; its recorded checks
 * passed; and it is NOT revoked. Revocation is a separately-signed record the admission side collects into a deny-set.
 *
 * (Distinct from pqattest, which is NOTARIZATION — timestamp + transparency-log + seal. pqadmit is the deploy-time
 * authorization gate: "may THIS exact artifact run here, now, under this policy?")
 *
 * FALSIFIABLE PROPERTIES (given the cert + the PINNED authority keys): the authority attested THIS exact artifact at
 * THIS level (forging needs a classical AND a lattice [AND hash-based] break); a different binary cannot deploy under
 * the cert (digest binding); a revoked / under-graded / check-failing artifact is refused. Ed25519 ∧ ML-DSA-87 ∧
 * optional SLH-DSA-256f (anti-downgrade), dual-anchor-ready. Unaudited reference implementation.
 *
 * Self-test: node pqadmit.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

const ADMIT_CTX = utf8ToBytes('trelyan-deploy-admission-v1');       // signing domain (Ed25519 + ML-DSA legs)
const ADMIT_SLH_CTX = utf8ToBytes('trelyan-deploy-admission-slh-v1'); // distinct domain for the optional SLH leg
const REV_CTX = utf8ToBytes('trelyan-deploy-revocation-v1');        // distinct domain for revocation records
const REV_SLH_CTX = utf8ToBytes('trelyan-deploy-revocation-slh-v1');

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
export function makeAuthorityId(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('authority keys must be { ed, mldsa[, slh] }');
  return 'admit:trelyan:authority:v1:' + bytesToHex(sha256(concatBytes(utf8ToBytes('admit:trelyan:authority:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}

export const CERT_LEVELS = ['SOVEREIGN_READY', 'SOVEREIGN_PLUS', 'SOVEREIGN_GOLD'];
const CERT_RANK = { SOVEREIGN_READY: 1, SOVEREIGN_PLUS: 2, SOVEREIGN_GOLD: 3 };
function normChecks(c) {
  const o = (c && typeof c === 'object') ? c : {};
  return { cbom_pass: !!o.cbom_pass, cve_pass: !!o.cve_pass, opa_pass: !!o.opa_pass, pqc_pass: !!o.pqc_pass };
}
// cert_id is a deterministic function of the identifying fields (used as the revocation key).
function certId(m) { return bytesToHex(sha256(utf8ToBytes(canon({ issuer: m.issuer, app: m.app, version: m.version, artifact_digest: m.artifact_digest })))); }
// numeric/semver-ish version compare for the anti-rollback floor: -1 / 0 / 1, or null if either side is unparseable.
function cmpVersion(a, b) {
  const seg = (v) => String(v).split(/[^0-9]+/).filter((s) => s !== '').map(Number);
  const pa = seg(a), pb = seg(b);
  if (!pa.length || !pb.length) return null;     // unparseable → caller treats as fail-dangerous
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) { const x = pa[i] || 0, y = pb[i] || 0; if (x !== y) return x < y ? -1 : 1; }
  return 0;
}
function certCore(m) {
  return { v: '1', issuer: m.issuer, app: m.app, version: m.version, artifact_digest: m.artifact_digest,
    sbom_hash: m.sbom_hash ?? null, cert_level: m.cert_level, checks: m.checks, policy_id: m.policy_id ?? null,
    issued_at: m.issued_at ?? null, expires_at: m.expires_at ?? null, cert_id: m.cert_id, anchor_commitment: m.anchor_commitment ?? null };
}

// issuerKeys = authority { ed, mldsa[, slh] }. Provide artifactBytes (hashed here) OR artifactDigest (hex sha256).
export function issueAppCert({ issuerKeys, app, version, artifactBytes, artifactDigest, sbomHash, certLevel, checks, policyId, issuedAt, expiresAt }) {
  if (!issuerKeys || !issuerKeys.ed || !issuerKeys.mldsa) throw new Error('issuerKeys must be { ed, mldsa[, slh] }');
  if (!app || !version) throw new Error('app and version are required');
  if (!CERT_RANK[certLevel]) throw new Error('certLevel must be one of ' + CERT_LEVELS.join('/'));
  const digest = artifactBytes ? bytesToHex(sha256(artifactBytes)) : String(artifactDigest || '');
  if (!/^[0-9a-f]{64}$/i.test(digest)) throw new Error('provide artifactBytes or a 32-byte hex artifactDigest');
  const issuer = makeAuthorityId(issuerKeys);
  const idFields = { issuer, app: String(app), version: String(version), artifact_digest: digest.toLowerCase() };
  const cert_id = certId(idFields);
  const anchor_commitment = bytesToHex(sha256(utf8ToBytes('trelyan-admit-anchor-v1' + canon({ ...idFields, cert_id }))));
  const core = certCore({ ...idFields, sbom_hash: sbomHash ?? null, cert_level: certLevel, checks: normChecks(checks),
    policy_id: policyId ?? null, issued_at: issuedAt ?? null, expires_at: expiresAt ?? null, cert_id, anchor_commitment });
  const coreBytes = utf8ToBytes(canon(core));
  const cert = { ...core,
    issuer_pub: { ed: bytesToHex(_pub(issuerKeys.ed)), mldsa: bytesToHex(_pub(issuerKeys.mldsa)) },
    ed_sig: bytesToHex(ed25519.sign(concatBytes(ADMIT_CTX, coreBytes), issuerKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, issuerKeys.mldsa.secretKey, { context: ADMIT_CTX })) };
  if (issuerKeys.slh) { cert.issuer_pub.slh = bytesToHex(_pub(issuerKeys.slh)); cert.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, issuerKeys.slh.secretKey, { context: ADMIT_SLH_CTX })); }
  return cert;
}

// a separately-signed revocation. The admission side verifies it, then adds cert_id to its deny-set.
export function revokeCert({ issuerKeys, certId: cid, reason, revokedAt }) {
  if (!issuerKeys || !issuerKeys.ed || !issuerKeys.mldsa) throw new Error('issuerKeys must be { ed, mldsa[, slh] }');
  if (!cid) throw new Error('certId is required');
  const core = { v: '1', issuer: makeAuthorityId(issuerKeys), cert_id: String(cid), reason: reason ?? null, revoked_at: revokedAt ?? null };
  const coreBytes = utf8ToBytes(canon(core));
  const rec = { ...core, ed_sig: bytesToHex(ed25519.sign(concatBytes(REV_CTX, coreBytes), issuerKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, issuerKeys.mldsa.secretKey, { context: REV_CTX })) };
  if (issuerKeys.slh) rec.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, issuerKeys.slh.secretKey, { context: REV_SLH_CTX }));
  return rec;
}
export function verifyRevocation(rec, trustedIssuer) {
  try {
    if (!rec || typeof rec !== 'object' || !trustedIssuer || !trustedIssuer.ed || !trustedIssuer.mldsa) return { verified: false };
    if (rec.issuer !== makeAuthorityId(trustedIssuer)) return { verified: false };
    const coreBytes = utf8ToBytes(canon({ v: rec.v, issuer: rec.issuer, cert_id: rec.cert_id, reason: rec.reason ?? null, revoked_at: rec.revoked_at ?? null }));
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(rec.ed_sig), concatBytes(REV_CTX, coreBytes), trustedIssuer.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(rec.mldsa_sig), coreBytes, trustedIssuer.mldsa, { context: REV_CTX }); } catch { pqOk = false; }
    if (trustedIssuer.slh) { try { slhOk = !!(rec.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(rec.slh_sig), coreBytes, trustedIssuer.slh, { context: REV_SLH_CTX })); } catch { slhOk = false; } }
    return { verified: edOk && pqOk && slhOk, cert_id: rec.cert_id, reason: rec.reason ?? null };
  } catch { return { verified: false }; }
}

// admission gate. TOTAL / fail-closed. trustedIssuer = pinned authority { ed, mldsa[, slh] }.
// opts: artifactBytes (the binary about to deploy — bound by DEFAULT), allowUnboundArtifact (DANGEROUS skip),
// now (expiry), minCertLevel (require >= this rank), minVersion (anti-rollback floor — refuse older versions),
// revoked ({has(cert_id)->bool} deny-set), requireAllChecks (default TRUE — any failing recorded check refused),
// expectedAnchor.
// REVOCATION CAVEAT (apex-team / council): the deny-set only works if the gate HAS received the revocation — a
// withheld/undelivered revocation admits a revoked cert (inherent deny-list limitation). Mitigate with SHORT
// expires_at + an online/transparency-log check anchored via anchor_commitment; do not rely on revocation alone.
export function verifyAdmission(cert, trustedIssuer, opts = {}) {
  try {
    if (!cert || typeof cert !== 'object' || !trustedIssuer || !trustedIssuer.ed || !trustedIssuer.mldsa) return { verified: false };
    if (!CERT_RANK[cert.cert_level]) return { verified: false, reason: 'bad cert_level' };
    if (cert.issuer !== makeAuthorityId(trustedIssuer)) return { verified: false, reason: 'issuer id != pinned authority keys' };
    if (cert.cert_id !== certId(cert)) return { verified: false, reason: 'cert_id does not bind the identifying fields' };
    const coreBytes = utf8ToBytes(canon(certCore(cert)));
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(cert.ed_sig), concatBytes(ADMIT_CTX, coreBytes), trustedIssuer.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(cert.mldsa_sig), coreBytes, trustedIssuer.mldsa, { context: ADMIT_CTX }); } catch { pqOk = false; }
    if (trustedIssuer.slh) { try { slhOk = !!(cert.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(cert.slh_sig), coreBytes, trustedIssuer.slh, { context: ADMIT_SLH_CTX })); } catch { slhOk = false; } }
    if (!edOk || !pqOk || !slhOk) return { verified: false, reason: 'hybrid signature invalid (or required leg missing)' };
    // artifact binding — only the attested binary may deploy. SAFE DEFAULT: require it (apex-team pqfirmware lesson).
    let artifactOk;
    if (opts.artifactBytes) artifactOk = bytesToHex(sha256(opts.artifactBytes)).toLowerCase() === cert.artifact_digest;
    else artifactOk = opts.allowUnboundArtifact === true;
    if (!artifactOk) return { verified: false, reason: 'deployed artifact != attested digest (or no artifact bound)' };
    if (cert.expires_at != null && opts.now != null && Number(opts.now) >= Number(cert.expires_at)) return { verified: false, reason: 'expired' };
    if (opts.minCertLevel != null) { const need = CERT_RANK[opts.minCertLevel]; if (!need || CERT_RANK[cert.cert_level] < need) return { verified: false, reason: 'cert level below policy floor' }; }
    // monotonic version floor — refuse a rollback to an older (signed-but-now-vulnerable) version (apex-team fix,
    // same anti-rollback guard as pqfirmware). The gate supplies its known-good floor as opts.minVersion.
    if (opts.minVersion != null) {
      const r = cmpVersion(cert.version, opts.minVersion);
      if (r === null) return { verified: false, reason: 'version not numerically comparable to the floor (fail-dangerous)' };
      if (r < 0) return { verified: false, reason: 'version below floor (rollback to an older version refused)' };
    }
    if (opts.requireAllChecks !== false) { const c = cert.checks || {}; if (!(c.cbom_pass && c.cve_pass && c.opa_pass && c.pqc_pass)) return { verified: false, reason: 'a recorded supply-chain check did not pass' }; }
    if (opts.revoked && typeof opts.revoked.has === 'function' && opts.revoked.has(cert.cert_id)) return { verified: false, reason: 'revoked' };
    if (opts.expectedAnchor != null && cert.anchor_commitment !== opts.expectedAnchor) return { verified: false, reason: 'anchor commitment mismatch' };
    return { verified: true, artifactOk, cert_id: cert.cert_id, app: cert.app, version: cert.version, cert_level: cert.cert_level, artifact_digest: cert.artifact_digest };
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqadmit.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const auth = { ed: ed(1), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)) };
  const tAuth = { ed: auth.ed.publicKey, mldsa: auth.mldsa.publicKey };
  const attacker = { ed: ed(9), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)) };
  const image = new Uint8Array(4096).fill(0xab);           // the OCI image / artifact bytes
  const allChecks = { cbom_pass: true, cve_pass: true, opa_pass: true, pqc_pass: true };

  const c = issueAppCert({ issuerKeys: auth, app: 'acme/api', version: '1.4.2', artifactBytes: image, sbomHash: 'ab'.repeat(32), certLevel: 'SOVEREIGN_PLUS', checks: allChecks, policyId: 'opa-bundle-10', expiresAt: 1000 });
  ok(typeof c.cert_id === 'string' && c.artifact_digest === bytesToHex(sha256(image)), 'cert binds artifact digest + has a cert_id');
  ok(verifyAdmission(c, tAuth, { artifactBytes: image, now: 1, minCertLevel: 'SOVEREIGN_READY' }).verified === true, 'valid cert + bound artifact + meets floor -> ADMIT');
  ok(verifyAdmission(c, { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }, { artifactBytes: image, now: 1 }).verified === false, 'wrong pinned authority -> FAILS');
  const evil = new Uint8Array(4096).fill(0xcd);
  ok(verifyAdmission(c, tAuth, { artifactBytes: evil, now: 1 }).verified === false, 'deployed binary != attested digest -> FAILS (no swap)');
  ok(verifyAdmission(c, tAuth, { now: 1 }).verified === false, 'no artifact bound -> FAILS by default (must bind the deployed image)');
  ok(verifyAdmission(c, tAuth, { now: 1, allowUnboundArtifact: true }).verified === true, 'explicit allowUnboundArtifact -> metadata-only check passes');
  ok(verifyAdmission(c, tAuth, { artifactBytes: image, now: 1000 }).verified === false, 'expired -> FAILS');
  ok(verifyAdmission(c, tAuth, { artifactBytes: image, now: 1, minCertLevel: 'SOVEREIGN_GOLD' }).verified === false, 'cert PLUS below GOLD policy floor -> FAILS');
  // APEX-TEAM FIX: monotonic version floor — no rollback to an older signed-but-vulnerable version (council #1)
  ok(verifyAdmission(c, tAuth, { artifactBytes: image, now: 1, minVersion: '1.4.2' }).verified === true, 'version == floor -> ADMIT (re-deploy ok)');
  ok(verifyAdmission(c, tAuth, { artifactBytes: image, now: 1, minVersion: '1.4.1' }).verified === true, 'version newer than floor -> ADMIT');
  ok(verifyAdmission(c, tAuth, { artifactBytes: image, now: 1, minVersion: '1.5.0' }).verified === false, 'version BELOW floor (1.4.2 < 1.5.0) -> rollback REFUSED');
  const cNightly = issueAppCert({ issuerKeys: auth, app: 'acme/api', version: 'nightly', artifactBytes: image, certLevel: 'SOVEREIGN_GOLD', checks: allChecks });
  ok(verifyAdmission(cNightly, tAuth, { artifactBytes: image, minVersion: '1.0.0' }).verified === false, 'unparseable version vs a floor -> fail-dangerous REFUSE');
  // checks must pass (default ON)
  const cBad = issueAppCert({ issuerKeys: auth, app: 'acme/api', version: '1.4.3', artifactBytes: image, certLevel: 'SOVEREIGN_GOLD', checks: { cbom_pass: true, cve_pass: false, opa_pass: true, pqc_pass: true } });
  ok(verifyAdmission(cBad, tAuth, { artifactBytes: image }).verified === false, 'a recorded CVE failure -> refused admission by default (no rubber-stamp)');
  ok(verifyAdmission(cBad, tAuth, { artifactBytes: image, requireAllChecks: false }).verified === true, 'requireAllChecks:false -> the check gate can be explicitly relaxed');
  // tamper: bump cert_level without re-sign
  const t = JSON.parse(JSON.stringify(c)); t.cert_level = 'SOVEREIGN_GOLD';
  ok(verifyAdmission(t, tAuth, { artifactBytes: image, now: 1 }).verified === false, 'tampered cert_level (re-sign-free) -> signature FAILS');
  const t2 = JSON.parse(JSON.stringify(c)); t2.cert_id = 'ff'.repeat(32);
  ok(verifyAdmission(t2, tAuth, { artifactBytes: image, now: 1 }).verified === false, 'swapped cert_id -> id no longer binds fields -> FAILS');

  // revocation flow
  const rev = revokeCert({ issuerKeys: auth, certId: c.cert_id, reason: 'cve-2026-9999', revokedAt: 5 });
  ok(verifyRevocation(rev, tAuth).verified === true && verifyRevocation(rev, tAuth).cert_id === c.cert_id, 'revocation record verifies under the authority');
  ok(verifyRevocation(JSON.parse(JSON.stringify(rev)), { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }).verified === false, 'forged revocation (wrong authority) -> FAILS (cannot DoS by revoking another app cert)');
  const denySet = new Set([verifyRevocation(rev, tAuth).cert_id]);
  ok(verifyAdmission(c, tAuth, { artifactBytes: image, now: 1, revoked: denySet }).verified === false, 'revoked cert in the admission deny-set -> FAILS');

  // anchor pin
  ok(verifyAdmission(c, tAuth, { artifactBytes: image, now: 1, expectedAnchor: c.anchor_commitment }).verified === true && verifyAdmission(c, tAuth, { artifactBytes: image, now: 1, expectedAnchor: 'beef' }).verified === false, 'expectedAnchor pin enforced');

  // 3-leg hash-based hardening
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5));
  const auth3 = { ed: auth.ed, mldsa: auth.mldsa, slh };
  const tAuth3 = { ed: tAuth.ed, mldsa: tAuth.mldsa, slh: slh.publicKey };
  const c3 = issueAppCert({ issuerKeys: auth3, app: 'acme/api', version: '2.0.0', artifactBytes: image, certLevel: 'SOVEREIGN_GOLD', checks: allChecks });
  ok(typeof c3.slh_sig === 'string' && verifyAdmission(c3, tAuth3, { artifactBytes: image }).verified === true, '3-leg cert verifies');
  const c3s = JSON.parse(JSON.stringify(c3)); c3s.slh_sig = '00';
  ok(verifyAdmission(c3s, tAuth3, { artifactBytes: image }).verified === false, 'stripped SLH leg fails when authority.slh pinned (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { cert_level: 'X' }, { ...c, ed_sig: 'zz' }]) { try { if (verifyAdmission(bad, tAuth, { artifactBytes: image }).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed certs -> verified:false, never throws');

  console.log('pqadmit self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqadmit\.mjs$/.test(process.argv[1] || '')) selfTest();
