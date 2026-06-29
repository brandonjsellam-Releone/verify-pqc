/*!
 * pqposture — read-only PQC POSTURE scanner + signed posture Evidence Pack (reference, DRAFT). Market-#1 ungated wedge:
 * probe a TLS endpoint and report (a) whether the KEY-EXCHANGE leg negotiated an ML-KEM hybrid group and (b) whether the
 * AUTHENTICATION leg (leaf certificate key) is still classical (RSA/ECDSA) — then sign the report so a third party can
 * verify it. It NEVER terminates or proxies traffic and custodies no plaintext (that's the FIPS/pen-audit-gated product
 * we do NOT ship); this is an external, read-only observation + a falsifiable, dual-signed posture artifact.
 *
 * NOVEL FALSIFIABLE PROPERTY: a buyer (or their auditor) gets a dated, Ed25519∧ML-DSA-87 dual-signed report stating the
 * exact TLS version, KEX group, and leaf-cert key type THIS probe observed, gradeable A–F — independently re-verifiable
 * (re-run the probe; verify the signature under the pinned scanner key). HONEST / the make-or-break caveat: KEX-leg PQ
 * detection requires the PROBE CLIENT to be able to OFFER ML-KEM (OpenSSL >= 3.5). If it cannot, the KEX result is
 * reported as INCONCLUSIVE — never as "classical" — so we never falsely fail a PQ-capable server. This is "posture
 * observed in our handshake," downgrade-detecting under the declared trust model; it is NOT a penetration test, and a
 * fuller probe enumerates every offered group. LIMITATION (verified on Node v24 / OpenSSL 3.5.6): Node's public TLS API
 * does NOT expose the negotiated TLS-1.3 KEX group (getEphemeralKeyInfo() returns {}), so the KEX leg is reported
 * INCONCLUSIVE until the planned raw ClientHello/ServerHello key_share parser lands; the TLS-version + auth-leg
 * (leaf-certificate key type) findings ARE reliable today.
 *
 * Dependency-light: node:tls + @noble/curves (ed25519) + @noble/post-quantum (ml-dsa-87) + @noble/hashes (sha256).
 * Self-test (offline): node pqposture.mjs   ·   Live probe: PQC_LIVE_PROBE=1 node pqposture.mjs cloudflare.com
 */
import tls from 'node:tls';
import { probeKexGroup } from './pqtls.mjs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

const POSTURE_CTX = utf8ToBytes('trelyan-pqposture-v1');
const POSTURE_HASH_TAG = utf8ToBytes('trelyan-pqposture-hash-v1');

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const reportHash = (coreBytes) => bytesToHex(sha256(concatBytes(POSTURE_HASH_TAG, coreBytes)));

// ---- classification (pure functions — testable with no network) ----
export function classifyKex(group) {
  const g = String(group || '');
  if (/MLKEM|KYBER/i.test(g)) return { leg: 'kex', group: g, pq: true, risk: 'pq-hybrid', label: 'ML-KEM hybrid (' + g + ')' };
  if (/^X25519$|^X448$|prime256|secp|^P-?\d|ECDH/i.test(g)) return { leg: 'kex', group: g, pq: false, risk: 'quantum-vulnerable', label: 'classical ECDHE (' + g + ') — harvest-now-decrypt-later' };
  if (/^DH|FFDHE|^DHE/i.test(g)) return { leg: 'kex', group: g, pq: false, risk: 'quantum-vulnerable', label: 'finite-field DH (' + g + ')' };
  return { leg: 'kex', group: g, pq: false, risk: 'unknown', label: g || 'unknown KEX group' };
}
export function classifyAuth(keyType, detail) {
  const t = String(keyType || '').toUpperCase();
  if (/ML-?DSA|DILITHIUM|SLH-?DSA|SPHINCS|FALCON/.test(t)) return { leg: 'auth', key_type: keyType, pq: true, risk: 'pq', label: 'PQ certificate (' + keyType + ')' };
  if (t === 'RSA') return { leg: 'auth', key_type: 'RSA', pq: false, risk: 'quantum-forgeable', label: 'RSA leaf cert (' + (detail || '') + ')' };
  if (t === 'EC' || t === 'ECDSA') return { leg: 'auth', key_type: 'EC', pq: false, risk: 'quantum-forgeable', label: 'ECDSA leaf cert (' + (detail || '') + ')' };
  return { leg: 'auth', key_type: keyType || 'unknown', pq: false, risk: 'unknown', label: 'unknown leaf-cert key type' };
}
export function classifyTls(version) {
  const v = String(version || '');
  if (v === 'TLSv1.3') return { version: v, risk: 'ok' };
  if (v === 'TLSv1.2') return { version: v, risk: 'acceptable' };
  if (/TLSv1(\.1)?$|SSLv/.test(v)) return { version: v, risk: 'broken' };
  return { version: v || 'unknown', risk: 'unknown' };
}
// grade: F if TLS broken; A both legs PQ; B KEX PQ + classical auth; C KEX inconclusive; D both classical; else N/A.
export function gradePosture({ kex, auth, tls, inconclusive }) {
  if (tls && tls.risk === 'broken') return 'F';
  if (inconclusive || (kex && kex.risk === 'inconclusive')) return 'C';
  const kpq = kex && kex.pq === true, apq = auth && auth.pq === true;
  if (kpq && apq) return 'A';
  if (kpq && !apq) return 'B';
  if (!kpq && (kex && kex.risk === 'quantum-vulnerable')) return 'D';
  return 'N/A';
}

// build a posture report from a probe() observation (or a failed probe)
export function buildPostureReport(obs) {
  if (!obs || !obs.ok) return { v: '1', ok: false, host: obs && obs.host, port: obs && obs.port, observed_at: obs && obs.observed_at, reason: (obs && obs.reason) || 'probe failed', grade: 'N/A' };
  const kex = !obs.client_pq_capable
    ? { leg: 'kex', group: obs.kex_group, pq: null, risk: 'inconclusive', label: 'INCONCLUSIVE — this probe client (OpenSSL ' + obs.client_openssl + ') cannot offer ML-KEM, so server PQ-KEX support was not tested' }
    : (obs.kex_group
      ? classifyKex(obs.kex_group)
      : { leg: 'kex', group: '', pq: null, risk: 'inconclusive', label: "INCONCLUSIVE — the raw key_share probe returned no group (network/parse error) and Node's TLS API does not expose the TLS-1.3 group either. The TLS-version + auth-leg findings ARE reliable." });
  const auth = classifyAuth(obs.auth_key_type, obs.auth_detail);
  const tls = classifyTls(obs.tls_version);
  return {
    v: '1', ok: true, host: obs.host, port: obs.port, observed_at: obs.observed_at,
    tls_version: obs.tls_version, cipher: obs.cipher || null, kex_source: obs.kex_source || 'node-api', kex, auth,
    grade: gradePosture({ kex, auth, tls, inconclusive: kex.risk === 'inconclusive' }),
    client: { openssl: obs.client_openssl, pq_capable: obs.client_pq_capable },
    note: 'Posture observed in THIS probe (downgrade-detecting under the declared trust model). The KEX group is read from the raw TLS key_share (the probe offers ML-KEM first; kex_source = raw-hrr / raw-serverhello, or a node-api fallback); the auth leg is classified from the leaf certificate key type. Not a penetration test; a fuller probe enumerates every offered group.',
  };
}

// ---- signed posture Evidence Pack (hybrid Ed25519 AND ML-DSA-87) ----
function reportCore(r) { const { ed_sig, mldsa_sig, signer_pub, report_hash, ...core } = r; return core; }
// signer = { ed:{secretKey,publicKey}, mldsa:{secretKey,publicKey} }
export function signPosture(report, signer) {
  if (!signer || !signer.ed || !signer.mldsa) throw new Error('signer must be { ed, mldsa } keypairs');
  const coreBytes = utf8ToBytes(canon(report));
  return {
    ...report,
    signer_pub: { ed: bytesToHex(signer.ed.publicKey), mldsa: bytesToHex(signer.mldsa.publicKey) },
    ed_sig: bytesToHex(ed25519.sign(concatBytes(POSTURE_CTX, coreBytes), signer.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, signer.mldsa.secretKey, { context: POSTURE_CTX })),
    report_hash: reportHash(coreBytes),
  };
}
// TOTAL / fail-closed. trusted = { ed, mldsa } pinned scanner pubkeys (required for authenticity).
export function verifyPosture(pack, trusted) {
  try {
    if (!pack || typeof pack !== 'object' || !trusted || !trusted.ed || !trusted.mldsa) return { verified: false };
    const coreBytes = utf8ToBytes(canon(reportCore(pack)));
    const hashOk = reportHash(coreBytes) === pack.report_hash;
    let edOk = false, pqOk = false;
    try { edOk = ed25519.verify(hexToBytes(pack.ed_sig), concatBytes(POSTURE_CTX, coreBytes), trusted.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(pack.mldsa_sig), coreBytes, trusted.mldsa, { context: POSTURE_CTX }); } catch { pqOk = false; }
    return { verified: hashOk && edOk && pqOk, hashOk, edOk, pqOk, grade: pack.grade, host: pack.host };
  } catch { return { verified: false }; }
}

// ---- live probe (read-only TLS handshake) ----
function clientOpenssl() { return (process.versions && process.versions.openssl) || '0'; }
function clientPqCapable() { const m = clientOpenssl().match(/^(\d+)\.(\d+)/); return !!m && (Number(m[1]) > 3 || (Number(m[1]) === 3 && Number(m[2]) >= 5)); }

function tlsProbe(host, port = 443, opts = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (o) => { if (!done) { done = true; try { socket.destroy(); } catch { /* noop */ } resolve(o); } };
    const socket = tls.connect({ host, port, servername: host, minVersion: 'TLSv1.2', rejectUnauthorized: false, ...(opts.tlsOpts || {}) }, () => {
      try {
        const cipher = socket.getCipher ? socket.getCipher() : null;
        const kx = socket.getEphemeralKeyInfo ? socket.getEphemeralKeyInfo() : null;
        const cert = (socket.getPeerCertificate ? socket.getPeerCertificate(false) : {}) || {};
        const authKeyType = cert.modulus ? 'RSA' : (cert.asn1Curve || cert.pubkey ? 'EC' : 'unknown');
        const authDetail = cert.asn1Curve || (cert.bits ? cert.bits + '-bit' : '');
        finish({ ok: true, host, port, observed_at: Date.now(), tls_version: socket.getProtocol && socket.getProtocol(),
          cipher: cipher && cipher.name, kex_group: (kx && kx.name) || '', kex_type: (kx && kx.type) || '',
          auth_key_type: authKeyType, auth_detail: authDetail, client_openssl: clientOpenssl(), client_pq_capable: clientPqCapable() });
      } catch (e) { finish({ ok: false, host, port, reason: 'parse: ' + e.message }); }
    });
    socket.setTimeout(opts.timeout || 10000, () => finish({ ok: false, host, port, reason: 'timeout' }));
    socket.on('error', (e) => finish({ ok: false, host, port, reason: e.message }));
  });
}
// combined probe: the raw KEX prober (offers ML-KEM first -> authoritative negotiated group) runs alongside the TLS
// handshake (TLS version / cipher / leaf-cert auth leg). The raw group overrides Node's (empty) getEphemeralKeyInfo.
export async function probe(host, port = 443, opts = {}) {
  const [tlsObs, kex] = await Promise.all([
    tlsProbe(host, port, opts),
    probeKexGroup(host, port, opts).catch((e) => ({ error: String((e && e.message) || e) })),
  ]);
  if (!tlsObs || !tlsObs.ok) return tlsObs || { ok: false, host, port, reason: 'tls probe failed' };
  const rawOk = !!(kex && !kex.error && kex.group_name);
  return { ...tlsObs,
    kex_group: rawOk ? kex.group_name : tlsObs.kex_group,
    kex_source: rawOk ? (kex.is_hrr ? 'raw-hrr' : 'raw-serverhello') : 'node-api',
    client_pq_capable: rawOk ? true : tlsObs.client_pq_capable };  // the raw prober ALWAYS offers ML-KEM, so a hit genuinely tested PQ-KEX
}
export async function scanAndSign(host, port, signer, opts = {}) { return signPosture(buildPostureReport(await probe(host, port, opts)), signer); }

/* ---------- self-test (offline) + optional live probe ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // classification
  ok(classifyKex('X25519MLKEM768').pq === true && classifyKex('X25519MLKEM768').risk === 'pq-hybrid', 'ML-KEM hybrid group -> PQ KEX detected');
  ok(classifyKex('X25519').pq === false && classifyKex('X25519').risk === 'quantum-vulnerable', 'classical X25519 -> quantum-vulnerable (HNDL)');
  ok(classifyKex('prime256v1').risk === 'quantum-vulnerable', 'P-256 ECDHE -> quantum-vulnerable');
  ok(classifyAuth('RSA', '2048-bit').pq === false && classifyAuth('RSA').risk === 'quantum-forgeable', 'RSA leaf cert -> quantum-forgeable auth leg');
  ok(classifyAuth('EC', 'prime256v1').pq === false, 'ECDSA leaf cert -> classical auth leg');
  ok(classifyAuth('ML-DSA-87').pq === true, 'ML-DSA leaf cert -> PQ auth leg');
  ok(classifyTls('TLSv1.3').risk === 'ok' && classifyTls('TLSv1').risk === 'broken', 'TLS version classification');

  // grading
  ok(gradePosture({ kex: classifyKex('X25519MLKEM768'), auth: classifyAuth('ML-DSA-87'), tls: classifyTls('TLSv1.3') }) === 'A', 'both legs PQ + TLS1.3 -> A');
  ok(gradePosture({ kex: classifyKex('X25519MLKEM768'), auth: classifyAuth('RSA'), tls: classifyTls('TLSv1.3') }) === 'B', 'KEX PQ + classical auth -> B');
  ok(gradePosture({ kex: classifyKex('X25519'), auth: classifyAuth('RSA'), tls: classifyTls('TLSv1.3') }) === 'D', 'both classical -> D');
  ok(gradePosture({ kex: classifyKex('X25519'), auth: classifyAuth('RSA'), tls: classifyTls('TLSv1') }) === 'F', 'broken TLS -> F');
  ok(gradePosture({ inconclusive: true }) === 'C', 'inconclusive KEX -> C (not falsely failed)');

  // build report: PQ-capable client sees ML-KEM + RSA -> grade B
  const r1 = buildPostureReport({ ok: true, host: 'example.com', port: 443, observed_at: 1000, tls_version: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', kex_group: 'X25519MLKEM768', auth_key_type: 'RSA', auth_detail: '2048-bit', client_openssl: '3.5.0', client_pq_capable: true });
  ok(r1.grade === 'B' && r1.kex.pq === true && r1.auth.pq === false, 'report: ML-KEM KEX + RSA auth -> grade B');
  ok(buildPostureReport({ ok: true, host: 'h', port: 443, observed_at: 1, tls_version: 'TLSv1.3', kex_group: 'X25519MLKEM768', kex_source: 'raw-hrr', auth_key_type: 'RSA', client_pq_capable: true }).kex_source === 'raw-hrr', 'raw key_share source (raw-hrr) is recorded in the signed report');
  // build report: client CANNOT offer ML-KEM -> KEX inconclusive (never falsely "classical")
  const r2 = buildPostureReport({ ok: true, host: 'example.com', port: 443, observed_at: 1000, tls_version: 'TLSv1.3', cipher: 'x', kex_group: 'X25519', auth_key_type: 'RSA', auth_detail: '2048-bit', client_openssl: '3.0.2', client_pq_capable: false });
  ok(r2.kex.risk === 'inconclusive' && r2.grade === 'C', 'old probe client -> KEX INCONCLUSIVE (honest, not a false classical fail)');
  // failed probe
  ok(buildPostureReport({ ok: false, host: 'x', reason: 'timeout' }).grade === 'N/A', 'failed probe -> grade N/A');

  // signed posture Evidence Pack (hybrid)
  const signer = { ed: { secretKey: new Uint8Array(32).fill(7), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(7)) }, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(8)) };
  const trusted = { ed: signer.ed.publicKey, mldsa: signer.mldsa.publicKey };
  const pack = signPosture(r1, signer);
  ok(verifyPosture(pack, trusted).verified === true, 'signed posture pack verifies under the pinned scanner key (Ed25519 AND ML-DSA-87)');
  const tampered = JSON.parse(JSON.stringify(pack)); tampered.grade = 'A';
  ok(verifyPosture(tampered, trusted).verified === false, 'tampered grade (B->A) -> verify FAILS');
  ok(verifyPosture(pack, { ed: ed25519.getPublicKey(new Uint8Array(32).fill(9)), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey }).verified === false, 'wrong pinned scanner key -> FAILS');
  const stripped = JSON.parse(JSON.stringify(pack)); stripped.mldsa_sig = '00';
  ok(verifyPosture(stripped, trusted).verified === false, 'stripped PQ leg -> FAILS (anti-downgrade)');
  let total = true; for (const bad of [null, undefined, {}, 42, []]) { try { if (verifyPosture(bad, trusted).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed packs -> verified:false, never throws');

  // optional LIVE probe (off by default; never in CI)
  if (process.env.PQC_LIVE_PROBE) {
    const host = process.argv[2] || 'cloudflare.com';
    const live = buildPostureReport(await probe(host, 443, { timeout: 8000 }));
    console.log('  LIVE ' + host + ': grade ' + live.grade + ' · TLS ' + live.tls_version + ' · KEX ' + (live.kex && live.kex.label) + ' · AUTH ' + (live.auth && live.auth.label) + ' · client OpenSSL ' + clientOpenssl() + (clientPqCapable() ? ' (PQ-capable)' : ' (NOT PQ-capable -> KEX inconclusive)'));
  }

  console.log('pqposture self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqposture\.mjs$/.test(process.argv[1] || '')) selfTest();
