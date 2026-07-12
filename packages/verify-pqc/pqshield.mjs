/*!
 * pqshield — TRELYANShield: signed cryptographic-posture / quantum-risk report (reference, DRAFT).
 *
 * Composes a CBOM (cryptographic bill of materials) into ONE hybrid-signed, dual-anchor-ready posture report.
 * THE FALSIFIABLE PROPERTY (the apex bit): the risk grade is a DETERMINISTIC function of the signed asset list,
 * RE-COMPUTED by the verifier. The signature binds a hash of the exact assets AND the aggregate it implies, so you
 * cannot sign a clean grade over broken crypto: change an asset → the assets hash breaks; forge the grade → the
 * recomputed aggregate no longer matches the signed core. Either way verify() returns false.
 *
 * Each asset gets a QuantumRiskScore (0-100) = base(algorithm) × exposure × sensitivity × harvest, clamped — the
 * TRELYANShield model. RED > 70 (migrate now), AMBER 40-70 (plan), GREEN < 40 (monitor). The model is FAIL-DANGEROUS:
 * anything not positively recognized as quantum-safe (an unknown label, a bare "hybrid" with no PQ scheme, a missing
 * algorithm) scores CRITICAL — a risk tool must never under-report. The report is signed with
 * Ed25519 ∧ ML-DSA-87 ∧ optional SLH-DSA-256f (three crypto families; stripping a pinned leg fails — anti-downgrade)
 * and carries an `anchor_commitment` ready for bridge-free dual-anchoring (Algorand canonical + QRL Zond witness via
 * pqanchor). HONEST: this is a risk/readiness SIGNAL under the declared scoring model — NOT an audit, attestation, or
 * certification, and not a guarantee a system is secure. Unaudited reference implementation.
 *
 * Self-test: node pqshield.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

const SHIELD_CTX = utf8ToBytes('trelyan-shield-report-v1');         // signing domain (Ed25519 + ML-DSA legs)
const SHIELD_SLH_CTX = utf8ToBytes('trelyan-shield-report-slh-v1'); // distinct domain for the optional SLH-DSA leg

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const _pub = (k) => (k && k.publicKey ? k.publicKey : k);
// issuer id binds the COMPLETE hybrid key set (full 256-bit).
export function makeIssuerId(keys) {
  if (!keys || !keys.ed || !keys.mldsa) throw new Error('issuer keys must be { ed, mldsa[, slh] }');
  return 'shield:trelyan:' + bytesToHex(sha256(concatBytes(utf8ToBytes('shield:trelyan:v1:'), _pub(keys.ed), _pub(keys.mldsa), keys.slh ? _pub(keys.slh) : new Uint8Array(0))));
}

/* ---------- QuantumRiskScore model (deterministic, the scoring contract) ---------- */
// Base quantum-risk weight by algorithm family. Post-quantum schemes are low; classical asymmetric is high
// (Shor-breakable); weak/legacy primitives are highest. Symmetric is moderate (Grover halves the security level).
function baseRisk(algorithm) {
  const a = String(algorithm || '').toUpperCase().replace(/[\s_]/g, '-');
  if (!a) return 100;                                       // no algorithm declared → cannot assert safety → CRITICAL
  // FAIL-DANGEROUS allow-list: low risk ONLY if a NIST PQ scheme is positively present. A bare "hybrid" with no PQ
  // token, an unknown label, or a missing field is NOT trusted — a posture tool must never under-report (apex-team fix).
  const PQ = /(ML-?KEM|ML-?DSA|SLH-?DSA|KYBER|DILITHIUM|SPHINCS|FALCON|FN-?DSA|HQC|FRODO|BIKE|MCELIECE)/.test(a);
  const ASYM = /(RSA|DSA|ECDSA|ECDH|ECC|SECP|P-?256|P-?384|P-?521|BRAINPOOL|ED25519|ED448|X25519|X448|CURVE25519|DIFFIE|\bDH\b)/.test(a);
  if (PQ) return ASYM ? 8 : 5;                              // genuine hybrid (PQ+classical) = 8; pure PQ = 5
  // — no PQ protection present below this line —
  if (/(MD5|SHA-?1|RC4|3DES|\bDES\b|RSA-?1024|RSA-?512|EXPORT|NULL-)/.test(a)) return 100; // broken / legacy
  if (/(RSA|DSA)/.test(a)) return 95;                       // Shor-breakable
  if (/(ECDSA|ECDH|ECC|SECP|P-?256|P-?384|P-?521|BRAINPOOL|ED25519|ED448|X25519|X448|CURVE25519|DIFFIE|\bDH\b)/.test(a)) return 80; // EC/25519 raised 65→80 (harvest-now)
  if (/(AES-?256|CHACHA20|SHA-?512|SHA-?384|SHA-?3|SHA3|SHAKE|BLAKE)/.test(a)) return 10; // symmetric/hash, Grover-only
  if (/(AES-?128|AES|SHA-?256|SHA-?224|HMAC|POLY1305)/.test(a)) return 30;
  return 100;                                               // UNKNOWN → fail-dangerous (cannot prove quantum-safe → flag)
}
export function scoreAsset(asset) {
  const base = baseRisk(asset && asset.algorithm);
  const mult = (asset && asset.internet_facing ? 1.5 : 1) * (asset && asset.sensitive ? 1.4 : 1) * (asset && asset.long_retention ? 1.3 : 1);
  return Math.max(0, Math.min(100, Math.round(base * mult)));
}
export function band(score) { return score > 70 ? 'RED' : score >= 40 ? 'AMBER' : 'GREEN'; }
// normalize an asset to a stable shape so the canon (and assets hash) is deterministic across producer + verifier.
function normAsset(a) {
  return { label: String((a && a.label) || ''), algorithm: String((a && a.algorithm) || ''),
    internet_facing: !!(a && a.internet_facing), sensitive: !!(a && a.sensitive), long_retention: !!(a && a.long_retention) };
}
// the deterministic aggregate the verifier re-derives. Letter grade reflects the worst exposure present.
function aggregate(assets) {
  const norm = assets.map(normAsset);
  const scored = norm.map((a) => ({ ...a, score: scoreAsset(a), band: band(scoreAsset(a)) }));
  const red = scored.filter((s) => s.band === 'RED').length;
  const amber = scored.filter((s) => s.band === 'AMBER').length;
  const green = scored.filter((s) => s.band === 'GREEN').length;
  const n = scored.length;
  const risk_index = n ? Math.round(scored.reduce((t, s) => t + s.score, 0) / n) : 0;
  const pqc_pct = n ? Math.round((green / n) * 100) : 100; // honest "share of low-risk assets" — a readiness signal, NOT attestation
  // grade: dominated by RED share, then risk_index
  const redShare = n ? red / n : 0;
  let grade;
  if (redShare > 0.30 || risk_index >= 70) grade = 'F';
  else if (redShare > 0.10 || risk_index >= 55) grade = 'D';
  else if (red > 0 || risk_index >= 40) grade = 'C';
  else if (amber > 0 || risk_index >= 20) grade = 'B';
  else grade = 'A';
  const top_critical = scored.filter((s) => s.band !== 'GREEN').sort((x, y) => y.score - x.score).slice(0, 10)
    .map((s) => ({ label: s.label, algorithm: s.algorithm, score: s.score, band: s.band }));
  return { norm, scored, red, amber, green, n, risk_index, pqc_pct, grade, top_critical,
    assets_hash: bytesToHex(sha256(utf8ToBytes(canon(norm)))) };
}

function shieldCore(m) {
  return { v: '1', issuer: m.issuer, target: m.target, generated_at: m.generated_at ?? null,
    asset_count: m.asset_count, red: m.red, amber: m.amber, green: m.green, risk_index: m.risk_index,
    pqc_pct: m.pqc_pct, grade: m.grade, assets_hash: m.assets_hash,
    standards: m.standards ?? null, anchor_commitment: m.anchor_commitment ?? null };
}

// issuerKeys = { ed, mldsa[, slh] }. assets = [{label, algorithm, internet_facing?, sensitive?, long_retention?}].
// opts.standards = ['DORA','NIS2',...] → echoed with the readiness pct (honest: readiness signal, not attestation).
export function createShieldReport({ issuerKeys, target, assets, standards, generatedAt }) {
  if (!issuerKeys || !issuerKeys.ed || !issuerKeys.mldsa) throw new Error('issuerKeys must be { ed, mldsa[, slh] }');
  if (!Array.isArray(assets)) throw new Error('assets must be an array');
  if (!target) throw new Error('target (what was scanned) is required');
  // A posture report MUST carry a finite signed generated_at. It is the anti-replay ordering anchor the pqmonitor ledger
  // relies on; leaving it optional produced a null-generated_at report that a monitor legitimately rejects (a producer/
  // consumer disagreement). Fail closed at the source so every report is monitorable + freshness-anchored. (fix-verif 1 Jul)
  if (!Number.isFinite(generatedAt)) throw new Error('generatedAt (a finite signed report timestamp) is required — an untimestamped posture report cannot anchor freshness/anti-replay when monitored (fail-closed)');
  const agg = aggregate(assets);
  const stds = Array.isArray(standards) && standards.length
    ? standards.reduce((o, s) => { o[String(s)] = { readiness_pct: agg.pqc_pct, note: 'readiness signal, not attestation' }; return o; }, {}) : null;
  // anchor_commitment binds the signed core to a dual-anchor (pqanchor: Algorand canonical + QRL Zond witness).
  const pre = { issuer: makeIssuerId(issuerKeys), target: String(target), asset_count: agg.n, risk_index: agg.risk_index, grade: agg.grade, assets_hash: agg.assets_hash };
  const anchor_commitment = bytesToHex(sha256(utf8ToBytes('trelyan-shield-anchor-v1' + canon(pre))));
  const core = shieldCore({ issuer: pre.issuer, target: String(target), generated_at: generatedAt ?? null,
    asset_count: agg.n, red: agg.red, amber: agg.amber, green: agg.green, risk_index: agg.risk_index,
    pqc_pct: agg.pqc_pct, grade: agg.grade, assets_hash: agg.assets_hash, standards: stds, anchor_commitment });
  const coreBytes = utf8ToBytes(canon(core));
  const report = { ...core, assets: agg.norm,
    issuer_pub: { ed: bytesToHex(_pub(issuerKeys.ed)), mldsa: bytesToHex(_pub(issuerKeys.mldsa)) },
    top_critical: agg.top_critical,
    ed_sig: bytesToHex(ed25519.sign(concatBytes(SHIELD_CTX, coreBytes), issuerKeys.ed.secretKey)),
    mldsa_sig: bytesToHex(ml_dsa87.sign(coreBytes, issuerKeys.mldsa.secretKey, { context: SHIELD_CTX })) };
  if (issuerKeys.slh) { report.issuer_pub.slh = bytesToHex(_pub(issuerKeys.slh)); report.slh_sig = bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, issuerKeys.slh.secretKey, { context: SHIELD_SLH_CTX })); }
  return report;
}

// TOTAL / fail-closed. trustedIssuer = { ed, mldsa[, slh] } pinned. Re-derives the aggregate from report.assets and
// rejects unless it matches the signed core AND the hybrid signature verifies under the pinned issuer.
export function verifyShieldReport(report, trustedIssuer, opts = {}) {
  try {
    if (!report || typeof report !== 'object' || !Array.isArray(report.assets) || !trustedIssuer || !trustedIssuer.ed || !trustedIssuer.mldsa) return { verified: false };
    if (report.issuer !== makeIssuerId(trustedIssuer)) return { verified: false, reason: 'issuer id != pinned issuer keys' };
    // re-derive the aggregate from the carried assets — the grade must be a function of the signed data, not asserted
    const agg = aggregate(report.assets);
    if (agg.assets_hash !== report.assets_hash) return { verified: false, reason: 'assets hash mismatch (assets tampered)' };
    if (agg.n !== report.asset_count || agg.red !== report.red || agg.amber !== report.amber || agg.green !== report.green
      || agg.risk_index !== report.risk_index || agg.pqc_pct !== report.pqc_pct || agg.grade !== report.grade) {
      return { verified: false, reason: 'recomputed aggregate != signed aggregate (grade forged over data)' };
    }
    const coreBytes = utf8ToBytes(canon(shieldCore(report)));
    let edOk = false, pqOk = false, slhOk = true;
    try { edOk = ed25519.verify(hexToBytes(report.ed_sig), concatBytes(SHIELD_CTX, coreBytes), trustedIssuer.ed); } catch { edOk = false; }
    try { pqOk = ml_dsa87.verify(hexToBytes(report.mldsa_sig), coreBytes, trustedIssuer.mldsa, { context: SHIELD_CTX }); } catch { pqOk = false; }
    if (trustedIssuer.slh) { try { slhOk = !!(report.slh_sig && slh_dsa_sha2_256f.verify(hexToBytes(report.slh_sig), coreBytes, trustedIssuer.slh, { context: SHIELD_SLH_CTX })); } catch { slhOk = false; } }
    if (!edOk || !pqOk || !slhOk) return { verified: false, reason: 'hybrid signature invalid (or required leg missing)' };
    // optional anchor pin: caller can require the report match a known dual-anchor commitment
    if (opts.expectedAnchor != null && report.anchor_commitment !== opts.expectedAnchor) return { verified: false, reason: 'anchor commitment mismatch' };
    return { verified: true, grade: report.grade, risk_index: report.risk_index, red: report.red, amber: report.amber, green: report.green, asset_count: report.asset_count, anchor_commitment: report.anchor_commitment };
  } catch { return { verified: false }; }
}

/* ---------- self-test: node pqshield.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const ed = (n) => ({ secretKey: new Uint8Array(32).fill(n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(n)) });
  const issuer = { ed: ed(1), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)) };
  const tIssuer = { ed: issuer.ed.publicKey, mldsa: issuer.mldsa.publicKey };
  const attacker = { ed: ed(9), mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(9)) };

  // scoring model
  ok(band(scoreAsset({ algorithm: 'RSA-2048', internet_facing: true })) === 'RED', 'RSA-2048 internet-facing -> RED');
  ok(band(scoreAsset({ algorithm: 'ML-KEM-1024' })) === 'GREEN', 'ML-KEM-1024 -> GREEN (post-quantum)');
  ok(scoreAsset({ algorithm: 'RSA-1024' }) === 100 && band(scoreAsset({ algorithm: 'SHA1' })) === 'RED', 'legacy/broken primitives -> max risk');
  ok(scoreAsset({ algorithm: 'ECDSA-P256', internet_facing: true, sensitive: true }) === 100, 'multipliers stack + clamp at 100');
  // FAIL-DANGEROUS (apex-team fix): the model must never under-report by trusting the algorithm string
  ok(band(scoreAsset({ algorithm: 'HYBRID-RSA' })) === 'RED', 'a "hybrid" label with NO PQ scheme is NOT trusted -> RSA -> RED');
  ok(scoreAsset({ algorithm: 'ACME-CustomCipher' }) === 100 && scoreAsset({ algorithm: '' }) === 100, 'unknown / missing algorithm -> 100 (RED), never assumed safe');
  ok(band(scoreAsset({ algorithm: 'X25519' })) === 'RED', 'Ed25519/X25519 raised to high risk (harvest-now-decrypt-later)');
  ok(band(scoreAsset({ algorithm: 'HYBRID-X25519-ML-KEM-768' })) === 'GREEN', 'a genuine hybrid WITH a PQ scheme -> low risk (GREEN)');

  const assets = [
    { label: 'edge-tls', algorithm: 'RSA-2048', internet_facing: true, sensitive: true },
    { label: 'vpn', algorithm: 'ECDH-P256', internet_facing: true },
    { label: 'data-at-rest', algorithm: 'AES-256' },
    { label: 'new-tls', algorithm: 'HYBRID-X25519-ML-KEM-768', internet_facing: true },
  ];
  const r = createShieldReport({ issuerKeys: issuer, target: 'acme-bank/prod', assets, standards: ['DORA', 'NIS2'], generatedAt: 1000 });
  ok(r.issuer === makeIssuerId(issuer) && typeof r.assets_hash === 'string', 'report binds issuer id + assets hash');
  ok(['A', 'B', 'C', 'D', 'F'].includes(r.grade) && r.red >= 1, 'report has a grade + counts RED assets');
  ok(typeof r.anchor_commitment === 'string' && r.standards.DORA.note.includes('not attestation'), 'anchor commitment present + standards are honest readiness signals');
  ok(verifyShieldReport(r, tIssuer).verified === true, 'valid report verifies under pinned issuer');
  ok(verifyShieldReport(r, { ed: attacker.ed.publicKey, mldsa: attacker.mldsa.publicKey }).verified === false, 'wrong pinned issuer -> FAILS');

  // THE apex property: cannot sign a clean grade over bad crypto
  const forged = JSON.parse(JSON.stringify(r)); forged.grade = 'A'; forged.red = 0; forged.risk_index = 5;
  ok(verifyShieldReport(forged, tIssuer).verified === false, 'forged rosy grade (same assets) -> recomputed aggregate mismatch -> FAILS');
  const swapped = JSON.parse(JSON.stringify(r)); swapped.assets[0].algorithm = 'ML-KEM-1024'; // pretend the bad asset is fine
  ok(verifyShieldReport(swapped, tIssuer).verified === false, 'swapped asset (no re-sign) -> assets hash mismatch -> FAILS');
  const t = JSON.parse(JSON.stringify(r)); t.ed_sig = '00'.repeat(64);
  ok(verifyShieldReport(t, tIssuer).verified === false, 'tampered Ed25519 sig -> hybrid FAILS');

  // anchor pin
  ok(verifyShieldReport(r, tIssuer, { expectedAnchor: r.anchor_commitment }).verified === true && verifyShieldReport(r, tIssuer, { expectedAnchor: 'deadbeef' }).verified === false, 'expectedAnchor pin enforced');

  // empty estate -> grade A, risk 0
  const empty = createShieldReport({ issuerKeys: issuer, target: 'greenfield', assets: [], generatedAt: 1 });
  ok(empty.grade === 'A' && empty.risk_index === 0 && verifyShieldReport(empty, tIssuer).verified === true, 'empty asset set -> grade A, verifies');

  // 3-leg hash-based hardening
  const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5));
  const issuer3 = { ed: issuer.ed, mldsa: issuer.mldsa, slh };
  const tIssuer3 = { ed: tIssuer.ed, mldsa: tIssuer.mldsa, slh: slh.publicKey };
  const r3 = createShieldReport({ issuerKeys: issuer3, target: 'acme/prod', assets, generatedAt: 1 });
  ok(typeof r3.slh_sig === 'string' && verifyShieldReport(r3, tIssuer3).verified === true, '3-leg (Ed25519∧ML-DSA∧SLH-DSA) report verifies');
  const r3s = JSON.parse(JSON.stringify(r3)); r3s.slh_sig = '00';
  ok(verifyShieldReport(r3s, tIssuer3).verified === false, 'stripped SLH leg fails when issuer.slh pinned (anti-downgrade)');

  // TOTAL fail-closed
  let total = true; for (const bad of [null, undefined, {}, 42, { assets: 'x' }, { ...r, assets: undefined }]) { try { if (verifyShieldReport(bad, tIssuer).verified !== false) total = false; } catch { total = false; } }
  ok(total, 'TOTAL: malformed reports -> verified:false, never throws');

  console.log('pqshield self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqshield\.mjs$/.test(process.argv[1] || '')) selfTest();
