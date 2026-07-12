/*!
 * pqcbom-server — hosted "Post-Quantum Readiness Scorecard" handler + CI policy gate (reference, DRAFT, standalone).
 *
 * The product surface of pqcbom: a serverless-shaped handler that turns a scan into (a) the free shareable
 * BADGE (shields.io endpoint JSON — we emit JSON only; shields renders it, so NO SVG is authored here, per
 * the media policy), (b) the free scorecard, and (c) the paid full CBOM + findings. Plus a CI policy gate
 * (fail the build on banned crypto / below a minimum grade). Self-test: node pqcbom-server.mjs
 */
import { scanFiles, gradeOf, toCycloneDX } from './pqcbom.mjs';
import { buildEvidencePack, signEvidencePack } from './pqcbom-report.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const GRADE_COLOR = { A: 'brightgreen', B: 'green', C: 'yellow', D: 'orange', F: 'red' };
const gradeRank = (g) => ({ F: 0, D: 1, C: 2, B: 3, A: 4 }[g] ?? 0);
// Honest labeling carried on EVERY response so a PREVIEW deploy is self-describing (no silent prod claim).
export const PREVIEW_NOTICE = 'PREVIEW — built on @trelyan/verify-pqc (UNAUDITED reference crypto, not FIPS-140-3 validated). pqcbom is a LEXICAL scanner: treat findings as leads to verify, not a complete inventory. Not for production reliance until the third-party audit.';

// shields.io endpoint schema — README badge via https://img.shields.io/endpoint?url=<this JSON>. JSON only, no SVG.
export function scorecardBadge(grade) {
  return { schemaVersion: 1, label: 'PQ Readiness', message: grade.letter + ' (' + grade.score + ')', color: GRADE_COLOR[grade.letter] || 'lightgrey' };
}

// CI policy gate: fail on banned risk classes and/or below a minimum grade.
const RISK_CLASSES = new Set(['broken-classical', 'quantum-broken', 'quantum-weakened', 'classical-hybrid-ok', 'quantum-safe']);
const VALID_GRADES = new Set(['A', 'B', 'C', 'D', 'F']);
export function policyGate(report, policy = {}) {
  const failOn = policy.failOn || ['broken-classical'];
  const violations = [], configErrors = [];
  for (const risk of failOn) {
    // fail-CLOSED on a typo'd risk class — otherwise summary[unknown] is undefined and the clause silently disables
    if (!RISK_CLASSES.has(risk)) { configErrors.push('unknown fail-on risk class: "' + risk + '"'); continue; }
    const n = report.summary[risk.replace(/-/g, '_')] || 0;
    if (n > 0) violations.push(risk + ' x' + n);
  }
  if (policy.minGrade) {
    // an invalid min-grade must NOT silently disable the grade gate (gradeRank falls back to 0 → never triggers)
    if (!VALID_GRADES.has(String(policy.minGrade).toUpperCase())) configErrors.push('invalid min-grade: "' + policy.minGrade + '" (expected A–F)');
    else if (gradeRank(report.grade.letter) < gradeRank(String(policy.minGrade).toUpperCase())) violations.push('grade ' + report.grade.letter + ' < min ' + policy.minGrade);
  }
  const all = configErrors.concat(violations); // misconfiguration fails the gate, with a clear message (not a silent pass)
  return { pass: all.length === 0, violations: all, configErrors };
}

// the hosted scan handler. opts.full = paid tier (full CBOM + findings); opts.evidencePack = signed Evidence Pack
// (opts.signer = {secretKey, publicKey}; opts.meta = {org,scope,generated_ts}); opts.policy = CI gate.
export function handleScan(files, opts = {}) {
  const report = scanFiles(files);
  const out = {
    notice: PREVIEW_NOTICE,
    scorecard: { grade: report.grade.letter, score: report.grade.score, label: report.grade.label, summary: report.summary },
    badge: scorecardBadge(report.grade),
  };
  if (opts.full) { out.cbom = toCycloneDX(report); out.findings = report.findings; }
  if (opts.evidencePack) { // paid deliverable: the PQ-signed Evidence Pack (unsigned if no signer supplied)
    const pack = buildEvidencePack({ scan: report, meta: opts.meta || {} });
    out.evidence_pack = opts.signer ? signEvidencePack(pack, opts.signer.secretKey, opts.signer.publicKey) : pack;
  }
  if (opts.policy) out.gate = policyGate(report, opts.policy);
  return out;
}

// node http adapter (demo): POST { files:[{name,text}], full?, policy? } -> JSON. (Production = serverless fn.)
export function nodeHandler() {
  return (req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 8_000_000) req.destroy(); });
    req.on('end', () => {
      try { const { files, full, policy } = JSON.parse(body || '{}'); res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(handleScan(files || [], { full, policy }))); }
      catch (e) { res.statusCode = 400; res.end(JSON.stringify({ error: String(e.message || e) })); }
    });
  };
}

/* ---------- self-test: node pqcbom-server.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const vuln = [{ name: 'legacy.js', text: 'RSA.generate(2048); ECDSA; MD5; AES-128-CBC;' }];
  const safe = [{ name: 'modern.mjs', text: 'ml_kem1024; ml_dsa87; AES-256-GCM; SHA-512; X25519 + ML-KEM-768;' }];

  const rV = handleScan(vuln);
  ok(rV.scorecard.grade === 'F' && rV.badge.color === 'red' && rV.badge.message.startsWith('F'), 'vulnerable scan -> grade F, red badge');
  ok(rV.badge.schemaVersion === 1 && rV.badge.label === 'PQ Readiness', 'badge is a valid shields.io endpoint object (JSON, no SVG authored)');
  ok(!rV.cbom, 'free tier omits the full CBOM');

  const rS = handleScan(safe, { full: true });
  ok(rS.scorecard.grade === 'A' && rS.badge.color === 'brightgreen', 'all-PQ-safe scan -> grade A, brightgreen badge');
  ok(rS.cbom && rS.cbom.bomFormat === 'CycloneDX' && Array.isArray(rS.findings), 'paid tier (full) includes the CycloneDX CBOM + findings');

  // CI policy gate
  ok(handleScan(vuln, { policy: { failOn: ['broken-classical'] } }).gate.pass === false, 'policy gate fails the build on broken-classical (MD5)');
  ok(handleScan(safe, { policy: { failOn: ['broken-classical', 'quantum-broken'], minGrade: 'B' } }).gate.pass === true, 'policy gate passes a clean PQ-safe repo (grade A >= min B)');
  ok(handleScan([{ name: 'x', text: 'ECDSA secp256k1' }], { policy: { failOn: ['quantum-broken'] } }).gate.pass === false, 'policy gate fails on quantum-broken (ECDSA)');
  // fail-CLOSED on misconfiguration (a typo'd fail-on or invalid min-grade must NOT silently pass a security gate)
  ok(handleScan(safe, { policy: { failOn: ['broken-classicl'] } }).gate.pass === false, 'policy gate FAILS CLOSED on a typo\'d fail-on risk class (not a silent pass)');
  ok(handleScan(safe, { policy: { minGrade: 'Z' } }).gate.pass === false, 'policy gate FAILS CLOSED on an invalid min-grade (not a silent pass)');

  // honest PREVIEW notice on every response
  ok(rV.notice === PREVIEW_NOTICE && /UNAUDITED/.test(rV.notice) && /LEXICAL/.test(rV.notice), 'every response carries the PREVIEW/unaudited/lexical-scanner notice (honest labeling)');

  // paid deliverable: a signed Evidence Pack, verifiable + grade-recompute-bound
  const signer = ml_dsa87.keygen(new Uint8Array(32).fill(62));
  const rEP = handleScan(vuln, { evidencePack: true, signer, meta: { org: 'acme', scope: 'repo', generated_ts: 1 } });
  ok(rEP.evidence_pack && rEP.evidence_pack.signature && rEP.evidence_pack.grade.letter === 'F', 'evidencePack tier returns a signed Evidence Pack (grade F)');

  console.log('pqcbom-server self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqcbom-server\.mjs$/.test(process.argv[1] || '')) selfTest();
