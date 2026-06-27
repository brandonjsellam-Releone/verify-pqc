/*!
 * pqcompliance — signed cryptographic-control evidence mapper (reference, DRAFT, standalone).
 *
 * The regulated-buyer deliverable (the monitoring-SaaS tier): turns a CBOM scan into a per-CONTROL gap analysis
 * mapping findings to specific cryptography requirements in CNSA 2.0 / NIS2 / CRA / DORA / NIST SP 800-53, with
 * status (met / gap / n-a), the finding-evidence, and remediation — ML-DSA-87 SIGNED and verifiable.
 *
 * HONEST SCOPE (load-bearing): this is a RELEVANCE + GAP analysis, NOT a certification, audit opinion, or legal
 * advice. A lexical CBOM scan (pqcbom) cannot determine full control compliance (it sees crypto usage, not key
 * management, HSMs, processes, or scope). "met" means "no triggering finding + PQ-safe crypto present in the scanned
 * surface" — necessary, not sufficient. Use it to PRIORITIZE remediation and as auditor input, not as a compliance
 * claim. Composes pqcbom (scan) + ML-DSA-87 signing. Self-test: node pqcompliance.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { scanFiles, gradeOf, riskTally } from './pqcbom.mjs';

const COMP_CTX = utf8ToBytes('trelyan-pqcompliance-report-v1');
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

// triggers = risk classes whose presence (in CODE, not comments) makes the control a GAP. scope_note states what the
// control's crypto-primitive check does NOT cover. requiresPQAsym: control needs real PQ asymmetric adoption
// (ML-KEM/ML-DSA/SLH-DSA), so AES-256 alone does NOT satisfy it (CNSA 2.0). Status: 'gap' | 'no-gap-found' | 'n-a'
// — deliberately NOT "met" (avoids implying conformance; council/Mistral).
const CONTROLS = [
  { regime: 'CNSA 2.0 (NSA)', control: 'PQC adoption (ML-KEM-1024/ML-DSA-87) for NSS; software-signing PQC by 2025, broad 2030–2033', triggers: ['quantum-broken', 'quantum-weakened'], requiresPQAsym: true, scope_note: 'Crypto-primitive adoption only — NOT key management, HSM, protocol config, or accreditation.', remediation: 'Migrate public-key crypto to ML-KEM-1024 / ML-DSA-87 (hybrid during transition).' },
  { regime: 'NIS2 Art.21(2)(h)+(e) (EU)', control: 'Cryptography/encryption use + secure development & vulnerability handling', triggers: ['broken-classical', 'quantum-broken'], scope_note: 'Cryptographic primitives only — NOT organisational measures, incident handling, governance, or supply-chain risk (risk-based; context may permit exceptions).', remediation: 'Remove broken primitives; document a crypto policy + PQC migration plan; handle the vulnerabilities found.' },
  { regime: 'CRA (EU) Annex I', control: 'Secure-by-design; no known-exploitable crypto; protect confidentiality/integrity', triggers: ['broken-classical'], scope_note: 'Classically-broken primitives only — NOT vulnerability disclosure, SBOM, or secure-dev lifecycle; CRA is risk-based (non-critical use may differ).', remediation: 'Eliminate classically-broken crypto (MD5/SHA-1/RC4/3DES) before placing on market.' },
  { regime: 'DORA (EU financial) Art.9', control: 'ICT risk management — cryptographic controls', triggers: ['broken-classical', 'quantum-broken', 'quantum-weakened'], scope_note: 'Cryptographic primitives only — NOT operational resilience, testing, or third-party risk; compensating controls may apply for non-critical functions.', remediation: 'Adopt strong + quantum-safe crypto; evidence key-management controls (HSM/KMS).' },
  { regime: 'NIST SP 800-53 SC-13', control: 'Cryptographic protection using approved crypto', triggers: ['broken-classical', 'quantum-broken'], scope_note: 'Algorithm selection only — NOT key management (SC-12), module validation, or system scoping.', remediation: 'Use FIPS-approved algorithms (FIPS 203/204/205, AES-256, SHA-2/3); replace non-approved.' },
];
const PQ_ASYM_FAMILIES = new Set(['kem', 'signature']);

// derives EVERYTHING from the scan FINDINGS using CODE occurrences (comment/doc mentions excluded — council/DeepSeek).
export function assessCompliance(scan, opts = {}) {
  const findings = scan.findings || [];
  const codeOf = (f) => (typeof f.code_count === 'number' ? f.code_count : (f.count || 0));
  const codeCount = (risk) => findings.filter((f) => f.risk === risk).reduce((n, f) => n + codeOf(f), 0);
  const anyCryptoCode = findings.some((f) => codeOf(f) > 0);
  const pqAsymCode = findings.some((f) => f.risk === 'quantum-safe' && PQ_ASYM_FAMILIES.has(f.family) && codeOf(f) > 0); // real ML-KEM/ML-DSA/SLH usage, not AES-256
  const controls = CONTROLS.map((c) => {
    const hits = c.triggers.map((t) => ({ t, count: codeCount(t) })).filter((x) => x.count > 0);
    let status, rationale;
    if (!anyCryptoCode) { status = 'n-a'; rationale = 'no cryptography detected in CODE (comment/doc mentions excluded)'; }
    else if (hits.length) { status = 'gap'; rationale = 'triggering code findings: ' + hits.map((h) => h.t + ' ×' + h.count).join(', '); }
    else if (c.requiresPQAsym && !pqAsymCode) { status = 'gap'; rationale = 'no broken crypto, but NO post-quantum asymmetric (ML-KEM/ML-DSA/SLH-DSA) adoption detected in code — CNSA 2.0 mandates PQC migration (AES-256 alone does not satisfy it)'; }
    else { status = 'no-gap-found'; rationale = 'no triggering code findings' + (c.requiresPQAsym ? '; PQ-asymmetric adoption present' : '') + ' — single-dimension (crypto-primitive) check, NECESSARY not sufficient'; }
    return { regime: c.regime, control: c.control, scope_note: c.scope_note, status, rationale, remediation: status === 'gap' ? c.remediation : null };
  });
  const gaps = controls.filter((c) => c.status === 'gap').length;
  return {
    kind: 'pqcompliance-report', v: '0.2',
    disclaimer: 'SINGLE-DIMENSION cryptographic-PRIMITIVE gap analysis from a lexical CBOM scan (code-context). NOT a certification, audit opinion, or legal advice, and NOT evidence of NIS2/CRA/DORA/CNSA conformance. "no-gap-found" means no triggering primitive was found in code — NECESSARY, not sufficient; real compliance is multi-factor (key mgmt, process, scope) and requires independent validation.',
    subject: opts.subject || 'CONFIDENTIAL', generated_ts: opts.generated_ts ?? null,
    grade: scan.grade, summary: scan.summary, controls, control_gaps: gaps, findings, // findings embedded so the report is self-verifying (hash-bound at signing)
    posture: gaps === 0 ? (anyCryptoCode ? 'no primitive gaps found in code' : 'no crypto found') : gaps + ' control gap(s)',
  };
}

const findingsHash = (findings) => bytesToHex(sha512(utf8ToBytes(canon(findings || []))));
// signed core binds a HASH OF THE FULL FINDINGS (council/DeepSeek) — not just the summary — so altering findings is caught.
// tamper-binding harness: `summary` (headline counts a buyer reads) AND `disclaimer` (the "NOT a certification" honesty
// caveat) MUST be in the signed core — else an attacker could rewrite the counts or STRIP the caveat from a signed report.
const core = (r) => ({ kind: r.kind, v: r.v, subject: r.subject, generated_ts: r.generated_ts, grade: r.grade, summary: r.summary, controls: r.controls, control_gaps: r.control_gaps, posture: r.posture, disclaimer: r.disclaimer, findings_sha512: r.findings_sha512 });
export function signComplianceReport(report, sk, pub) {
  const r = { ...report, findings_sha512: findingsHash(report.findings) };
  return { ...r, signature: { alg: 'ML-DSA-87', signer_pub_hex: bytesToHex(pub), sig_hex: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core(r))), sk, { context: COMP_CTX })) } };
}
// verify: (a) the embedded findings hash to the signed findings_sha512 (binds findings); (b) the controls RECOMPUTE
// from those authenticated findings; (c) the signature is valid under the pinned key. Defeats findings-tamper + doctored status.
export function verifyComplianceReport(report, trustedPub) {
  try {
    const fhOk = report.findings_sha512 === findingsHash(report.findings);
    const recomputed = assessCompliance({ findings: report.findings, grade: report.grade, summary: report.summary });
    // ANTI grade-forgery (council/DeepSeek red-team + pre-ship review): recompute the risk tallies AND the grade FROM
    // the (hash-bound) findings — parallel to verifyEvidencePack — so a forged clean summary/grade over bad findings is
    // caught (not merely a grade that matches a forgeable summary).
    const ctx = (report.summary && report.summary.grade_context) === 'code' ? 'code' : 'total';
    const rt = riskTally(report.findings || [], ctx);
    const tallyKeys = ['broken_classical', 'quantum_broken', 'quantum_weakened', 'classical_hybrid_ok', 'quantum_safe'];
    const summaryOk = !!report.summary && tallyKeys.every((k) => rt[k] === report.summary[k]);
    const gradeOk = !!(report.grade && summaryOk && gradeOf(rt).letter === report.grade.letter);
    const consistent = fhOk && gradeOk && JSON.stringify(recomputed.controls) === JSON.stringify(report.controls) && recomputed.control_gaps === report.control_gaps;
    const s = report.signature;
    const pinned = !trustedPub || (s && s.signer_pub_hex && s.signer_pub_hex.toLowerCase() === bytesToHex(trustedPub).toLowerCase());
    let sigOk = false;
    if (s && s.sig_hex) sigOk = ml_dsa87.verify(hexToBytes(s.sig_hex), utf8ToBytes(canon(core(report))), trustedPub ? trustedPub : hexToBytes(s.signer_pub_hex), { context: COMP_CTX });
    return { verified: !!(consistent && pinned && sigOk), findingsBound: fhOk, gradeOk, consistent, pinned, sigOk };
  } catch { return { verified: false, findingsBound: false, consistent: false, pinned: false, sigOk: false }; }
}

/* ---------- self-test: node pqcompliance.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const signer = ml_dsa87.keygen(new Uint8Array(32).fill(63));
  const vulnScan = scanFiles([{ name: 'legacy.js', text: 'RSA.generate(2048); ECDSA secp256k1; MD5; AES-128;' }]);
  const safeScan = scanFiles([{ name: 'modern.mjs', text: 'kex = ML-KEM-1024; sig = ML-DSA-87; aead = AES-256-GCM; hash = SHA-512;' }]);

  const rv = assessCompliance(vulnScan, { subject: 'acme', generated_ts: 1 });
  ok(rv.control_gaps >= 4 && rv.controls.find((c) => /CRA/.test(c.regime)).status === 'gap', 'vulnerable scan -> control GAPS across regimes (CRA gap on broken MD5)');
  ok(rv.controls.every((c) => c.status !== 'gap' || c.remediation) && rv.controls.every((c) => c.scope_note), 'every GAP carries remediation; every control carries a scope_note');
  const rs = assessCompliance(safeScan, { subject: 'acme', generated_ts: 1 });
  ok(rs.control_gaps === 0 && rs.controls.find((c) => /CNSA/.test(c.regime)).status === 'no-gap-found', 'all-PQ-safe scan (incl. ML-KEM/ML-DSA) -> no gaps; CNSA no-gap-found');
  // DeepSeek fix: AES-256 + SHA-512 but NO PQ-asymmetric -> CNSA is a GAP (AES alone ≠ PQC adoption)
  const aesOnly = assessCompliance(scanFiles([{ name: 'a.js', text: 'AES-256-GCM; SHA-512;' }]));
  ok(aesOnly.controls.find((c) => /CNSA/.test(c.regime)).status === 'gap' && aesOnly.controls.find((c) => /CRA/.test(c.regime)).status === 'no-gap-found', 'AES-256 only (no PQ-asymmetric) -> CNSA GAP, CRA no-gap-found');
  // DeepSeek fix: crypto named only in a COMMENT must not trigger (code-context) -> N/A, not a gap
  const commentOnly = assessCompliance(scanFiles([{ name: 'c.js', text: '// legacy used MD5 and RSA\nconst x=1;' }]));
  ok(commentOnly.controls.every((c) => c.status === 'n-a'), 'crypto only in comments -> all N/A (code-context; no false gap)');
  ok(assessCompliance(scanFiles([{ name: 'x', text: 'hello world no crypto' }])).controls.every((c) => c.status === 'n-a'), 'no-crypto scan -> all controls N/A');
  ok(/NOT a certification/.test(rv.disclaimer) && /NECESSARY, not sufficient/.test(rv.disclaimer), 'report carries the honest not-a-certification / necessary-not-sufficient disclaimer');

  const signed = signComplianceReport(rv, signer.secretKey, signer.publicKey);
  ok(verifyComplianceReport(signed, signer.publicKey).verified === true, 'signed compliance report verifies under the pinned key');
  ok(verifyComplianceReport(signed, ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey).verified === false, 'wrong signer key -> NOT verified');
  // anti-forgery #1: flip a GAP control to no-gap -> recompute-from-findings catches it
  const f1 = JSON.parse(JSON.stringify(signed)); const g = f1.controls.find((c) => c.status === 'gap'); g.status = 'no-gap-found'; g.remediation = null;
  ok(verifyComplianceReport(f1, signer.publicKey).verified === false, 'forged "no-gap" over gap-triggering findings -> verify FAILS (recomputed from findings)');
  // anti-forgery #2 (DeepSeek): alter the underlying FINDINGS -> findings-hash mismatch catches it
  const f2 = JSON.parse(JSON.stringify(signed)); if (f2.findings[0]) f2.findings[0].risk = 'quantum-safe';
  const v2 = verifyComplianceReport(f2, signer.publicKey);
  ok(v2.verified === false && (v2.findingsBound === false || v2.consistent === false), 'altered FINDINGS (same-ish summary) -> verify FAILS (findings hash bound)');
  // anti-forgery #3 (pre-ship review): forge a CLEAN summary + grade over the real (bad) findings -> tallies recomputed
  // from the hash-bound findings catch it (grade is no longer trusted from the forgeable summary)
  const f3 = JSON.parse(JSON.stringify(signed));
  f3.summary = { ...f3.summary, broken_classical: 0, quantum_broken: 0, quantum_weakened: 0, classical_hybrid_ok: 0, quantum_safe: 0 };
  f3.grade = { letter: 'A', score: 100, label: 'Quantum-safe', badge: 'Quantum-Safe: A' };
  ok(verifyComplianceReport(f3, signer.publicKey).verified === false, 'forged clean summary+grade over bad findings -> verify FAILS (tallies recomputed from findings)');

  console.log('pqcompliance self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqcompliance\.mjs$/.test(process.argv[1] || '')) selfTest();
