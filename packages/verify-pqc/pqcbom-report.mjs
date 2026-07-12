/*!
 * pqcbom-report — "PQC Migration Evidence Pack" generator (reference, DRAFT, standalone).
 *
 * The PAID deliverable of the CBOM revenue product (pqcbom = free badge funnel → this = the audit artifact a buyer
 * pays for). Turns a scan into a professional, ML-DSA-87-SIGNED evidence pack: executive summary + A–F grade,
 * prioritized findings, a migration roadmap to the TRELYAN PQC SDK, a compliance crosswalk (CNSA 2.0 / NIS2 / CRA /
 * DORA / PCI), and an honest methodology+limits section. The pack is PQ-signed and verifiable with our OWN stack —
 * and verifyEvidencePack RECOMPUTES the grade from the findings, so a buyer/auditor cannot be handed a forged
 * "grade A" over quantum-broken findings.
 *
 * HONEST LIMITS: inherits pqcbom's lexical-scanner caveats (no AST / dep-graph / TLS-cert / cloud-KMS discovery yet);
 * the compliance crosswalk is INFORMATIONAL ("aligns with / informs"), NOT a certification or legal opinion. Pass
 * meta.generated_ts (no wall-clock here). Self-test: node pqcbom-report.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { gradeOf, toCycloneDX, scanFiles, riskTally } from './pqcbom.mjs';
import { buildMigrationPlan, renderMigrationPlan } from './pqcbom-plan.mjs';

const REPORT_CTX = utf8ToBytes('trelyan-pqcbom-evidence-pack-v1');
// distinct domain-separation context for the OPTIONAL SLH-DSA (FIPS-205, hash-based) diversity leg — algorithm-family
// diversity vs the lattice ML-DSA-87, so a forgery must break BOTH families (AND-composition). Same core bytes.
const REPORT_SLH_CTX = utf8ToBytes('trelyan-pqcbom-evidence-pack-slh-v1');
function canon(v) {
  if (v === undefined) return 'null';   // total: JSON.stringify would drop it; treat as null so canon() never hits Object.keys(undefined)
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

// INFORMATIONAL crosswalk: what each regime expects re: post-quantum / strong crypto (not a certification).
const COMPLIANCE = [
  { regime: 'CNSA 2.0 (NSA)', expects: 'PQC (ML-KEM/ML-DSA) for NSS; software-signing PQC from 2025, broad by 2030–2033', triggeredBy: ['quantum-broken', 'quantum-weakened'] },
  { regime: 'NIS2 (EU)', expects: 'Art.21 risk-management incl. cryptography & vuln handling for essential/important entities', triggeredBy: ['broken-classical', 'quantum-broken'] },
  { regime: 'CRA (EU)', expects: 'Secure-by-design for products with digital elements; no known-exploitable crypto', triggeredBy: ['broken-classical', 'quantum-broken'] },
  { regime: 'DORA (EU financial)', expects: 'ICT risk management incl. cryptographic controls & resilience', triggeredBy: ['broken-classical', 'quantum-broken', 'quantum-weakened'] },
  { regime: 'PCI DSS 4.0', expects: 'Strong cryptography; no broken/weak primitives for cardholder data', triggeredBy: ['broken-classical', 'quantum-weakened'] },
];

// (the migration roadmap is now the structured, sequenced plan from pqcbom-plan.mjs — see §3 in renderMarkdown)

function renderMarkdown({ summary, grade, findings, meta }) {
  const present = new Set(findings.map((f) => f.risk));
  const crosswalk = COMPLIANCE.map((c) => {
    const relevant = c.triggeredBy.some((r) => present.has(r));
    return '| ' + c.regime + ' | ' + (relevant ? '⚠️ action indicated' : '— no trigger found') + ' | ' + c.expects + ' |';
  }).join('\n');
  const top = findings.slice(0, 25).map((f) => '| `' + f.algo + '` | ' + f.risk + ' | ' + (f.confidence || 'lead-to-verify') + ' | ' + f.count + ' | ' + (f.file || '') + (f.lines && f.lines.length ? ' (L' + f.lines.join(', L') + ')' : '') + ' |').join('\n');
  const bc = summary.by_confidence;
  return [
    '# PQC Migration Evidence Pack',
    '**Subject:** ' + meta.org + '  ·  **Scope:** ' + meta.scope + '  ·  **Generated (ts):** ' + (meta.generated_ts ?? 'n/a'),
    '**Tool:** ' + meta.tool + ' ' + meta.tool_version + '  ·  **Report format:** v' + meta.report_version,
    '',
    '## 1. Post-Quantum Readiness Scorecard',
    '> ## Grade ' + grade.letter + ' — ' + grade.label + '  ·  Score ' + grade.score + '/100',
    '',
    '| Risk class | Occurrences |',
    '|---|---|',
    '| 🔴 broken (classical) | ' + summary.broken_classical + ' |',
    '| 🟠 quantum-broken (Shor) | ' + summary.quantum_broken + ' |',
    '| 🟡 quantum-weakened (Grover) | ' + summary.quantum_weakened + ' |',
    '| 🔵 classical-hybrid-ok | ' + summary.classical_hybrid_ok + ' |',
    '| 🟢 quantum-resistant | ' + summary.quantum_safe + ' |',
    '',
    'Files scanned: ' + summary.files_scanned + '  ·  Distinct algorithms: ' + summary.distinct_algorithms,
    bc ? '\n**Triage** (tool-derived; a human assessor confirms): 🟢 likely (declared dependency) ' + bc.likely + '  ·  🟡 lead-to-verify (in code) ' + bc.lead_to_verify + '  ·  ⚪ informational (comment/doc only) ' + bc.informational : '',
    '',
    '## 2. Prioritized findings',
    findings.length ? '| Algorithm | Risk | Confidence | Count | Location |\n|---|---|---|---|---|\n' + top : '_No cryptographic findings._',
    findings.length > 25 ? '\n_…and ' + (findings.length - 25) + ' more (see the CBOM)._' : '',
    '',
    '## 3. Migration roadmap',
    renderMigrationPlan(buildMigrationPlan({ findings, grade, summary })),
    '',
    '## 4. Compliance crosswalk (informational — not a certification)',
    '| Regime | Status | What it expects |\n|---|---|---|\n' + crosswalk,
    '',
    '## 5. Methodology & limitations (honest)',
    '- This is a **lexical / pattern** scan. It does not yet do AST parsing, dependency-graph resolution, or live TLS/certificate/cloud-KMS discovery — so it can miss crypto and produce false positives. Treat findings as **leads to verify**, not a complete inventory.',
    '- "quantum-broken" = broken by **Shor** (RSA/ECC/DH). Classical curves (X25519/Ed25519) are flagged but are **acceptable as the classical leg of a hybrid**.',
    '- The compliance crosswalk indicates **relevance**, not conformance; it is not legal advice.',
    '- The accompanying CycloneDX CBOM is the machine-readable evidence artifact.',
    '',
    '_This pack is ML-DSA-87 (FIPS 204) signed; verify it with @trelyan/verify-pqc `verifyEvidencePack`. Verification recomputes the risk tallies and the grade **from the findings** and binds this rendered report — so a forged grade, a doctored summary, or an altered report is caught._',
  ].join('\n');
}

// The signed core binds: the grade, the full summary AND findings, the CBOM bytes, AND a hash of the rendered
// markdown (so the human-readable report a buyer actually reads cannot be altered while still "verifying").
// slh_signer_pub_hex is BOUND in the core so a hybrid pack cannot be downgraded by stripping the SLH leg
// (the bound non-null key would then have no matching valid signature -> verify fails).
const evidenceCore = (p) => ({ kind: p.kind, report_version: p.report_version, meta: p.meta, grade: p.grade, summary: p.summary, findings: p.findings, cbom_sha512: bytesToHex(sha512(utf8ToBytes(canon(p.cbom)))), markdown_sha512: bytesToHex(sha512(utf8ToBytes(p.markdown || ''))), slh_signer_pub_hex: p.slh_signer_pub_hex ?? null });

export function buildEvidencePack({ scan, meta = {} }) {
  const m = { org: meta.org || 'CONFIDENTIAL', scope: meta.scope || 'n/a', generated_ts: meta.generated_ts ?? null, tool: 'pqcbom', tool_version: '0.2.0-draft', report_version: '0.1' };
  const cbom = toCycloneDX(scan);
  const pack = { kind: 'pqcbom-evidence-pack', report_version: '0.1', meta: m, grade: scan.grade, summary: scan.summary, findings: scan.findings, cbom };
  pack.markdown = renderMarkdown({ summary: scan.summary, grade: scan.grade, findings: scan.findings, meta: m });
  return pack;
}
// Sign with ML-DSA-87 (FIPS-204). Pass opts.slhdsa = { secretKey, publicKey } to ALSO add an SLH-DSA-256f (FIPS-205,
// hash-based) leg over the same core -> AND-composition hybrid (apex / defense-in-depth: a forgery must break BOTH
// a lattice AND a hash-based scheme). The SLH pubkey is bound into the ML-DSA-signed core (anti-downgrade).
export function signEvidencePack(pack, signerSecret, signerPub, opts = {}) {
  const slh = opts.slhdsa;
  const signed = { ...pack, slh_signer_pub_hex: slh ? bytesToHex(slh.publicKey) : null };
  const coreBytes = utf8ToBytes(canon(evidenceCore(signed)));
  signed.signature = { alg: 'ML-DSA-87', signer_pub_hex: bytesToHex(signerPub), sig_hex: bytesToHex(ml_dsa87.sign(coreBytes, signerSecret, { context: REPORT_CTX })) };
  if (slh) signed.signature_slh = { alg: 'SLH-DSA-SHA2-256f', signer_pub_hex: bytesToHex(slh.publicKey), sig_hex: bytesToHex(slh_dsa_sha2_256f.sign(coreBytes, slh.secretKey, { context: REPORT_SLH_CTX })) };
  return signed;
}
// Verify: (1) the signature binds the whole core (incl. the rendered markdown); (2) the stated risk tallies are
// independently RECOMPUTED FROM THE FINDINGS (a forged "clean" summary over bad findings is caught even with no key
// pinned); (3) the grade follows from those findings-derived tallies. So the grade is provably a function of the
// findings — not a trusted number.
// VALIDITY vs TRUST (honest model, council red-team Attack 5): with NO key pinned, a passing result proves only
// SELF-CONSISTENCY (signatures valid under the EMBEDDED key + grade/summary/markdown bound) — NOT authenticity, since
// an attacker can self-sign. Authenticity requires a trust anchor: check `trustAnchored` (a caller-supplied key
// matched), or pass opts.requirePinned to make `verified` itself demand it. For a paid artifact, ALWAYS pin.
// opts.trustedSlhPub = pin the SLH-DSA key (Uint8Array). opts.requireHybrid = reject a pack that is not dual-signed.
// opts.requirePinned = `verified` requires a matched trust anchor (recommended for high-assurance consumers).
export function verifyEvidencePack(pack, trustedSignerPub, opts = {}) {
  try {
    const ctx = (pack.summary && pack.summary.grade_context) === 'code' ? 'code' : 'total';
    const rt = riskTally(pack.findings || [], ctx);
    const keys = ['broken_classical', 'quantum_broken', 'quantum_weakened', 'classical_hybrid_ok', 'quantum_safe'];
    const summaryConsistent = !!pack.summary && keys.every((k) => rt[k] === pack.summary[k]);
    const recomputed = gradeOf(rt); // grade from the FINDINGS-derived tallies, not the (untrusted) stated summary
    const gradeConsistent = summaryConsistent && recomputed.letter === pack.grade.letter && recomputed.score === pack.grade.score;
    const coreBytes = utf8ToBytes(canon(evidenceCore(pack)));
    // ML-DSA-87 (primary)
    const s = pack.signature;
    // pinOk = "no key supplied, OR the supplied key matched" (internal: don't fail a no-pin verification). The SURFACED
    // `pinned` (see return) is the honest TRUST flag: a key was supplied AND matched — validity != trust (sweep R1).
    const pinOk = !trustedSignerPub || (s && s.signer_pub_hex && s.signer_pub_hex.toLowerCase() === bytesToHex(trustedSignerPub).toLowerCase());
    let sigOk = false;
    if (s && s.sig_hex) sigOk = ml_dsa87.verify(hexToBytes(s.sig_hex), coreBytes, trustedSignerPub ? trustedSignerPub : hexToBytes(s.signer_pub_hex), { context: REPORT_CTX });
    // SLH-DSA-256f diversity leg (AND-composition). The core BINDS slh_signer_pub_hex, so a hybrid pack cannot be
    // downgraded by stripping the leg; and an SLH leg bolted onto a non-hybrid core (slh_signer_pub_hex=null) fails.
    const declaredHybrid = pack.slh_signer_pub_hex != null;
    const s2 = pack.signature_slh;
    const hybrid = declaredHybrid || !!s2;
    let slhConsistent = !hybrid, slhValid = !hybrid;
    if (hybrid) {
      slhConsistent = !!(declaredHybrid && s2 && s2.signer_pub_hex && s2.signer_pub_hex.toLowerCase() === String(pack.slh_signer_pub_hex).toLowerCase());
      const slhPin = !opts.trustedSlhPub || (declaredHybrid && String(pack.slh_signer_pub_hex).toLowerCase() === bytesToHex(opts.trustedSlhPub).toLowerCase());
      slhValid = false;
      if (slhConsistent && slhPin && s2 && s2.sig_hex) { try { slhValid = slh_dsa_sha2_256f.verify(hexToBytes(s2.sig_hex), coreBytes, hexToBytes(pack.slh_signer_pub_hex), { context: REPORT_SLH_CTX }); } catch { slhValid = false; } }
    }
    const hybridOk = !hybrid || (slhConsistent && slhValid);          // a present 2nd leg MUST verify
    const meetsHybridReq = !opts.requireHybrid || (hybrid && slhValid); // caller can demand dual-signing
    // authenticity (not just self-consistency): a caller trust anchor was supplied AND matched (both legs, if hybrid)
    const trustAnchored = !!trustedSignerPub && pinOk && sigOk && (!hybrid || (!!opts.trustedSlhPub && slhValid));
    // SLH leg trust, surfaced independently (code-security review): requireHybrid ALONE proves a VALID 2nd leg is
    // present, NOT that it is pinned — without trustedSlhPub it's verified under the pack's OWN embedded SLH key.
    // High-assurance callers should combine requireHybrid + trustedSlhPub + requirePinned (which forces this true).
    const slhTrustAnchored = !!opts.trustedSlhPub && hybrid && slhConsistent && slhValid;
    const selfConsistent = summaryConsistent && gradeConsistent && pinOk && sigOk && hybridOk && meetsHybridReq;
    const verified = !!(selfConsistent && (!opts.requirePinned || trustAnchored));
    // surfaced `pinned` = TRUST (key supplied AND matched), not validity; `pinOk` exposes the internal matches-or-no-key.
    return { verified, trustAnchored, slhTrustAnchored, summaryConsistent, gradeConsistent, pinned: !!trustedSignerPub && !!pinOk, pinOk: !!pinOk, sigOk, hybrid, slhValid, slhConsistent };
  } catch { return { verified: false, trustAnchored: false, slhTrustAnchored: false, summaryConsistent: false, gradeConsistent: false, pinned: false, sigOk: false, hybrid: false, slhValid: false, slhConsistent: false }; }
}

/* ---------- self-test: node pqcbom-report.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const scan = scanFiles([{ name: 'legacy.js', text: 'RSA-2048; ECDSA secp256k1; AES-128; MD5; ml_kem1024; ml_dsa87; SHA-512;' }]);
  const signer = ml_dsa87.keygen(new Uint8Array(32).fill(61));

  const pack = buildEvidencePack({ scan, meta: { org: 'org-7f', scope: 'TLS + signing', generated_ts: 1000 } });
  ok(pack.kind === 'pqcbom-evidence-pack' && pack.grade.letter === 'F' && pack.cbom.bomFormat === 'CycloneDX', 'builds an evidence pack (grade F, CBOM embedded)');
  ok(/PQC Migration Evidence Pack/.test(pack.markdown) && /Migration roadmap/.test(pack.markdown) && /Compliance crosswalk/.test(pack.markdown) && /limitations/.test(pack.markdown), 'report markdown has scorecard + roadmap + crosswalk + honest limits');

  const signed = signEvidencePack(pack, signer.secretKey, signer.publicKey);
  ok(verifyEvidencePack(signed, signer.publicKey).verified === true, 'signed evidence pack verifies under the pinned signer key');
  ok(verifyEvidencePack(signed, ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey).verified === false, 'wrong signer key -> NOT verified');

  // anti grade-forgery: claim grade A over F findings -> recompute catches it
  const forged = JSON.parse(JSON.stringify(signed)); forged.grade = { letter: 'A', score: 100, label: 'PQ Readiness A', badge: 'PQ Readiness: A' };
  const fv = verifyEvidencePack(forged, signer.publicKey);
  ok(fv.verified === false && (fv.sigOk === false || fv.gradeConsistent === false), 'forged grade A over F findings -> verify FAILS (grade recomputed from findings + sig binds it)');

  // tamper a finding (changes signed core) -> signature fails
  const tampered = JSON.parse(JSON.stringify(signed)); if (tampered.findings[0]) tampered.findings[0].risk = 'quantum-safe';
  ok(verifyEvidencePack(tampered, signer.publicKey).verified === false, 'tampered findings -> signature verification FAILS');

  // forge BOTH summary AND grade to look clean while leaving the bad findings -> recompute-from-findings catches it
  const forgedSummary = JSON.parse(JSON.stringify(signed));
  forgedSummary.summary = { ...forgedSummary.summary, broken_classical: 0, quantum_broken: 0, quantum_weakened: 0, classical_hybrid_ok: 0, quantum_safe: 0 };
  forgedSummary.grade = { letter: 'A', score: 100, label: 'PQ Readiness A', badge: 'PQ Readiness: A' };
  const fs2 = verifyEvidencePack(forgedSummary, signer.publicKey);
  ok(fs2.verified === false && fs2.summaryConsistent === false, 'forged clean summary+grade over bad findings -> verify FAILS (tallies recomputed from findings)');

  // alter the human-readable markdown only (signed core binds markdown_sha512) -> verification FAILS
  const tamperedMd = JSON.parse(JSON.stringify(signed)); tamperedMd.markdown = (tamperedMd.markdown || '') + '\n<!-- the real posture is fine, ignore the F -->';
  ok(verifyEvidencePack(tamperedMd, signer.publicKey).verified === false, 'altered markdown report -> verification FAILS (markdown bound into signed core)');

  // --- HYBRID (AND-composition) dual-scheme signing: ML-DSA-87 ∧ SLH-DSA-256f ---
  const slhSigner = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(73));
  const hy = signEvidencePack(pack, signer.secretKey, signer.publicKey, { slhdsa: slhSigner });
  const hv = verifyEvidencePack(hy, signer.publicKey, { trustedSlhPub: slhSigner.publicKey });
  ok(hv.verified === true && hv.hybrid === true && hv.slhValid === true, 'hybrid pack verifies under BOTH pinned ML-DSA + SLH-DSA keys');
  ok(verifyEvidencePack(hy, signer.publicKey).verified === true, 'hybrid pack still verifies when only ML-DSA is pinned (SLH leg self-consistent)');
  ok(verifyEvidencePack(signed, signer.publicKey, { requireHybrid: true }).verified === false, 'requireHybrid REJECTS an ML-DSA-only pack');
  // anti-downgrade: STRIP the SLH leg from a hybrid pack -> the bound slh_signer_pub_hex has no matching sig -> FAILS
  const stripped = JSON.parse(JSON.stringify(hy)); delete stripped.signature_slh;
  ok(verifyEvidencePack(stripped, signer.publicKey).verified === false, 'stripping the SLH leg from a hybrid pack -> verify FAILS (anti-downgrade: SLH pubkey bound in core)');
  // tamper the SLH signature -> hybridOk false -> FAILS
  const badSlh = JSON.parse(JSON.stringify(hy)); badSlh.signature_slh.sig_hex = badSlh.signature_slh.sig_hex.slice(0, -2) + (badSlh.signature_slh.sig_hex.endsWith('00') ? '11' : '00');
  ok(verifyEvidencePack(badSlh, signer.publicKey).verified === false, 'tampered SLH signature -> verify FAILS (AND-composition)');
  // bolt an SLH leg onto a non-hybrid core (slh_signer_pub_hex stays null) -> not bound -> FAILS
  const bolted = JSON.parse(JSON.stringify(signed)); bolted.signature_slh = JSON.parse(JSON.stringify(hy.signature_slh));
  ok(verifyEvidencePack(bolted, signer.publicKey).verified === false, 'SLH leg bolted onto a non-hybrid (unbound) core -> verify FAILS');
  // wrong SLH pin -> FAILS even though the embedded SLH sig is self-consistent
  ok(verifyEvidencePack(hy, signer.publicKey, { trustedSlhPub: slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(5)).publicKey }).verified === false, 'wrong pinned SLH key -> verify FAILS');

  // VALIDITY vs TRUST (council Attack 5): an attacker self-signs a fabricated pack. With NO pin it is self-consistent
  // (verified) but NOT trust-anchored; requirePinned makes `verified` itself reject it.
  const evilSigner = ml_dsa87.keygen(new Uint8Array(32).fill(200));
  const evil = signEvidencePack(buildEvidencePack({ scan, meta: { org: 'attacker', generated_ts: 1 } }), evilSigner.secretKey, evilSigner.publicKey);
  const eUnpinned = verifyEvidencePack(evil); // no trust anchor
  ok(eUnpinned.verified === true && eUnpinned.trustAnchored === false, 'unpinned verify of a self-signed pack -> self-consistent (verified) but trustAnchored=FALSE (not authentic)');
  ok(eUnpinned.pinned === false && eUnpinned.pinOk === true, 'sweep-R1 lock: surfaced `pinned` is FALSE with no key supplied (trust, not validity); pinOk exposes the internal matches-or-no-key');
  ok(verifyEvidencePack(evil, undefined, { requirePinned: true }).verified === false, 'requirePinned -> unpinned self-signed pack is NOT verified');
  ok(verifyEvidencePack(signed, signer.publicKey).trustAnchored === true, 'pinned verify under the real key -> trustAnchored=TRUE');
  ok(verifyEvidencePack(evil, signer.publicKey).verified === false, 'attacker pack under the REAL pinned key -> verify FAILS');

  console.log('pqcbom-report self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqcbom-report\.mjs$/.test(process.argv[1] || '')) selfTest();
