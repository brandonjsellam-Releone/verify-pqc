/*!
 * pqcbom-plan — turn a CBOM scan into a PRIORITIZED, SEQUENCED PQC migration plan (reference, DRAFT, standalone).
 *
 * Net-new product layer on top of pqcbom: scan -> grade -> findings -> a PHASED migration roadmap, ordered by real
 * urgency + dependency (harvest-now-decrypt-later means KEM/key-establishment migrates BEFORE signatures), with a rough
 * effort tier per phase and the risk class each phase clears. It is the structured "roadmap" the paid Evidence Pack
 * promises — buildMigrationPlan() returns a plain object (embeddable + hashable in the signed pack), renderMigrationPlan()
 * renders it to markdown. Dependency-free; a pure function of the scan findings.
 *
 * HONEST: a RECOMMENDED, sequenced plan — not a guarantee. Effort tiers (S/M/L) are rough relative sizing, NOT estimates
 * or costs. Sequencing encodes the standard PQC-migration urgency (NSM-10 / CNSA 2.0 spirit), not a project schedule.
 * Findings are leads to verify; this is not legal/compliance advice. Self-test: node pqcbom-plan.mjs
 */

// Phases in execution order. Each finding is assigned to the FIRST phase it matches (no double-count, no drop).
const PHASE_DEFS = [
  { id: 1, name: 'Eliminate classically-broken cryptography', when: 'Now (P0)',
    match: (f) => f.risk === 'broken-classical',
    why: 'Broken regardless of quantum (MD5/SHA-1/RC4/3DES/Blowfish, deprecated TLS, and broken-PQ candidates like SIKE/SIDH) — exploitable today.',
    action: 'Remove/replace immediately: hashes -> SHA-512/SHA3-512; ciphers -> AES-256-GCM; require TLS 1.2+ (1.3 preferred); never use a broken-PQ candidate.' },
  { id: 2, name: 'Migrate quantum-broken key establishment (KEM/DH)', when: '0-6 months (P1, most urgent)',
    match: (f) => f.risk === 'quantum-broken' && f.family === 'kem',
    why: 'Harvest-now, decrypt-later: ciphertext recorded today becomes decryptable once a CRQC exists — the most time-urgent PQ move.',
    action: 'Adopt ML-KEM-1024 (FIPS 203) in a HYBRID X25519+ML-KEM construction during the transition.' },
  { id: 3, name: 'Migrate quantum-broken public keys & signatures', when: '6-18 months (P1)',
    match: (f) => f.risk === 'quantum-broken',
    why: 'Signature forgery needs a CRQC at verification time (less immediate than KEM), but long-lived roots / code-signing / certs must migrate early.',
    action: 'Adopt ML-DSA-87 (FIPS 204) + SLH-DSA (FIPS 205) for algorithm diversity; keep RSA/ECDSA only as a HYBRID leg.' },
  { id: 4, name: 'Upgrade quantum-weakened symmetric & hash', when: '6-18 months (P2)',
    match: (f) => f.risk === 'quantum-weakened',
    why: 'Grover roughly halves the effective security level of symmetric primitives and hashes.',
    action: 'Move AES-128/192 -> AES-256-GCM; SHA-256 -> SHA-384/512.' },
  { id: 5, name: 'Confirm hybrid legs & managed crypto', when: 'Ongoing (P3)',
    match: (f) => f.risk === 'classical-hybrid-ok',
    why: 'Classical curves (X25519/Ed25519) are safe ONLY inside a hybrid; managed KMS/HSM safety depends on the provider PQ roadmap.',
    action: 'Pair each classical leg with a PQ KEM/sig; confirm your KMS/HSM/library PQ support + a key-rotation plan.' },
];

function effortTier(occ, distinct) {
  if (occ <= 4 && distinct <= 2) return 'S';   // a few occurrences, 1-2 algorithms
  if (occ <= 20) return 'M';
  return 'L';                                   // pervasive across the codebase
}

// buildMigrationPlan(report): report = a pqcbom scanFiles()/scanDirectory() result ({ findings, grade, summary }).
export function buildMigrationPlan(report) {
  const findings = (report && report.findings) || [];
  const claimed = new Array(findings.length).fill(false);
  const phases = [];
  for (const p of PHASE_DEFS) {
    const items = [];
    findings.forEach((f, idx) => { if (!claimed[idx] && p.match(f)) { items.push(f); claimed[idx] = true; } });
    const occ = items.reduce((n, f) => n + (f.count || 0), 0);
    if (!occ) continue;
    const algos = [...new Set(items.map((f) => f.algo))];
    phases.push({
      phase: p.id, name: p.name, when: p.when, why: p.why, action: p.action,
      effort: effortTier(occ, algos.length), occurrences: occ, distinct_algorithms: algos.length,
      algorithms: algos, recommendations: [...new Set(items.map((f) => f.rec))],
    });
  }
  const toAddress = findings.filter((f) => f.risk !== 'quantum-safe').reduce((n, f) => n + (f.count || 0), 0);
  return {
    plan_version: '1',
    summary: {
      grade_now: report && report.grade ? report.grade.letter : null,
      phases: phases.length,
      occurrences_to_address: toAddress,
      first_action: phases.length ? `Phase ${phases[0].phase}: ${phases[0].name}` : 'No quantum-vulnerable or broken cryptography found — maintain posture.',
    },
    phases,
    note: 'Recommended, sequenced plan derived from the scan findings. Effort tiers (S/M/L) are ROUGH relative sizing, NOT estimates/costs; sequencing reflects harvest-now-decrypt-later urgency (KEM before signatures), not a project schedule. Findings are leads to verify. Not legal/compliance advice.',
  };
}

export function renderMigrationPlan(plan) {
  if (!plan || !plan.phases.length) return '_No quantum-vulnerable or broken cryptography detected — maintain current posture (re-scan on dependency changes)._';
  const out = [`**Sequenced plan** — ${plan.summary.phases} phase(s), ${plan.summary.occurrences_to_address} occurrence(s) to address. Start: ${plan.summary.first_action}.`, ''];
  for (const p of plan.phases) {
    out.push(`### Phase ${p.phase} — ${p.name}  ·  ${p.when}  ·  effort ${p.effort}`);
    out.push(`*${p.why}*`);
    out.push(`- **Affected:** ${p.occurrences} occurrence(s) across ${p.distinct_algorithms} algorithm(s): ${p.algorithms.map((a) => '`' + a + '`').join(', ')}`);
    out.push(`- **Do:** ${p.action}`);
    out.push('');
  }
  out.push('_' + plan.note + '_');
  return out.join('\n');
}

/* ---------- self-test: node pqcbom-plan.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const F = (algo, risk, family, count) => ({ algo, risk, family, count, rec: 'rec for ' + algo });
  const report = { grade: { letter: 'F' }, findings: [
    F('MD5', 'broken-classical', 'hash', 3),
    F('RSA', 'quantum-broken', 'pubkey', 2),
    F('ECDH', 'quantum-broken', 'kem', 1),
    F('ECDSA', 'quantum-broken', 'signature', 5),
    F('AES-128/192', 'quantum-weakened', 'cipher', 1),
    F('X25519/X448', 'classical-hybrid-ok', 'kem', 1),
    F('ML-KEM/Kyber', 'quantum-safe', 'kem', 4),    // must NOT appear in any phase
  ] };
  const plan = buildMigrationPlan(report);
  ok(plan.phases.length === 5, 'all 5 phases present when each risk class is represented');
  ok(plan.phases[0].phase === 1 && plan.phases[0].name.includes('broken'), 'phase 1 = eliminate broken (first)');
  // urgency ordering: KEM migration (phase 2) comes BEFORE signature migration (phase 3)
  const kemPhase = plan.phases.find((p) => p.phase === 2), sigPhase = plan.phases.find((p) => p.phase === 3);
  ok(kemPhase.algorithms.includes('ECDH') && !kemPhase.algorithms.includes('RSA'), 'phase 2 (KEM) holds ECDH, not the pubkey/sig items');
  ok(sigPhase.algorithms.includes('RSA') && sigPhase.algorithms.includes('ECDSA'), 'phase 3 holds the quantum-broken pubkey/sig items (RSA, ECDSA)');
  ok(plan.phases.indexOf(kemPhase) < plan.phases.indexOf(sigPhase), 'KEM phase is sequenced before the signature phase (harvest-now-decrypt-later)');
  // no double-count / no drop: every non-safe occurrence is in exactly one phase
  const inPhases = plan.phases.reduce((n, p) => n + p.occurrences, 0);
  ok(inPhases === 3 + 2 + 1 + 5 + 1 + 1, 'every non-quantum-safe occurrence assigned to exactly one phase (no drop, no double-count)');
  ok(!plan.phases.some((p) => p.algorithms.includes('ML-KEM/Kyber')), 'quantum-safe crypto is NOT put in the migration plan');
  ok(plan.phases.find((p) => p.phase === 3).effort === 'M' && plan.phases.find((p) => p.phase === 4).effort === 'S', 'effort tiers: 7 occ -> M, 1 occ -> S');
  ok(/Effort tiers .*ROUGH|ROUGH relative/.test(plan.note) && /Not legal/.test(plan.note), 'plan carries the honest "rough, not estimates / not legal advice" note');
  // clean scan -> no phases
  const clean = buildMigrationPlan({ grade: { letter: 'A' }, findings: [F('ML-DSA/Dilithium', 'quantum-safe', 'signature', 2)] });
  ok(clean.phases.length === 0 && /maintain posture/.test(clean.summary.first_action), 'all-safe scan -> no phases, maintain-posture summary');
  ok(renderMigrationPlan(clean).includes('No quantum-vulnerable'), 'render of an empty plan is the honest no-op message');
  ok(/Phase 1/.test(renderMigrationPlan(plan)) && /KEM/.test(renderMigrationPlan(plan)), 'markdown render lists the phases');

  console.log('pqcbom-plan self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqcbom-plan\.mjs$/.test(process.argv[1] || '')) selfTest();
