/*!
 * pqverify — real verifiers for the claim-gate (reference, DRAFT, standalone). Drives hallucination toward the floor.
 *
 * Pluggable verifiers conforming to the pqclaimgate interface { type, id, async check(claim, evidence_refs) }
 * -> { type, id, verdict: PASS|FAIL|ABSTAIN, score, detail }. Ordered by the council's measured impact:
 *   1. deterministicMath   — evaluates arithmetic claims; a false equation is a FAIL (hard catch).
 *   2. citationSupport     — checks the claim's content is actually PRESENT in its cited evidence (catches
 *                            "grounded but the source doesn't support it" — Gemini's failure mode); low support => ABSTAIN.
 *   3. selfConsistency     — semantic-entropy proxy: if the model's own re-samples disagree => ABSTAIN.
 *   4. refutation (factory)— CROSS-MODEL ADVERSARIAL: N refuters try to produce a GROUNDED counter-claim; a
 *                            validated refutation => FAIL. The single biggest hallucination reducer (DeepSeek).
 *
 * HONEST LIMITS: these are reference checks. deterministicMath only catches explicit arithmetic; citationSupport
 * is lexical (a real deployment uses NLI entailment + a trusted corpus); refutation is only as good as the
 * refuters + their grounding. PASS means "passed this check", never "true". Self-test: node pqverify.mjs
 */
const round = (x, n = 3) => Math.round(x * 10 ** n) / 10 ** n;

/* 1. deterministic arithmetic — a false equation is an unambiguous hallucination */
export const deterministicMath = { type: 'deterministic_math', id: 'math', async check(claim) {
  const m = String(claim.claim).match(/(-?\d+(?:\.\d+)?)\s*([+\-*/])\s*(-?\d+(?:\.\d+)?)\s*=\s*(-?\d+(?:\.\d+)?)/);
  if (!m) return { type: 'deterministic_math', id: 'math', verdict: 'ABSTAIN', score: 0, detail: 'no arithmetic claim' };
  const a = +m[1], op = m[2], b = +m[3], c = +m[4];
  const r = op === '+' ? a + b : op === '-' ? a - b : op === '*' ? a * b : (b !== 0 ? a / b : NaN);
  const okk = Number.isFinite(r) && Math.abs(r - c) < 1e-9;
  return { type: 'deterministic_math', id: 'math', verdict: okk ? 'PASS' : 'FAIL', score: okk ? 1 : 0, detail: a + op + b + '=' + (Number.isFinite(r) ? r : 'NaN') + ' (claimed ' + c + ')' };
} };

/* 2. citation support — the claim's content must actually appear in its cited evidence */
export const citationSupport = { type: 'source_attestation', id: 'citation', async check(claim, refs) {
  const toks = (String(claim.claim).toLowerCase().match(/[a-z0-9]{4,}/g) || []);
  const have = (refs || []).filter((r) => r.grounded);
  if (!toks.length || !have.length) return { type: 'source_attestation', id: 'citation', verdict: 'ABSTAIN', score: 0, detail: 'no content tokens or no grounded evidence' };
  const hay = have.map((r) => String((r.selector || '') + ' ' + (r.text || '')).toLowerCase()).join(' ');
  const present = toks.filter((t) => hay.includes(t)).length;
  const overlap = present / toks.length;
  const verdict = overlap >= 0.6 ? 'PASS' : 'ABSTAIN'; // low support => can't verify (not a contradiction) => ABSTAIN
  return { type: 'source_attestation', id: 'citation', verdict, score: round(overlap), detail: { overlap: round(overlap), present, total: toks.length } };
} };

/* 3. self-consistency — disagreement among the model's own re-samples => abstain (semantic-entropy proxy) */
export const selfConsistency = { type: 'self_consistency', id: 'selfcons', async check(claim) {
  const s = claim.samples;
  if (!Array.isArray(s) || s.length < 2) return { type: 'self_consistency', id: 'selfcons', verdict: 'ABSTAIN', score: 0, detail: 'insufficient samples' };
  const groups = new Map();
  for (const x of s) { const k = String(x).trim().toLowerCase(); groups.set(k, (groups.get(k) || 0) + 1); }
  const agreement = Math.max(...groups.values()) / s.length;
  return { type: 'self_consistency', id: 'selfcons', verdict: agreement >= 0.7 ? 'PASS' : 'ABSTAIN', score: round(agreement), detail: { agreement: round(agreement), samples: s.length } };
} };

/* 4. cross-model adversarial refutation — callRefuter(claim, refs, i) -> { refuted: bool, grounded: bool, counter? } */
export function makeRefutation(callRefuter, { n = 3 } = {}) {
  return { type: 'refutation', id: 'refute', async check(claim, refs) {
    let tried = 0, validated = null;
    for (let i = 0; i < n; i++) { const r = await callRefuter(claim, refs, i); tried++; if (r && r.refuted && r.grounded) { validated = r; break; } }
    return validated
      ? { type: 'refutation', id: 'refute', verdict: 'FAIL', score: 0, detail: { refuted_by: validated.counter || 'a grounded counter-claim', after: tried } }
      : { type: 'refutation', id: 'refute', verdict: 'PASS', score: 1, detail: 'survived ' + tried + ' refutation attempts' };
  } };
}

/* ---------- self-test: node pqverify.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // 1. deterministic math
  ok((await deterministicMath.check({ claim: '2 + 2 = 4' })).verdict === 'PASS', 'math: 2+2=4 -> PASS');
  ok((await deterministicMath.check({ claim: 'clearly 1 + 1 = 3 here' })).verdict === 'FAIL', 'math: 1+1=3 -> FAIL (hallucination caught)');
  ok((await deterministicMath.check({ claim: 'the sky is blue' })).verdict === 'ABSTAIN', 'math: no arithmetic -> ABSTAIN');

  // 2. citation support
  ok((await citationSupport.check({ claim: 'Category post-quantum security level' }, [{ grounded: true, selector: 'provides Category 5 post-quantum security level' }])).verdict === 'PASS', 'citation: content present in source -> PASS');
  ok((await citationSupport.check({ claim: 'Atlantis discovered beneath antarctic ice' }, [{ grounded: true, selector: 'an article about domestic cats' }])).verdict === 'ABSTAIN', 'citation: source does not support -> ABSTAIN');

  // 3. self-consistency
  ok((await selfConsistency.check({ claim: 'x', samples: ['A', 'A', 'A', 'B'] })).verdict === 'PASS', 'selfcons: 3/4 agree -> PASS');
  ok((await selfConsistency.check({ claim: 'x', samples: ['A', 'B', 'C'] })).verdict === 'ABSTAIN', 'selfcons: all disagree -> ABSTAIN');
  ok((await selfConsistency.check({ claim: 'x' })).verdict === 'ABSTAIN', 'selfcons: no samples -> ABSTAIN');

  // 4. refutation (stub refuter refutes known-false claims with a grounded counter)
  const callRefuter = async (claim) => ({ refuted: /vaccines cause autism|moon landing was faked|earth is flat/i.test(claim.claim), grounded: true, counter: 'peer-reviewed evidence' });
  const refute = makeRefutation(callRefuter, { n: 3 });
  ok((await refute.check({ claim: 'The earth is flat.' })).verdict === 'FAIL', 'refutation: a grounded counter refutes -> FAIL');
  ok((await refute.check({ claim: 'ML-KEM-1024 is a NIST-standardized KEM.' })).verdict === 'PASS', 'refutation: survives -> PASS');

  // 5. END-TO-END through the real ClaimGate: lowest-hallucination stack catches false-math, refuted, unsupported; passes the good one
  const { ClaimGate } = await import('./pqclaimgate.mjs');
  const gate = new ClaimGate({ verifiers: [deterministicMath, citationSupport, selfConsistency, refute] });
  const cons = { strength: 0.85, total_considered: 4, dissent: { count: 0 } };
  const claims = [
    { id: 'good', claim: 'ML-KEM-1024 provides Category 5 post-quantum security.', evidence_refs: [{ ref: 'src:fips203', selector: 'ML-KEM-1024 provides Category 5 post-quantum security', grounded: true, ef_score: 0.9 }], consensus: cons, samples: ['ML-KEM-1024 provides Category 5 post-quantum security', 'ML-KEM-1024 provides Category 5 post-quantum security', 'ML-KEM-1024 provides Category 5 post-quantum security'] },
    { id: 'falsemath', claim: 'Therefore 1 + 1 = 3.', evidence_refs: [{ ref: 'src:x', selector: '1 + 1 = 3', grounded: true, ef_score: 0.5 }], consensus: cons },
    { id: 'refuted', claim: 'The earth is flat.', evidence_refs: [{ ref: 'src:y', selector: 'the earth is flat', grounded: true, ef_score: 0.5 }], consensus: cons },
    { id: 'unsupported', claim: 'Atlantis discovered beneath antarctic ice in 2024.', evidence_refs: [{ ref: 'src:cats', selector: 'an article about domestic cats and behavior', grounded: true, ef_score: 0.3 }], consensus: cons },
  ];
  const ev = await gate.evaluateAll(claims);
  const st = (id) => ev.find((c) => c.id === id).status;
  ok(st('good') === 'verified', 'e2e: grounded + consistent + survives refutation -> VERIFIED');
  ok(st('falsemath') === 'rejected', 'e2e: false arithmetic -> REJECTED');
  ok(st('refuted') === 'rejected', 'e2e: refuted by counter-evidence -> REJECTED');
  ok(st('unsupported') === 'abstained', 'e2e: source does not support -> ABSTAINED (not emitted)');
  const env = gate.assemble('q', ev);
  ok(env.emitted.verified_claims.length === 1 && !env.emitted.rendered.includes('flat') && !env.emitted.rendered.includes('Atlantis') && !env.emitted.rendered.includes('1 + 1 = 3'), 'e2e: only the verified claim is emitted; hallucinations excluded');

  console.log('pqverify self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqverify\.mjs$/.test(process.argv[1] || '')) selfTest();
