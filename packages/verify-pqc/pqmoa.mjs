/*!
 * pqmoa — Post-Quantum-Attested Mixture-of-Agents (reference, DRAFT, standalone).
 *
 * The flagship of "the AI you can put on the record": an orchestrated council of N models whose final
 * answer ships a VERIFIABLE receipt of which models contributed, what each said, the synthesis, and the
 * DISSENT — cryptographically attested (ML-DSA-87) and transparency-loggable, reusing pqcouncil.
 *
 * This is NOT a weight-merge of models (we never claim to have trained/distilled one). It is a verifiable
 * Mixture-of-Agents: proposers -> aggregate (consensus + dissent) -> attest. The value is ATTRIBUTABLE,
 * ACCOUNTABLE AI, not a magic accuracy boost.
 *
 * HONEST LIMITS:
 *  - `consensus_strength` = the fraction of proposers that AGREE on the answer — it is NOT a calibrated
 *    accuracy/confidence and must never be reported as "% correct". Real accuracy must be MEASURED on real
 *    benchmarks (MMLU-Pro / GPQA / SWE-bench / Arena-Hard) vs the best single model WITH the same tools.
 *  - Published evidence (Together-AI MoA) shows ~+3-5% on reasoning/coding + ~30% fewer severe hallucinations,
 *    domain-dependent and at higher cost/latency — not universal superiority.
 *  - The attestation proves WHAT ran (which models said what + the synthesis), NOT that the answer is correct.
 * New, self-contained reference code; reuses pqcouncil for the attestation. Self-test: node pqmoa.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { notarizeCouncilRun, addWitness, verifyCouncilRun, generateCouncilKey } from './pqcouncil.mjs';

const sha = (s) => bytesToHex(sha256(typeof s === 'string' ? utf8ToBytes(s) : s));

/* ---------- Mixture-of-Agents aggregation (consensus + dissent) ----------
 * proposals: [{ seat, model_id, response, answer? }]  — `answer` is an optional normalized label/key used
 * for agreement grouping (else the raw response is used). `synthesize(proposals, top, dissent)` is an optional
 * aggregator (in production: a strong supervisor model); default returns the plurality answer. */
export function aggregate({ proposals, synthesize } = {}) {
  if (!Array.isArray(proposals) || proposals.length === 0) throw new Error('pqmoa.aggregate: need >=1 proposal');
  const key = (p) => String(p.answer ?? p.response).trim();
  const groups = new Map();
  for (const p of proposals) { const k = key(p); (groups.get(k) || groups.set(k, []).get(k)).push(p); }
  const ranked = [...groups.entries()].sort((a, b) => b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1));
  const [topAnswer, topGroup] = ranked[0];
  const consensus_strength = topGroup.length / proposals.length; // AGREEMENT, not accuracy
  const dissent = proposals.filter((p) => key(p) !== topAnswer).map((p) => ({ seat: p.seat, model_id: p.model_id, position: key(p) }));
  const synthesis = synthesize ? synthesize(proposals, topAnswer, dissent) : topAnswer;
  return { answer: topAnswer, synthesis, consensus_strength, agreed: topGroup.length, total: proposals.length, distinct_positions: groups.size, dissent };
}

/* ---------- PQ attestation of the MoA run (reuses pqcouncil) ----------
 * Signs { question, roster of (seat,model_id), each seat's response, synthesis } so anyone can verify WHAT ran.
 * order = { secretKey, publicKey } (ML-DSA-87); opts forwarded to pqcouncil (nonce/ts). */
export function attestMoA({ question, proposals, synthesis, councilName }, order, opts = {}) {
  const seats = proposals.map((p) => ({ seat: p.seat, model_id: p.model_id, response: p.response }));
  return notarizeCouncilRun({ question, seats, synthesis, council: councilName || 'trelyan-pq-moa-v1' }, order.secretKey, order.publicKey, opts);
}
// add an independent witness co-signature (signed-claim -> witnessed-record)
export function addMoAWitness(att, witness, role = 'witness') { return addWitness(att, witness.secretKey, witness.publicKey, role); }
// verify the attested run (pinned trustedSigners + expectedRoster + optional witnesses); evidence = { question, seats, synthesis }
export function verifyMoA(att, evidence, opts = {}) { return verifyCouncilRun(att, evidence, opts); }

// convenience: run the whole pipeline given already-collected proposals + an order key
export function runAttestedMoA({ question, proposals, synthesize, councilName }, order, opts = {}) {
  const agg = aggregate({ proposals, synthesize });
  const att = attestMoA({ question, proposals, synthesis: agg.synthesis, councilName }, order, opts);
  return { ...agg, attestation: att };
}

/* ---------- self-test: node pqmoa.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const order = generateCouncilKey(new Uint8Array(32).fill(41));
  const w1 = generateCouncilKey(new Uint8Array(32).fill(42));
  const trustedSigners = [bytesToHex(order.publicKey)];

  // 5 proposers: 3 agree on "A", 2 dissent ("B","C")
  const proposals = [
    { seat: 'deepseek', model_id: 'deepseek-v4-pro', response: 'The answer is A because X.', answer: 'A' },
    { seat: 'openai', model_id: 'gpt-5.5-pro', response: 'A — supported by Y.', answer: 'A' },
    { seat: 'gemini', model_id: 'gemini-3.1-pro', response: 'A.', answer: 'A' },
    { seat: 'grok', model_id: 'grok-4.3', response: 'Actually B.', answer: 'B' },
    { seat: 'mistral', model_id: 'mistral-large-2512', response: 'I think C.', answer: 'C' },
  ];
  const question = 'What is the answer?';

  // 1. aggregation: plurality A, consensus 3/5, dissent = the B and C seats
  const agg = aggregate({ proposals });
  ok(agg.answer === 'A' && Math.abs(agg.consensus_strength - 0.6) < 1e-9 && agg.agreed === 3 && agg.total === 5, 'aggregate: plurality A, consensus_strength 0.6');
  ok(agg.dissent.length === 2 && agg.dissent.some((d) => d.seat === 'grok') && agg.dissent.some((d) => d.seat === 'mistral'), 'dissent map names the 2 dissenting seats');
  ok(agg.distinct_positions === 3, 'three distinct positions counted');

  // 2. unanimous -> consensus 1.0, no dissent
  const unan = aggregate({ proposals: proposals.slice(0, 3) });
  ok(unan.consensus_strength === 1 && unan.dissent.length === 0, 'unanimous run -> consensus_strength 1.0, empty dissent');

  // 3. custom synthesizer is used
  const aggS = aggregate({ proposals, synthesize: (ps, top, d) => `Consensus ${top}; ${d.length} dissent(s).` });
  ok(aggS.synthesis === 'Consensus A; 2 dissent(s).', 'custom synthesize() applied');

  // 4. attest the run + verify (signed-claim) with pinned signer + expected roster
  const run = runAttestedMoA({ question, proposals }, order, { ts: 1000, nonce: 'moa-1' });
  const expectedRoster = proposals.map((p) => ({ seat: p.seat, model_id: p.model_id }));
  const evidence = { question, seats: proposals.map((p) => ({ seat: p.seat, model_id: p.model_id, response: p.response })), synthesis: run.synthesis };
  const v = verifyMoA(run.attestation, evidence, { trustedSigners, expectedRoster, expectedNonce: 'moa-1' });
  ok(v.verified === true && v.assurance === 'signed-claim', 'attested MoA run verifies as signed-claim');

  // 5. tamper a proposer's response -> verification fails (the receipt is bound to exact outputs)
  const tampered = { ...evidence, seats: evidence.seats.map((s, i) => i === 3 ? { ...s, response: 'FAKED' } : s) };
  ok(verifyMoA(run.attestation, tampered, { trustedSigners, expectedRoster }).seatsOk === false, 'tampered proposer output -> seatsOk false');

  // 6. add an independent witness -> witnessed-record
  addMoAWitness(run.attestation, w1);
  ok(verifyMoA(run.attestation, evidence, { trustedSigners, trustedWitnesses: [bytesToHex(w1.publicKey)], minWitnesses: 1, expectedRoster }).assurance === 'witnessed-record', 'witness co-sign -> witnessed-record');

  // 7. untrusted signer -> not verified
  ok(verifyMoA(run.attestation, evidence, { trustedSigners: [], expectedRoster }).verified === false, 'untrusted signer -> NOT verified');

  console.log('pqmoa self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqmoa\.mjs$/.test(process.argv[1] || '')) selfTest();
