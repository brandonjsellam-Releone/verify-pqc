/*!
 * pqassistant — QDS-Ω verifiable AI answer assistant (reference, DRAFT, standalone). "Comet, but provable."
 *
 * The super-advanced in-search-engine chatbot, the apex (honest) way: it does NOT just emit a fluent answer —
 * it composes the whole TRELYAN spine into a VERIFIABLE one:
 *   retrieve (verifiable index, pqindex) -> propose (Mixture-of-Agents, pqmoa) -> claim-gate (pqclaimgate +
 *   pqverify: grounding + cross-seat consensus + adversarial refutation) -> emit ONLY verified claims, abstain
 *   the rest -> ATTEST the answer (which sources, which models, which claims; ML-DSA-signed via pqclaimgate).
 *
 * Why this beats Comet/Perplexity: every emitted claim is grounded in an index result that itself can't be
 * forged (pqindex inclusion proof), agreed by multiple models, survives refutation, and ships a post-quantum
 * provenance receipt. Unverifiable claims are flagged, not asserted -> ~zero UNFLAGGED hallucination.
 *
 * HONEST LIMITS: orchestration reference. retrieve/callSeat/callRefuter are pluggable (production wires the
 * live verifiable index + the 11 council seats via the bridge). `verified` = passed gates, not "true";
 * attestation proves WHAT ran, not correctness. Self-test: node pqassistant.mjs
 */
import { aggregate } from './pqmoa.mjs';
import { ClaimGate, attestClaimGate, verifyClaimGate, stubConsensusGate } from './pqclaimgate.mjs';
import { citationSupport, makeRefutation } from './pqverify.mjs';

// answer(): the full verifiable-assistant pipeline.
//  query        : user question (string)
//  retrieve(q)  : async -> [{ id, snippet, score? }]  (verifiable index results; production = pqindex)
//  seats        : [{ seat, model_id }]
//  callSeat(s,q,sources) : async -> { claims: [string], response: string }  (each seat's atomic claims)
//  callRefuter(claim,refs,i): async -> { refuted, grounded }  (cross-model adversarial)
//  order        : { secretKey, publicKey } ML-DSA-87 for the attestation
export async function answer({ query, retrieve, seats, callSeat, callRefuter, order, policy }, opts = {}) {
  // 1. retrieve verifiable sources -> evidence refs
  const sources = await retrieve(query);
  const evidence_refs = sources.map((s) => ({ ref: s.id, selector: s.snippet, grounded: true, ef_score: s.score ?? 0.9 }));

  // 2. proposers (Mixture-of-Agents): each seat emits atomic claims + a response
  const proposals = [];
  for (const seat of seats) { const r = await callSeat(seat, query, sources); proposals.push({ seat: seat.seat, model_id: seat.model_id, response: r.response, claims: r.claims || [] }); }
  const moa = aggregate({ proposals: proposals.map((p) => ({ ...p, answer: p.response })) }); // consensus/dissent over responses (for the record)

  // 3. build per-claim records: consensus = fraction of seats asserting the claim; grounded in the retrieved sources
  const total = seats.length || 1;
  const byClaim = new Map();
  for (const p of proposals) for (const c of p.claims) { const k = c.trim(); (byClaim.get(k) || byClaim.set(k, new Set()).get(k)).add(p.seat); }
  let i = 0;
  const claims = [...byClaim.entries()].map(([text, seatSet]) => ({
    id: 'c' + (i++), claim: text, evidence_refs,
    consensus: { strength: seatSet.size / total, total_considered: total, dissent: { count: total - seatSet.size } },
  }));

  // 4. gate: grounding (citationSupport) + cross-seat consensus + adversarial refutation
  const gate = new ClaimGate({ verifiers: [citationSupport, stubConsensusGate, makeRefutation(callRefuter)], policy });
  const evaluated = await gate.evaluateAll(claims);
  const env = gate.assemble(query, evaluated);

  // 5. AUGMENT first, THEN attest (3rd code-security sweep): env.sources + env.moa must be INSIDE the signed manifest,
  // else a MITM/runner swaps citations or rewrites dissent under a "PQ-verified" stamp — forge-proof provenance is the point.
  env.sources = sources;
  env.moa = { consensus_strength: moa.consensus_strength, dissent: moa.dissent };
  attestClaimGate(env, order, opts);
  return env; // env.emitted.rendered = the answer; env.emitted.verified_claims / abstained / rejected; env.attestation (verifyClaimGate)
}

/* ---------- self-test: node pqassistant.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  return import('@noble/post-quantum/ml-dsa.js').then(async ({ ml_dsa87 }) => {
    const order = ml_dsa87.keygen(new Uint8Array(32).fill(71));
    const TRUE_CLAIM = 'ML-KEM is a NIST standardized post quantum key encapsulation mechanism';
    const HALLUCINATION = 'ML-KEM was secretly invented in the year 1990 by aliens';

    // verifiable index returns a source whose snippet supports the TRUE claim only
    const retrieve = async () => [
      { id: 'idx://fips203#1', snippet: 'ML-KEM is a NIST standardized post quantum key encapsulation mechanism defined in FIPS 203', score: 0.95 },
      { id: 'idx://overview#2', snippet: 'lattice based key encapsulation mechanism standardized by NIST', score: 0.8 },
    ];
    const seats = [{ seat: 'deepseek', model_id: 'ds' }, { seat: 'openai', model_id: 'oa' }, { seat: 'gemini', model_id: 'gm' }];
    // all 3 seats assert the true claim; 2 also hallucinate
    const callSeat = async (s) => s.seat === 'gemini'
      ? { response: TRUE_CLAIM, claims: [TRUE_CLAIM] }
      : { response: TRUE_CLAIM + ' ' + HALLUCINATION, claims: [TRUE_CLAIM, HALLUCINATION] };
    // refuter knocks down the hallucination with grounded counter-evidence
    const callRefuter = async (claim) => ({ refuted: /invented in the year 1990|aliens/i.test(claim.claim), grounded: true });

    const res = await answer({ query: 'what is ML-KEM?', retrieve, seats, callSeat, callRefuter, order }, { ts: 1000 });

    ok(res.emitted.verified_claims.length === 1 && res.emitted.verified_claims[0].claim === TRUE_CLAIM, 'only the grounded, agreed, refutation-surviving claim is VERIFIED');
    ok(!res.emitted.rendered.includes('1990') && !res.emitted.rendered.includes('aliens'), 'the hallucination is NOT in the emitted answer');
    ok(res.rejected.some((c) => c.claim === HALLUCINATION) || res.abstained.some((c) => c.claim === HALLUCINATION), 'the hallucination is flagged (rejected/abstained), not asserted');
    ok(res.sources.length === 2 && res.coverage < 1, 'answer cites its verifiable sources + reports honest coverage (<1, since a claim was dropped)');
    ok(verifyClaimGate(res, order.publicKey).verified === true, 'the answer carries a verifiable PQ attestation (which claims, under which policy)');
    ok(verifyClaimGate(res, ml_dsa87.keygen(new Uint8Array(32).fill(99)).publicKey).verified === false, 'attestation fails under a non-order key');

    console.log('pqassistant self-test: ' + pass + ' pass, ' + fail + ' fail');
    if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
  });
}
if (typeof process !== 'undefined' && process.argv && /pqassistant\.mjs$/.test(process.argv[1] || '')) selfTest();
