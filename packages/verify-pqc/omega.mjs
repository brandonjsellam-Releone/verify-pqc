/*!
 * omega — TRELYAN OMEGA (QTOS) integration manifest + capability registry (reference, DRAFT). OMEGA is NOT a new
 * monolith: it is a 7-layer architecture whose substance is the ALREADY-SHIPPED verify-pqc modules, composed under one
 * honest status map. This file is the SINGLE SOURCE OF TRUTH for what each layer actually is (BUILT / REFERENCE / MOCK /
 * STUB / GATED), which real modules back it, what is deliberately GATED (securities / token / hardware / on-chain deploy /
 * autonomous action), and which blueprint phrases are overclaims to avoid. A pitch or datasheet should be generated FROM
 * this manifest so no layer is described beyond what the code does.
 *
 * HONEST FRAMING (for a cryptographer reviewer): OMEGA's defensible core is a post-quantum TRUST + PROVENANCE layer —
 * AND-composition signing (pqseal), tamper-evident logs + anchoring (pqauditlog/pqanchor/pqtsa), an IP vault (qiv),
 * M-of-N governance (omega-gov), hybrid-key derivation + entropy estimation (omega-bridge), and hybrid-PQ messaging
 * (pqx3dh/pqratchet/pqtransport). It does NOT include quantum hardware (QKD/QRNG), autonomous key rotation, a token, a
 * marketplace, or any legal/regulatory guarantee — those are MOCK/STUB/GATED and labelled as such. Nothing here is
 * "quantum-proof", "unbreakable", "post-catastrophe", or "legally admissible". Self-test: node omega.mjs
 */
import * as qiv from './qiv.mjs';
import * as omegaGov from './omega-gov.mjs';
import * as omegaBridge from './omega-bridge.mjs';
import { seal, openSeal } from './pqseal.mjs';
import { utf8ToBytes } from '@noble/hashes/utils.js';

export const OMEGA_VERSION = '0.1.0-draft';

// status vocabulary (honest capability level):
//  BUILT      — a tested reference core exists in this SDK for the core function
//  REFERENCE  — buildable/built as an unaudited JS reference; the on-chain/hardware productionization is gated
//  MOCK       — a clearly-labelled placeholder (e.g. CSPRNG standing in for QRNG); NO real capability claimed
//  STUB       — interface/spec only; the feature is not implemented
//  GATED      — deliberately NOT built pending owner/legal/hardware/securities action
export const OMEGA_LAYERS = {
  L1: {
    name: 'OMEGA FOUNDATION — Swiss governance', status: 'REFERENCE',
    backing: ['omega-gov.mjs', 'pqauditlog.mjs', 'pqseal.mjs', 'pqcap.mjs'],
    summary: 'M-of-N PQ-signed threshold governance: proposals, per-member AND-composed ballots (ML-DSA-87 ∧ Ed25519[∧SLH]), class thresholds (2/3/4-of-5), lifecycle, time-lock, 2-of-3 emergency pause, key-rotation authorization — offline-verifiable, fail-closed.',
    gated: ['PyTeal constitutional contract DEPLOY to Algorand (funded account — owner)', 'on-chain constitution-hash pinning', 'token-holder / quadratic voting (token = securities)', 'treasury-token integration', 'real-time on-chain enforcement'],
    hazards: ['NOT "quantum-proof governance" — PQ-signed, breaks if signing keys are compromised', 'NOT "legally admissible" — a Stiftung\'s authority is its statutes + board + counsel, not this code', 'NOT FIPS-validated — @noble is unaudited reference'],
  },
  L2: {
    name: 'OMEGA CHAIN — PQ blockchain binding', status: 'REFERENCE',
    backing: ['omega-chain.mjs', 'pqanchor.mjs', 'pqauditlog.mjs', 'pqtsa.mjs', 'pqkt.mjs', 'index.js'],
    summary: 'omega-chain batches OMEGA events (governance/vault/capability) into a PQ-signed log and binds the batch to an Algorand anchor, producing the EXACT note/calldata bytes to post + the offline proof they bind. Falcon-1024 on-chain verify via the AVM falcon_verify opcode (live TestNet app 763809096).',
    gated: ['on-chain broadcast (funded account + deployed app — owner)', 'cross-chain bridges ETH/SOL/BTC/DOT (stubs)', 'ZK-rollup (design only)', 'oracles Chainlink/Pyth (stubs)'],
    hazards: ['Falcon-1024 / FIPS 206 = DRAFT — caveat every mention', 'Algorand account layer is still Ed25519 (classically) at the wallet level', 'anchoring proves BINDING, not chain honesty/availability or "immutability"'],
  },
  L3: {
    name: 'OMEGA VAULT — post-quantum IP registry (QIV)', status: 'BUILT',
    backing: ['qiv.mjs', 'pqseal.mjs', 'pqtsa.mjs', 'pqanchor.mjs'],
    summary: 'Quantum IP Vault: hash an IP artifact → 3-family AND-composed signature → Vault Cell (1..1024, sealed→inscribed→released) → PQ timestamp → deterministic Algorand note bytes (not broadcast) + hash-chained signed chain of custody. 21/21 self-tests.',
    gated: ['marketplace() (securities: fractional/tokenized IP)', 'on-chain broadcast (funded account + Falcon signer)', 'off-chain pinning (IPFS/Arweave/Pinata)', 'multi-sig high-value transfer', 'WIPO/registry integration', 'ML valuation'],
    hazards: ['NOT "legally admissible" — SUPPORTS IP evidence; admissibility = court + counsel', 'inscription ≠ patent filing / does not confer any IP right', 'NOT "world\'s first" — blockchain IP-timestamping exists; the distinct claim is the PQ composition', 'Falcon = DRAFT on-chain leg only'],
  },
  L4: {
    name: 'OMEGA BRIDGE — hybrid crypto + entropy (QKD interface MOCK)', status: 'REFERENCE',
    backing: ['omega-bridge.mjs', 'pqgateway.mjs', 'pqgateway-session.mjs', 'pqtransport.mjs', 'pqseal.mjs'],
    summary: 'Real SP 800-90B §6.3.1 MCV min-entropy ESTIMATOR + accept gate; hybrid-key HKDF combiner (QKD-slot ∥ ML-KEM ∥ classical, OR-secure, domain-separated); PQ-signed key-derivation attestation. Hybrid-PQ SIGMA handshake + downgrade-safe negotiation + transcript-bound session attestation (pqgateway/pqtransport).',
    gated: ['QKD hardware (ETSI QKD 014/15/16 — certified integration, owner)', 'true m-of-n secret-sharing / BLS-MPC key escrow (thresholdSecretShare — gated)', 'HSM key storage', 'satellite QKD'],
    hazards: ['MCV is ONE IID estimator + a lower bound — NOT the full 90B battery or a certification', 'hybridCombine is OR-secure KDF composition — NOT threshold reconstruction', 'qkdSessionMock / getEntropyMock are OS CSPRNG — NEVER "quantum" or "QKD-integrated"', 'attestation = participant-verifiable non-repudiation, NOT an access grant'],
  },
  L5: {
    name: 'OMEGA FOUNTAIN — quantum randomness', status: 'MOCK',
    backing: ['omega-bridge.mjs (getEntropyMock)'],
    summary: 'Entropy source ABSTRACTION. MVP source is OS CSPRNG (crypto.getRandomValues), labelled MOCK_CSPRNG, so a certified QRNG/QKD source can be swapped behind the same interface later.',
    gated: ['certified QRNG/QKD hardware (owner)', 'on-chain randomness contract deploy', '"entropy mining" token rewards (securities/token)', 'any quantum-advantage or FIPS-140-3 claim on the mock'],
    hazards: ['NEVER "true quantum randomness / quantum-secure randomness" — MVP is a standard CSPRNG', 'NOT "world\'s first QRNG network" — ID Quantique / IQE etc. ship real hardware'],
  },
  L6: {
    name: 'OMEGA NEXUS — secure communication', status: 'REFERENCE',
    backing: ['omega-nexus.mjs', 'pqx3dh.mjs', 'pqratchet.mjs', 'pqratchet-he.mjs', 'pqtransport.mjs', 'pqvault.mjs', 'pqindex.mjs'],
    summary: 'omega-nexus establishes a 1:1 async PQ session between two PINNED OMEGA identities (PQXDH prekey bundle → PQ triple ratchet) and exchanges verified messages. Also: mutual-auth hybrid transport, long-term confidentiality vault, encrypted search. Video/onion/group are NOT built.',
    gated: ['"Quantum Voice" one-time-pad (not a Vernam cipher — do not claim OTP)', 'onion routing / Tor-grade anonymity (out of scope)', 'group messaging (no MLS ratchet yet)', 'file/video streaming encryption (no media module)'],
    hazards: ['NOT "impossible to decrypt retroactively" — forward secrecy holds under HNDL + endpoint integrity; endpoint compromise breaks it', 'the ratchet is hybrid DH+KEM, NOT a one-time pad', 'no Tor/onion layer exists — do not claim metadata anonymity beyond sealed-sender headers'],
  },
  L7: {
    name: 'OMEGA SENTIENCE — AI threat intelligence', status: 'GATED',
    backing: ['omega-sentinel.mjs', 'pqmonitor.mjs', 'pqshield.mjs', 'pqkt.mjs'],
    summary: 'omega-sentinel: human-in-the-loop ONLY — a tamper-evident PQ-signed posture ledger, reactive regression detection (new RED assets / risk delta), an ALERT that AWAITS explicit human approval (authorizeResponse), and a machine-gated autonomous path. Reactive/falsifiable signals, not predictions. The "AI agent" is a stub, not a deployed LLM.',
    gated: ['autonomous key rotation on an AI signal alone (autonomousKeyRotation — gated)', 'deployed LLM agents wired to production key material', 'any AI-triggered irreversible crypto action (key destruction / revocation)', 'federated learning over production estates (data egress)', 'published predictive confidence scores as SLA'],
    hazards: ['NOT "autonomous AI that auto-rotates keys" — human approval is mandatory', 'NO fabricated predictions like "73.4% RSA break" — track FALSIFIABLE operational signals (migration backlog) instead', 'the threat SIGNALS are classical; only the LOGGING is PQ-signed — not "quantum-safe threat prediction"'], // pqcbom-ignore: claim-hygiene / migration prose
  },
};

/** capabilityMatrix() — compact [{layer, name, status, backing, gatedCount, hazardCount}] for a datasheet/table. */
export function capabilityMatrix() {
  return Object.entries(OMEGA_LAYERS).map(([id, L]) => ({ layer: id, name: L.name, status: L.status, backing: L.backing, gated: L.gated.length, hazards: L.hazards.length }));
}
/** gatedFeatures() — the full register of everything deliberately NOT built (securities/token/hardware/deploy/autonomous). */
export function gatedFeatures() {
  const out = []; for (const [id, L] of Object.entries(OMEGA_LAYERS)) for (const g of L.gated) out.push({ layer: id, feature: g });
  return out;
}
/** claimHazards() — the full register of blueprint phrases to avoid, per layer. */
export function claimHazards() {
  const out = []; for (const [id, L] of Object.entries(OMEGA_LAYERS)) for (const h of L.hazards) out.push({ layer: id, avoid: h });
  return out;
}
/** layer(id) — the honest record for one layer (throws on unknown id). */
export function layer(id) { const L = OMEGA_LAYERS[id]; if (!L) throw new Error('omega: unknown layer ' + id); return L; }

/* ---------- Layer 7 human-in-the-loop gate (machine-enforced) ---------- */
/** reviewThreatSignal(posture) — REACTIVE, human-in-the-loop. Given a posture summary { redAssets, riskDelta }, returns an
 *  ALERT with a recommended action but NEVER acts. `requiresHumanApproval` is always true for any state-changing action. */
export function reviewThreatSignal(posture = {}) {
  const red = Number(posture.redAssets) || 0;
  const delta = Number(posture.riskDelta) || 0;
  const severity = red >= 5 || delta >= 0.5 ? 'high' : (red > 0 || delta > 0 ? 'elevated' : 'nominal');
  return {
    severity, redAssets: red, riskDelta: delta,
    recommendation: severity === 'nominal' ? 'no action' : 'operator review recommended (e.g. schedule key rotation for regressed assets)',
    requiresHumanApproval: true,   // ALWAYS — no autonomous action
    note: 'Reactive operational signal (posture regression), not a prediction. Any rotation must be approved + executed by a human via an authenticated channel.',
  };
}
/** autonomousKeyRotation() — GATED. The blueprint's "auto-rotate keys WITHOUT human intervention on an AI threat signal"
 *  is an irreversible action driven by a heuristic; machine-enforced OFF. Always throws. */
export function autonomousKeyRotation() {
  throw new Error('OMEGA_AUTONOMOUS_ACTION_GATED: autonomous (no-human) key rotation on an AI/threat signal is disabled by design. Use reviewThreatSignal() to alert an operator; rotation requires explicit human approval + execution.');
}

/* ---------- Capability attestation: TRELYAN's product PQ-signs its own capability claims (eat-your-own-dogfood) ----------
 * The honest claim set (status per layer + gate register + hazard register) is itself made TAMPER-EVIDENT + ATTRIBUTABLE
 * by a pqseal AND-composition (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519). A reviewer (VC / cryptographer) verifies the
 * capability statement is exactly what TRELYAN signed and hasn't drifted — no more "trust the slide deck". This canonical
 * statement is what a datasheet/pitch should be generated FROM. It contains ONLY the honest manifest — no marketing.
 */
function jcanon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcanon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcanon(v[k])).join(',') + '}';
}
/** capabilityStatement() — the canonical, signable claim object (deterministic). */
export function capabilityStatement() {
  return {
    v: 'omega-capability-1', omega_version: OMEGA_VERSION,
    layers: capabilityMatrix(), gates: gatedFeatures(), hazards: claimHazards(),
    note: 'Honest capability manifest. Statuses: BUILT/REFERENCE/MOCK/STUB/GATED. No affirmative overclaims; every gate is machine-enforced; Falcon-1024 = DRAFT FIPS 206. Generate any datasheet FROM this object.',
  };
}
/** attestCapabilities(signers) — PQ-sign the capability statement. signers = pqseal signer set (recommend 3-family). */
export function attestCapabilities(signers) {
  const statement = capabilityStatement();
  return { statement, seal: seal(utf8ToBytes(jcanon(statement)), signers) };
}
/** verifyCapabilities(att, opts) — TOTAL / fail-closed. Recomputes the statement bytes + verifies the seal (pinned). */
export function verifyCapabilities(att, opts = {}) {
  try {
    if (!att || !att.statement || !att.seal) return { verified: false, reason: 'shape' };
    const sv = openSeal(utf8ToBytes(jcanon(att.statement)), att.seal, { trusted: opts.trusted, requireKinds: opts.requireKinds, requireDistinctLegs: true });
    return { verified: sv.verified, kinds: sv.kinds, suite: att.seal.suite, reason: sv.verified ? 'ok' : 'seal invalid (statement tampered or wrong signer)' };
  } catch { return { verified: false, reason: 'exception' }; }
}

/** omegaSelfCheck() — composition sanity: sub-cores load and their securities/hardware/autonomy GATES actually throw. */
export function omegaSelfCheck() {
  const checks = [];
  const gate = (label, fn) => { let threw = false; try { fn(); } catch { threw = true; } checks.push({ gate: label, enforced: threw }); };
  gate('L3 marketplace (securities)', () => qiv.marketplace());
  gate('L1 token-holder vote (securities)', () => omegaGov.tokenHolderVote());
  gate('L4 threshold-MPC (gated)', () => omegaBridge.thresholdSecretShare());
  gate('L7 autonomous key rotation (gated)', () => autonomousKeyRotation());
  const allEnforced = checks.every((c) => c.enforced);
  return { version: OMEGA_VERSION, layers: Object.keys(OMEGA_LAYERS).length, gatesEnforced: allEnforced, checks };
}

/* ---------------------------------------- self-test: node omega.mjs ---------------------------------------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  ok(Object.keys(OMEGA_LAYERS).length === 7, 'manifest: 7 layers');
  ok(capabilityMatrix().length === 7, 'capabilityMatrix: 7 rows');
  ok(OMEGA_LAYERS.L3.status === 'BUILT', 'L3 vault = BUILT');
  ok(OMEGA_LAYERS.L5.status === 'MOCK' && OMEGA_LAYERS.L7.status === 'GATED', 'L5=MOCK, L7=GATED');
  // every layer carries at least one gate + one hazard (honesty invariants)
  ok(Object.values(OMEGA_LAYERS).every((L) => L.gated.length >= 1 && L.hazards.length >= 1 && L.backing.length >= 1), 'every layer: >=1 backing, gate, hazard');
  ok(gatedFeatures().length >= 20 && claimHazards().length >= 14, 'registers: gates + hazards populated');
  // no forbidden affirmative claim leaks into the AFFIRMATIVE fields (name + summary — what a datasheet quotes as a claim).
  // The `hazards` fields intentionally quote these phrases to FORBID them, so they are excluded from this scan.
  const affirmative = Object.values(OMEGA_LAYERS).map((L) => (L.name + ' ' + L.summary)).join(' ').toLowerCase();
  const forbidden = ['quantum-proof', 'quantum proof', 'unbreakable', 'post-catastrophe', 'impossible to decrypt', 'legally admissible', 'true quantum random', 'quantum-safe'];
  ok(forbidden.every((f) => !affirmative.includes(f)), 'manifest summaries carry no forbidden affirmative claim');
  // L7 human-in-the-loop always requires approval; nominal vs high severity
  ok(reviewThreatSignal({ redAssets: 0, riskDelta: 0 }).severity === 'nominal', 'L7: nominal posture');
  ok(reviewThreatSignal({ redAssets: 6 }).severity === 'high' && reviewThreatSignal({ redAssets: 6 }).requiresHumanApproval, 'L7: high severity still requires human approval');
  // all gates enforced
  const sc = omegaSelfCheck();
  ok(sc.gatesEnforced && sc.checks.length === 4, 'omegaSelfCheck: all 4 securities/hardware/autonomy gates throw');
  console.log('  gates:', sc.checks.map((c) => `${c.gate}=${c.enforced ? 'ON' : 'OFF!'}`).join('  '));

  // capability attestation (product signs its own claim set)
  const st = capabilityStatement();
  ok(st.layers.length === 7 && st.gates.length >= 20 && st.hazards.length >= 14, 'capabilityStatement: full honest manifest');
  // deterministic (same statement bytes every call)
  ok(JSON.stringify(capabilityStatement()) === JSON.stringify(st), 'capabilityStatement: deterministic');
  // sign with a 3-family signer set + verify pinned
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { slh_dsa_sha2_256f } = await import('@noble/post-quantum/slh-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const s = (n, l = 32) => new Uint8Array(l).fill(n);
  const A = { alg: 'ML-DSA-87', ...ml_dsa87.keygen(s(1)) };
  const B = { alg: 'SLH-DSA-256f', ...slh_dsa_sha2_256f.keygen(s(2, 96)) };
  const C = (() => { const sk = s(3); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })();
  const trusted = { 'ML-DSA-87': A.publicKey, 'SLH-DSA-256f': B.publicKey, 'Ed25519': C.publicKey };
  const att = attestCapabilities([A, B, C]);
  ok(verifyCapabilities(att, { trusted, requireKinds: ['lattice', 'hash-based', 'classical'] }).verified, 'attestCapabilities: signs + verifies (pinned 3-family)');
  const drift = JSON.parse(JSON.stringify(att)); drift.statement.layers[6].status = 'BUILT'; // fake: claim L7 is BUILT
  ok(!verifyCapabilities(drift, { trusted }).verified, 'verifyCapabilities: claim-drift (tampered status) rejected');

  return { pass, fail };
}
async function selfTestWrap() {
  const r = await selfTest();
  console.log(`\nomega self-test: ${r.pass} passed, ${r.fail} failed`);
  if (r.fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTestWrap();
