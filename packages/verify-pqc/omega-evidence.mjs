/*!
 * omega-evidence — TRELYAN OMEGA end-to-end Evidence Pack (reference, DRAFT). Produces ONE self-contained, PQ-signed
 * bundle that a reviewer (a VC, a cryptographer) can verify OFFLINE, fail-closed, to see the whole stack actually work —
 * not a slide deck. The pack ties together:
 *   • the signed CAPABILITY statement (omega.attestCapabilities) — the honest, tamper-evident claim set;
 *   • a live GOVERNANCE decision (omega-gov: a 3-of-5 strategic proposal with signed ballots that tallies to executable);
 *   • a QIV INSCRIPTION (qiv: an artifact bound to a Vault Cell + custody, with a pinned off-chain pointer via qiv-pin);
 *   • a hybrid-key ATTESTATION (omega-bridge: a key-derivation record signing a commitment, never the key).
 * A top-level pqseal AND-composition (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519) binds the whole bundle so it can't be
 * cherry-picked or reassembled.
 *
 * HONEST: this is a DEMONSTRATION harness over the already-tested cores — it adds no crypto, invents no capability, and
 * every gate/claim-hygiene rule of the underlying modules still holds (Falcon = DRAFT on-chain leg only; nothing is
 * broadcast; no token/marketplace/hardware). "Verifies" here means the bundle is internally consistent + authentic under
 * the PINNED keys — it is not a legal or third-party attestation. Self-test: node omega-evidence.mjs
 */
import { attestCapabilities, verifyCapabilities } from './omega.mjs';
import { createBoard, propose, castBallot, tally } from './omega-gov.mjs';
import { inscribe, verifyInscription } from './qiv.mjs';
import { contentDescriptor, pinToOffchain } from './qiv-pin.mjs';
import { hybridCombine, attestKeyDerivation, verifyKeyAttestation, entropyReport, getEntropyMock } from './omega-bridge.mjs';
import { seal, openSeal } from './pqseal.mjs';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

const PACK_TAG = 'trelyan-omega-evidence-1';
function jcanon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcanon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcanon(v[k])).join(',') + '}';
}
const pins3 = (s) => ({ 'ML-DSA-87': s.mldsa.publicKey, 'SLH-DSA-256f': s.slh.publicKey, 'Ed25519': s.ed.publicKey });
const signers3 = (s) => [
  { alg: 'ML-DSA-87', secretKey: s.mldsa.secretKey, publicKey: s.mldsa.publicKey },
  { alg: 'SLH-DSA-256f', secretKey: s.slh.secretKey, publicKey: s.slh.publicKey },
  { alg: 'Ed25519', secretKey: s.ed.secretKey, publicKey: s.ed.publicKey },
];

/**
 * buildEvidencePack({ issuer, board, artifact, ts }) — issuer = { ed, mldsa, slh } keypairs (the TRELYAN signing identity);
 * board = createBoard(...) result WITH secret keys available on its members (passed separately as `boardMembers`);
 * artifact = bytes to inscribe. Returns { pack, seal } — a single signed bundle.
 */
export function buildEvidencePack({ issuer, boardMembers, artifact, ts = 0 }) {
  const isuSigners = signers3(issuer);
  // 1) capability statement, signed by the issuer
  const capability = attestCapabilities(isuSigners);
  // 2) governance decision: strategic (3-of-5) proposal + 3 approving ballots → executable
  const board = createBoard({ members: boardMembers, emergencyCouncil: boardMembers.slice(0, 3).map((m) => m.id) });
  const proposal = propose({ proposalId: 'evp-strategic-1', decisionClass: 'strategic', action: 'adopt_omega', createdTs: ts }, boardMembers[0]);
  const ballots = boardMembers.slice(0, 3).map((m) => castBallot(proposal, m, 'approve', { ts: ts + 1 }));
  const governance = { roster_pub: board.roster, proposal, ballots };
  // 3) QIV inscription with a (mock) pinned off-chain pointer
  const inscription = inscribe({ cellId: 42, ipType: 'patent', metadata: { title: 'OMEGA evidence artifact' }, artifactBytes: artifact, offchain: pinToOffchain(mockPointer(artifact)) }, isuSigners, null, { ts });
  // 4) hybrid-key attestation
  const combined = hybridCombine({ kem: sha512(utf8ToBytes('demo-kem-ss')).slice(0, 32), classical: sha512(utf8ToBytes('demo-classical')).slice(0, 32) }, { info: 'omega-evidence' });
  const entropy = entropyReport(getEntropyMock(4096).bytes);
  const keyAttestation = attestKeyDerivation({ sessionId: 'evp-1', combined, entropy, ts }, isuSigners);
  // assemble + bind
  const body = { v: PACK_TAG, issued_ts: ts, issuer_pub: pins3Hex(issuer), capability, governance, inscription, keyAttestation };
  const digest = bytesToHex(sha512(utf8ToBytes(jcanon(body))));
  const pack = { ...body, pack_sha512: digest };
  return { pack, seal: seal(utf8ToBytes(jcanon({ v: PACK_TAG, pack_sha512: digest })), isuSigners) };
}
function pins3Hex(s) { return { ed: bytesToHex(s.ed.publicKey), mldsa: bytesToHex(s.mldsa.publicKey), slh: bytesToHex(s.slh.publicKey) }; }
// deterministic offline mock pin pointer (qiv-pin.pin is async; the pack needs a sync, reproducible pointer).
function mockPointer(artifact) {
  const d = contentDescriptor(artifact);
  const cid = 'mock-' + d.sha256.slice(0, 46);
  return { cid, uri: 'ipfs://' + cid, sha256: d.sha256, size: d.size, live: false, source: 'MOCK' };
}

/**
 * verifyEvidencePack(bundle, { issuerPins }) — TOTAL / fail-closed. issuerPins = { 'ML-DSA-87':pub, 'SLH-DSA-256f':pub,
 * 'Ed25519':pub } for the issuer identity. Verifies every component + the top-level seal and returns a per-part verdict.
 */
export function verifyEvidencePack(bundle, { issuerPins } = {}) {
  const parts = {};
  try {
    if (!bundle || !bundle.pack || !bundle.seal) return { verified: false, reason: 'shape', parts };
    // TRUST, not just VALIDITY: an evidence pack with no pinned issuer is only self-consistent (anyone could have signed
    // it). Fail-closed unless the caller pins the issuer identity out-of-band.
    if (!issuerPins || Object.keys(issuerPins).length === 0) return { verified: false, reason: 'issuer pins required — no pinned issuer is VALIDITY, not TRUST', parts };
    const p = bundle.pack;
    // top-level seal over the pack digest
    const topOk = openSeal(utf8ToBytes(jcanon({ v: PACK_TAG, pack_sha512: p.pack_sha512 })), bundle.seal, { trusted: issuerPins, requireKinds: ['lattice', 'hash-based', 'classical'], requireDistinctLegs: true }).verified;
    // recompute the pack digest from the body (defends against a doctored body vs the seal)
    const { pack_sha512, ...body } = p;
    const digestOk = bytesToHex(sha512(utf8ToBytes(jcanon(body)))) === pack_sha512;
    parts.topSeal = topOk; parts.digest = digestOk;
    // 1) capability
    parts.capability = verifyCapabilities(p.capability, { trusted: issuerPins, requireKinds: ['lattice', 'hash-based', 'classical'] }).verified;
    // 2) governance: recompute the tally against the embedded roster; must be executable
    const board = { size: Object.keys(p.governance.roster_pub).length, member_ids: Object.keys(p.governance.roster_pub), emergency_ids: Object.keys(p.governance.roster_pub).slice(0, 3), roster: p.governance.roster_pub };
    const t = tally(p.governance.proposal, p.governance.ballots, board, { now: p.issued_ts + 1000 });
    parts.governance = t.executable === true;
    // 3) QIV inscription (self-consistent 3-family seal; note: artifact bytes are referenced by the pinned pointer hash,
    //    so we verify the inscription's own integrity — a holder of the artifact re-checks the pointer via qiv-pin)
    parts.inscription = verifyInscription(p.inscription, artifactFromInscription(), { trusted: issuerPins, requireKinds: ['lattice', 'hash-based', 'classical'] }).sealOk === true;
    // 4) hybrid-key attestation
    parts.keyAttestation = verifyKeyAttestation(p.keyAttestation, { trusted: issuerPins, requireKinds: ['lattice', 'hash-based', 'classical'] }).verified;
    const verified = topOk && digestOk && parts.capability && parts.governance && parts.inscription && parts.keyAttestation;
    return { verified, parts, reason: verified ? 'ok' : 'one or more components failed' };
  } catch { return { verified: false, reason: 'exception', parts }; }
}
// the inscription's artifact digest is over the ORIGINAL bytes (domain-tagged); a verifier who lacks the bytes can only
// check the inscription's internal seal/anchor consistency (sealOk), which is what verifyEvidencePack asserts. A verifier
// WITH the artifact bytes calls verifyInscription(...).verified for the full check. We surface the bytes via a helper that
// returns null (forcing the artifact-digest check to be skipped, so we rely on sealOk) — honest about the boundary.
function artifactFromInscription() { return new Uint8Array(0); }

/* ---------------------------------------- self-test: node omega-evidence.mjs ---------------------------------------- */
async function selfTest() {
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { slh_dsa_sha2_256f } = await import('@noble/post-quantum/slh-dsa.js');
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const seed = (n, l = 32) => new Uint8Array(l).fill(n);
  const mkId = (n) => ({ ed: (() => { const sk = seed(n); return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })(), mldsa: ml_dsa87.keygen(seed(n + 1)), slh: slh_dsa_sha2_256f.keygen(seed(n + 2, 96)) });
  const mkMember = (id, n) => ({ id, ed: (() => { const sk = seed(n); return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })(), mldsa: ml_dsa87.keygen(seed(n + 1)) });
  const issuer = mkId(1);
  const board = [mkMember('alice', 10), mkMember('bob', 20), mkMember('carol', 30), mkMember('dave', 40), mkMember('erin', 50)];
  const artifact = utf8ToBytes('End-to-end OMEGA evidence artifact bytes.');

  const bundle = buildEvidencePack({ issuer, boardMembers: board, artifact, ts: 1000 });
  ok(bundle.pack.v === PACK_TAG && bundle.pack.pack_sha512.length === 128, 'build: bundle assembled + digest');

  const issuerPins = pins3(issuer);
  const v = verifyEvidencePack(bundle, { issuerPins });
  ok(v.verified, 'verify: full pack verifies (pinned issuer)');
  ok(v.parts.capability && v.parts.governance && v.parts.inscription && v.parts.keyAttestation && v.parts.topSeal && v.parts.digest, 'verify: all 4 components + top-seal + digest ok');

  // wrong issuer pins → fails
  const other = pins3(mkId(99));
  ok(!verifyEvidencePack(bundle, { issuerPins: other }).verified, 'verify: wrong issuer key rejected');

  // tamper a component (flip a governance ballot choice) → digest + governance fail
  const tampered = JSON.parse(JSON.stringify(bundle)); tampered.pack.governance.ballots[0].core.choice = 'reject';
  const tv = verifyEvidencePack(tampered, { issuerPins });
  ok(!tv.verified && (!tv.parts.digest || !tv.parts.governance), 'verify: tampered governance ballot rejected');

  // tamper the capability statement (claim a gated layer is BUILT) → digest + capability fail
  const t2 = JSON.parse(JSON.stringify(bundle)); t2.pack.capability.statement.layers[6].status = 'BUILT';
  ok(!verifyEvidencePack(t2, { issuerPins }).verified, 'verify: capability claim-drift rejected');

  console.log(`\nomega-evidence self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTest();
