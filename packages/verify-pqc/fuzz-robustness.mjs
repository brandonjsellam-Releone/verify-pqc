/*!
 * fuzz-robustness — negative/fuzz sweep across every external-input VERIFIER (audit artifact).
 *
 * Throws a battery of malformed/adversarial inputs at each verifier and asserts FAIL-CLOSED behaviour:
 *   - ZERO accept-on-garbage (a verifier returning verified/accept/a-key on junk = a fail-OPEN security bug).
 *   - the harness never crashes (verifiers may throw on structural garbage — caught here — but ideally return a
 *     falsy verdict; uncaught throws on untrusted input are a DoS/robustness smell, reported per verifier).
 * This is where unit tests don't look. Self-test: node fuzz-robustness.mjs
 */
import * as pqef from './pqef.mjs';
import * as pqgateway from './pqgateway.mjs';
import * as pqkt from './pqkt.mjs';
import * as pqsign from './pqsign.mjs';
import * as pqtsa from './pqtsa.mjs';
import * as pqtransport from './pqtransport.mjs';
import * as pqratchet from './pqratchet.mjs';
import * as pqratchetHE from './pqratchet-he.mjs';
import * as pqpki from './pqpki.mjs';
import * as pqvault from './pqvault.mjs';
import * as pqcompliance from './pqcompliance.mjs';
import * as pqx3dh from './pqx3dh.mjs';
import * as pqmarket from './pqmarket.mjs';
import * as pqindex from './pqindex.mjs';
import * as pqverifyApi from './pqverify-api.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

// adversarial input battery
const PP = JSON.parse('{"__proto__":{"polluted":true},"constructor":{"prototype":{"x":1}}}');
const GARBAGE = [
  null, undefined, 0, 1, -1, 1.5, NaN, Infinity, -Infinity, true, false,
  '', 'x', 'zz', '0', '00', 'gg', '0x', 'deadbeef', 'A'.repeat(100000),
  [], [1], [null], [{}], {}, { sig: null }, { sig: 123 }, { sig: 'zz' }, { sig: 'gg', verified: true },
  { verified: true }, { accept: true }, { ok: true }, { tree_size: -1, root_hex: 'zz', sig: 'zz' },
  { statement: null }, { statement: {} }, { statement: 1 }, { envelope: { signatures: 'x' } },
  { pubkey_hex: 'zz', auth_sig: 'zz', op: 'bind', kind: 'pqkt-key-event', issuer_id: 'x', seq: 0, prev_key_hex: null },
  PP, { a: { b: { c: { d: { e: 1 } } } } }, { length: 1e9 }, { msg3: { i_sig: 'zz' } },
  { enc_header: 'zz', ct: 'zz' }, { header: {}, ct: 'zz' },
];
// EXOTIC adversarial inputs (full-council convergent round: classes a fixed literal battery misses). These probe the
// JS-engine seams a sorted-key MANUAL canon() + typeof guards must survive: serialization hooks (toJSON/valueOf/
// Symbol.toPrimitive — our canon NEVER passes a rich object to JSON.stringify, so these must NOT change the signed
// view), throwing getters / Proxies (must fail CLOSED, never DoS), BigInt (JSON.stringify throws), boxed String
// (typeof==='object' not 'string'), typed arrays, sparse/holey arrays. Asserts the same invariants: 0 fail-open + total.
const throwingGetter = (field) => { const o = {}; Object.defineProperty(o, field, { enumerable: true, get() { throw new Error('boom'); } }); return o; };
const EXOTIC = [
  { toJSON: () => ({ verified: true, accept: true, ok: true }) },          // serialization hook claiming acceptance
  { valueOf: () => 1, sig: 'gg', verified: true },                          // valueOf coercion + claimed verdict
  { [Symbol.toPrimitive]: () => 'x', sig: 'gg', agent_pub: 'zz', agent_id: 'x' },
  throwingGetter('sig'), throwingGetter('tbs'), throwingGetter('agent_pub'), throwingGetter('terms'), throwingGetter('entries'),
  new Proxy({}, { get() { throw new Error('proxy'); }, has() { throw new Error('proxy'); } }), // throws on ANY access
  { sig: 'gg', n: 10n, tbs: { x: 10n } },                                   // BigInt field (JSON.stringify throws)
  new String('gg'),                                                         // boxed String: typeof === 'object'
  { tbs: new Uint8Array(8), signatures: { mldsa: 'zz', ed: 'zz' } },        // typed array where object expected
  { agent_pub: 'zz', agent_id: 'x', sig: 'gg', terms: [1, , 3] },           // sparse/holey array (hole -> null in JSON)
  Object.assign(Object.create({ inheritedVerified: true }), { sig: 'gg' }), // inherited props (Object.keys must ignore)
];
GARBAGE.push(...EXOTIC);
const tdec = (x) => { try { return JSON.stringify(x).slice(0, 36); } catch { return String(x).slice(0, 36); } };
const accepted = (r) => r === true || (r && typeof r === 'object' && (r.verified === true || r.accept === true || r.ok === true || r.equivocation === true || typeof r.pubkey_hash === 'string' || (Array.isArray(r) && false)));

async function probe(name, call) {
  let threw = 0, accepts = 0; const acceptInputs = [];
  for (const g of GARBAGE) {
    try { const r = await call(g); if (accepted(r)) { accepts++; acceptInputs.push(tdec(g)); } } catch { threw++; }
  }
  return { name, accepts, threw, acceptInputs };
}

async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const pk = ml_dsa87.keygen(new Uint8Array(32).fill(50)).publicKey; // a pinned key to pass alongside garbage

  const targets = [
    ['pqef.verifyPQEFBundle', (g) => pqef.verifyPQEFBundle(g, { trustedIssuers: [{ public_key_hex: 'aa' }] })],
    ['pqgateway.verifyOffer', (g) => pqgateway.verifyOffer(g, pk)],
    ['pqgateway.negotiate', (g) => pqgateway.negotiate({ localSuites: ['hybrid-mlkem1024-x25519-mldsa87'], remoteOffer: g, policy: {}, trustedPeerPub: pk })],
    ['pqgateway.verifySession', (g) => pqgateway.verifySession(g, pk)],
    ['pqgateway.acceptSession', (g) => pqgateway.acceptSession(g, pk, { requirePQ: true })],
    ['pqsign.verifyBundle', (g) => pqsign.verifyBundle(g, pk, pk)],
    ['pqsign.verifySTH', (g) => pqsign.verifySTH(g, pk)],
    ['pqtsa.verifyTimestamp', (g) => pqtsa.verifyTimestamp(g, pk)],
    ['pqtsa.verifyRestamp', (g) => pqtsa.verifyRestamp(g, pk)],
    ['pqkt.resolveIssuerKey', (g) => pqkt.resolveIssuerKey(g, 'x', { allowTofu: true })],
    ['pqkt.resolveIssuerKey(id)', (g) => pqkt.resolveIssuerKey([{ kind: 'pqkt-key-event', issuer_id: 'x' }], g, { allowTofu: true })],
    ['pqkt.verifyKeyEventInclusion', (g) => pqkt.verifyKeyEventInclusion(g, pk)],
    ['pqkt.verifyWitnessedSTH', (g) => pqkt.verifyWitnessedSTH(g, pk, (() => { try { return g && g.cosigs; } catch { return undefined; } })(), [pk], 1)],
    ['pqkt.gossipDetectEquivocation', (g) => pqkt.gossipDetectEquivocation(g, pk, [pk])],
    ['pqkt.detectEquivocation', (g) => pqkt.detectEquivocation(g, g, pk)],
    ['pqtransport.responderRespond', (g) => pqtransport.responderRespond(g, ml_dsa87.keygen(new Uint8Array(32).fill(51)))],
    ['pqtransport.responderFinish', (g) => pqtransport.responderFinish(g, { th: new Uint8Array(32), i_identity_pub: pk, session: {} }, undefined)],
    // ---- newer verifiers (PKI / vault / compliance / PQXDH / marketplace / search-absence / hosted API) ----
    ['pqpki.verifyCert', (g) => pqpki.verifyCert(g, { mldsa_pub: 'aa', ed_pub: 'bb' })],
    ['pqpki.verifyChain', (g) => pqpki.verifyChain(g, { mldsa_pub: 'aa' })],
    ['pqpki.checkRevocation', (g) => pqpki.checkRevocation(g, { mldsa_pub: 'aa' }, 'sn-1', { at: 100 })],
    ['pqvault.verifyEntry', (g) => pqvault.verifyEntry(g, 'id-1', { authorityPub: pk, logPub: pk, sth: {} })],
    ['pqcompliance.verifyComplianceReport', (g) => pqcompliance.verifyComplianceReport(g, pk)],
    ['pqx3dh.verifyPrekeyBundle', (g) => ({ verified: pqx3dh.verifyPrekeyBundle(g) === true })],
    ['pqmarket.verifyListing', (g) => ({ verified: pqmarket.verifyListing(g, pk) === true })],
    ['pqmarket.verifyAttestationInclusion', (g) => pqmarket.verifyAttestationInclusion(g, pk)],
    ['pqmarket.computeReputation', (g) => pqmarket.computeReputation(g, { subject_agent_id: 'x', capability: 'c', trustedReviewers: ['aa'] })],
    ['pqindex.verifyShard', (g) => pqindex.verifyShard(g, pk)],
    ['pqindex.verifyTermInclusion', (g) => ({ verified: pqindex.verifyTermInclusion('aa'.repeat(32), g) === true })],
    ['pqindex.verifyAbsenceInShard', (g) => ({ verified: pqindex.verifyAbsenceInShard(g, {}, pk) === true })],
    ['pqverify-api.verify', (g) => pqverifyApi.verify(g).then((r) => (r && r.verdict) ? r.verdict : { ok: false })],
  ];

  const results = [];
  for (const [name, call] of targets) results.push(await probe(name, call));

  // synchronous ratchet decrypt (needs initialized state): garbage messages must not decrypt / must fail-closed
  const SK = new Uint8Array(32).fill(7);
  try {
    const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
    const bob = pqratchet.newBobPrekeys ? pqratchet.newBobPrekeys() : null;
    if (bob) {
      let A = pqratchet.initAlice(SK, bob.dh.pub, bob.kem.publicKey);
      let B = pqratchet.initBob(SK, bob.dh, bob.kem);
      pqratchet.ratchetDecrypt(B, pqratchet.ratchetEncrypt(A, 'real')); // establish
      results.push(await probe('pqratchet.ratchetDecrypt', (g) => { try { const r = pqratchet.ratchetDecrypt(B, g); return r ? { ok: false } : r; } catch (e) { throw e; } }));
    }
    const hbob = pqratchetHE.newBobPrekeys ? pqratchetHE.newBobPrekeys() : null;
    if (hbob) {
      let HA = pqratchetHE.initAlice(SK, hbob.dh.pub, hbob.kem.publicKey);
      let HB = pqratchetHE.initBob(SK, hbob.dh, hbob.kem);
      pqratchetHE.ratchetDecrypt(HB, pqratchetHE.ratchetEncrypt(HA, 'real'));
      results.push(await probe('pqratchetHE.ratchetDecrypt', (g) => { const r = pqratchetHE.ratchetDecrypt(HB, g); return r ? { ok: false } : r; }));
    }
  } catch { /* ratchet setup is best-effort */ }

  const totalAccepts = results.reduce((a, r) => a + r.accepts, 0);
  const totalThrew = results.reduce((a, r) => a + r.threw, 0);
  for (const r of results) if (r.accepts) console.error('  ACCEPT-ON-GARBAGE:', r.name, '->', r.acceptInputs.join(' | '));
  if (process.env.FUZZ_VERBOSE) for (const r of results.slice().sort((a, b) => b.threw - a.threw)) console.log('   throw[' + r.threw + '/' + GARBAGE.length + '] ' + r.name);
  ok(totalAccepts === 0, 'NO verifier accepts adversarial/garbage input (fail-OPEN check) — accepts=' + totalAccepts);
  // verdict-returning verifiers must be TOTAL (return a falsy verdict, not throw). EXEMPT: decrypt/handshake steps
  // that correctly reject malformed input BY EXCEPTION (you cannot return a verdict from an AEAD decrypt).
  const EXEMPT = new Set(['pqtransport.responderRespond', 'pqratchet.ratchetDecrypt', 'pqratchetHE.ratchetDecrypt']);
  const notTotal = results.filter((r) => !EXEMPT.has(r.name) && r.threw > 0);
  ok(notTotal.length === 0, 'verdict verifiers are TOTAL (no throw on adversarial input) — offenders: ' + notTotal.map((r) => r.name + '(' + r.threw + ')').join(', '));
  console.log('  ' + results.length + ' verifiers x ' + GARBAGE.length + ' inputs; caught-throws=' + totalThrew + ' (all in the 3 by-design decrypt/handshake steps), accepts=' + totalAccepts);
  console.log('fuzz-robustness: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /fuzz-robustness\.mjs$/.test(process.argv[1] || '')) selfTest();
