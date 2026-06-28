/*!
 * pqseal — apex crypto-AGILITY signing primitive: N-leg AND-composition over a registry of algorithm FAMILIES, with
 * built-in anti-downgrade binding + domain separation + per-family trust pinning. The "beyond hybrid" generalization
 * of the Evidence Pack's ML-DSA ∧ SLH-DSA: a forgery must break EVERY leg; dropping/swapping/adding a leg is detected;
 * you can rotate or ADD a signature family (lattice / hash-based / classical) WITHOUT changing the envelope format —
 * which is the crypto-agility property CNSA 2.0 / NIST emphasise for the post-quantum transition.
 *
 * HONEST: "beyond military grade" is not a claim we make — the claim is the precise property: N-of-N AND-composition
 * across distinct algorithm families, anti-downgrade-bound, verifiable offline against pinned keys. The crypto is the
 * independently-audited @noble/{post-quantum,curves}; pqseal is the (unaudited) composition layer. Self-test: node pqseal.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const SEAL_CTX = utf8ToBytes('trelyan-pqseal-v1');

// Algorithm-FAMILY registry. Add a family here → instant crypto-agility (new suites compose it; the format is unchanged).
// `kind` enables diversity policy (e.g. require a lattice AND a hash-based leg). Families without a native context arg
// (Ed25519) get the context prepended to the message — same domain separation, mechanically.
const FAMILIES = {
  'ML-DSA-87':    { kind: 'lattice',     sign: (m, sk, c) => ml_dsa87.sign(m, sk, { context: c }),            verify: (s, m, pk, c) => ml_dsa87.verify(s, m, pk, { context: c }) },
  'SLH-DSA-256f': { kind: 'hash-based',  sign: (m, sk, c) => slh_dsa_sha2_256f.sign(m, sk, { context: c }),   verify: (s, m, pk, c) => slh_dsa_sha2_256f.verify(s, m, pk, { context: c }) },
  'Ed25519':      { kind: 'classical',   sign: (m, sk, c) => ed25519.sign(concatBytes(c, m), sk),             verify: (s, m, pk, c) => ed25519.verify(s, concatBytes(c, m), pk) },
};
export function registeredFamilies() { return Object.keys(FAMILIES).map((alg) => ({ alg, kind: FAMILIES[alg].kind })); }

// The bytes EVERY leg signs: binds the suite id + the FULL ordered set of leg public keys + the payload hash. So
// dropping/swapping/adding any leg changes `legs` → every other leg's signature fails (N-of-N anti-downgrade), with no
// separate "bind the pubkey into the payload" step required of the caller.
function sealedMessage(suite, legPubsHex, payloadHash) {
  return utf8ToBytes(canon({ v: 'pqseal-1', suite, legs: legPubsHex, payload_sha512: payloadHash }));
}
const suiteOf = (algs) => 'trelyan-seal/' + algs.join('+');

/** seal(payloadBytes, signers) — signers: [{alg, secretKey, publicKey}, ...] (>=1, distinct families recommended). */
export function seal(payloadBytes, signers) {
  if (!Array.isArray(signers) || !signers.length) throw new Error('pqseal: need >=1 signer');
  for (const s of signers) if (!FAMILIES[s.alg]) throw new Error('pqseal: unknown family ' + s.alg);
  const suite = suiteOf(signers.map((s) => s.alg));
  const legPubsHex = signers.map((s) => bytesToHex(s.publicKey));
  const payloadHash = bytesToHex(sha512(payloadBytes));
  const msg = sealedMessage(suite, legPubsHex, payloadHash);
  const legs = signers.map((s, i) => ({ alg: s.alg, kind: FAMILIES[s.alg].kind, pub_hex: legPubsHex[i], sig_hex: bytesToHex(FAMILIES[s.alg].sign(msg, s.secretKey, SEAL_CTX)) }));
  return { v: 'pqseal-1', suite, payload_sha512: payloadHash, legs };
}

/** openSeal(payloadBytes, envelope, opts) — AND-composition: ALL legs must verify.
 *  opts.trusted = {alg: pubBytes,...}  pin per family — each pinned family must be PRESENT + match + valid.
 *  opts.requireSuite = 'trelyan-seal/ML-DSA-87+SLH-DSA-256f'  assert the EXACT composition (rejects any downgrade).
 *  opts.requireKinds = ['lattice','hash-based']  require these family labels among the valid legs (MULTISET — ['lattice',
 *    'lattice'] needs TWO distinct lattice legs). opts.minLegs = N  require >= N valid legs. opts.requireDistinctLegs = true
 *    reject duplicate (alg, pub_hex) legs for true N-leg independence. Result exposes distinctLegs / minLegsOk / distinctOk.
 *  opts.requirePinned = true  every leg must be trust-anchored.
 *  FOOTGUN (council): with NO pins, NO requireSuite, and NO requireKinds, a pass proves only SELF-CONSISTENCY of whatever
 *  legs are present — NOT authenticity or a particular composition. High-assurance callers MUST pass at least one of
 *  {trusted, requireSuite, requireKinds, requirePinned}. The result always exposes fullyAnchored/suiteMatch/kinds so a
 *  caller can never mistake self-consistency for trust. (Canon = deterministic sorted-key JSON over hex/fixed strings.) */
export function openSeal(payloadBytes, envelope, opts = {}) {
  try {
    if (!envelope || envelope.v !== 'pqseal-1' || !Array.isArray(envelope.legs) || !envelope.legs.length) return fail();
    const recomputedHash = bytesToHex(sha512(payloadBytes));
    const payloadOk = recomputedHash === envelope.payload_sha512;
    const suiteOk = envelope.suite === suiteOf(envelope.legs.map((l) => l.alg));
    const legPubsHex = envelope.legs.map((l) => l.pub_hex);
    const msg = sealedMessage(envelope.suite, legPubsHex, envelope.payload_sha512);
    const legs = envelope.legs.map((l) => {
      const fam = FAMILIES[l.alg];
      if (!fam) return { alg: l.alg, kind: 'unknown', valid: false, anchored: false, pinRequired: false };
      let valid = false; try { valid = fam.verify(hexToBytes(l.sig_hex), msg, hexToBytes(l.pub_hex), SEAL_CTX); } catch { valid = false; }
      const pin = opts.trusted && opts.trusted[l.alg];
      const anchored = !!pin && bytesToHex(pin).toLowerCase() === String(l.pub_hex).toLowerCase();
      return { alg: l.alg, kind: fam.kind, valid, anchored, pinRequired: !!pin };
    });
    const allValid = legs.every((r) => r.valid);
    const validLegs = legs.filter((r) => r.valid);
    const validKinds = new Set(validLegs.map((r) => r.kind));
    // requireKinds is a MULTISET predicate (4th sweep): requireKinds:['lattice','lattice'] needs TWO distinct lattice
    // legs, not one — closes the footgun where a single leg satisfied a duplicated requirement.
    const kindCounts = {}; for (const r of validLegs) kindCounts[r.kind] = (kindCounts[r.kind] || 0) + 1;
    const reqCounts = {}; for (const k of (opts.requireKinds || [])) reqCounts[k] = (reqCounts[k] || 0) + 1;
    const familiesOk = !opts.requireKinds || Object.keys(reqCounts).every((k) => (kindCounts[k] || 0) >= reqCounts[k]);
    const distinctLegs = new Set(envelope.legs.filter((l, i) => legs[i] && legs[i].valid).map((l) => l.alg + '\x1f' + l.pub_hex)).size;
    const minLegsOk = !opts.minLegs || validLegs.length >= opts.minLegs;               // require >= N VALID legs
    const distinctOk = !opts.requireDistinctLegs || distinctLegs === validLegs.length; // reject duplicate (alg,pub_hex) legs (true independence)
    const anchoredOk = legs.every((r) => !r.pinRequired || r.anchored);          // a pinned family that MISmatches fails
    // a pinned family must be PRESENT + anchored + valid — a dropped pinned leg is NOT silently ignored (DeepSeek fix #1)
    const pinnedAlgs = opts.trusted ? Object.keys(opts.trusted) : [];
    const pinnedPresent = pinnedAlgs.every((alg) => legs.some((l) => l.alg === alg && l.anchored && l.valid));
    const fullyAnchored = legs.length > 0 && legs.every((r) => r.anchored);
    const meetsPinned = !opts.requirePinned || fullyAnchored;
    const suiteMatch = !opts.requireSuite || envelope.suite === opts.requireSuite; // caller asserts the EXACT composition
    const verified = !!(payloadOk && suiteOk && allValid && familiesOk && anchoredOk && pinnedPresent && meetsPinned && suiteMatch && minLegsOk && distinctOk);
    return { verified, payloadOk, suiteOk, allValid, familiesOk, pinnedPresent, suiteMatch, fullyAnchored, minLegsOk, distinctOk, distinctLegs, kinds: [...validKinds], legs };
  } catch { return fail(); }
}
function fail() { return { verified: false, payloadOk: false, suiteOk: false, allValid: false, familiesOk: false, pinnedPresent: false, suiteMatch: false, fullyAnchored: false, minLegsOk: false, distinctOk: false, distinctLegs: 0, kinds: [], legs: [] }; }

/* ---------- self-test: node pqseal.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const seed = (n, len = 32) => new Uint8Array(len).fill(n);
  const mk = (alg, n) => {
    if (alg === 'ML-DSA-87') { const k = ml_dsa87.keygen(seed(n)); return { alg, secretKey: k.secretKey, publicKey: k.publicKey }; }
    if (alg === 'SLH-DSA-256f') { const k = slh_dsa_sha2_256f.keygen(seed(n, 96)); return { alg, secretKey: k.secretKey, publicKey: k.publicKey }; }
    if (alg === 'Ed25519') { const sk = seed(n); return { alg, secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; }
  };
  const payload = utf8ToBytes('the evidence pack core bytes, or any artifact');
  const A = mk('ML-DSA-87', 11), B = mk('SLH-DSA-256f', 22), C = mk('Ed25519', 33);
  const trustedAll = { 'ML-DSA-87': A.publicKey, 'SLH-DSA-256f': B.publicKey, 'Ed25519': C.publicKey };
  const trusted2 = { 'ML-DSA-87': A.publicKey, 'SLH-DSA-256f': B.publicKey }; // pin the families THIS 2-leg seal carries

  // 1-leg, 2-leg, 3-leg round trips
  ok(openSeal(payload, seal(payload, [A])).verified, '1-leg (ML-DSA) round-trips');
  const env2 = seal(payload, [A, B]);
  const r2 = openSeal(payload, env2, { trusted: trusted2, requireKinds: ['lattice', 'hash-based'], requirePinned: true });
  ok(r2.verified && r2.fullyAnchored && r2.kinds.includes('lattice') && r2.kinds.includes('hash-based'), '2-leg (lattice ∧ hash-based) verifies, anchored, diverse');
  const env3 = seal(payload, [A, B, C]);
  ok(openSeal(payload, env3, { requireKinds: ['lattice', 'hash-based', 'classical'] }).verified, '3-leg (lattice ∧ hash-based ∧ classical) verifies with diversity policy');

  // diversity policy: a single lattice leg cannot satisfy "need a hash-based leg too"
  ok(openSeal(payload, seal(payload, [A]), { requireKinds: ['lattice', 'hash-based'] }).verified === false, 'requireKinds rejects a seal missing a required family');

  // anti-downgrade: STRIP a leg
  const stripped = JSON.parse(JSON.stringify(env2)); stripped.legs.pop();
  ok(openSeal(payload, stripped).verified === false, 'stripping a leg -> FAILS (suite + sealed-message both change)');
  // SWAP a leg's pubkey to an attacker key (+re-sign that leg) — the OTHER leg still binds the original pubset
  const swapped = JSON.parse(JSON.stringify(env2)); const evil = mk('SLH-DSA-256f', 99);
  swapped.legs[1].pub_hex = bytesToHex(evil.publicKey);
  swapped.legs[1].sig_hex = bytesToHex(FAMILIES['SLH-DSA-256f'].sign(sealedMessage(swapped.suite, swapped.legs.map((l) => l.pub_hex), swapped.payload_sha512), evil.secretKey, SEAL_CTX));
  ok(openSeal(payload, swapped).verified === false, 'swapping one leg key -> FAILS (the untouched leg signed the original pubset)');
  // ADD an unsolicited leg
  const added = JSON.parse(JSON.stringify(env2)); added.legs.push({ alg: 'Ed25519', kind: 'classical', pub_hex: bytesToHex(C.publicKey), sig_hex: bytesToHex(FAMILIES['Ed25519'].sign(payload, C.secretKey, SEAL_CTX)) });
  ok(openSeal(payload, added).verified === false, 'adding a leg -> FAILS (suite mismatch + original legs signed the 2-pub set)');

  // tamper payload (hash mismatch)
  ok(openSeal(utf8ToBytes('different payload'), env2).verified === false, 'tampered payload -> FAILS');
  // forge payload + restate the hash to match -> legs signed the original hash -> still fails
  const restated = JSON.parse(JSON.stringify(env2)); restated.payload_sha512 = bytesToHex(sha512(utf8ToBytes('different payload')));
  ok(openSeal(utf8ToBytes('different payload'), restated).verified === false, 'forged payload + restated hash -> FAILS (legs bound the original hash)');
  // wrong pin
  ok(openSeal(payload, env2, { trusted: { 'ML-DSA-87': mk('ML-DSA-87', 77).publicKey } }).verified === false, 'wrong pinned key -> FAILS');
  // requirePinned with no pins
  ok(openSeal(payload, env2, { requirePinned: true }).verified === false, 'requirePinned without pins -> FAILS (self-consistent only)');
  // unpinned still self-consistent
  ok(openSeal(payload, env2).verified === true, 'unpinned -> verifies as self-consistent (validity vs trust model)');

  // requireSuite: assert the EXACT composition (rejects a different/downgraded suite)
  ok(openSeal(payload, env2, { requireSuite: env2.suite }).verified === true, 'requireSuite matching the seal -> verifies');
  ok(openSeal(payload, env2, { requireSuite: 'trelyan-seal/ML-DSA-87' }).verified === false, 'requireSuite mismatch (expected 1-leg, got 2) -> FAILS');
  // pinned-presence (DeepSeek fix): pinning a family that is ABSENT must fail, not be silently ignored
  ok(openSeal(payload, seal(payload, [A]), { trusted: { 'SLH-DSA-256f': B.publicKey } }).verified === false, 'pinning an ABSENT family (SLH on an ML-DSA-only seal) -> FAILS (no silent skip)');
  ok(openSeal(payload, env2, { trusted: trusted2 }).pinnedPresent === true, 'all pinned families present + anchored -> pinnedPresent true');
  ok(openSeal(payload, env3, { trusted: trusted2 }).verified === true, 'keyring pins a SUBSET present in a larger seal -> still verifies (3-leg, pinned 2)');
  ok(registeredFamilies().length === 3, 'registry exposes 3 families (lattice/hash-based/classical) — agility surface');
  console.log('pqseal self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqseal\.mjs$/.test(process.argv[1] || '')) selfTest();
