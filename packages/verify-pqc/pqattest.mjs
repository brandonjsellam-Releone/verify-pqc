/*!
 * pqattest — composes three TESTED TRELYAN primitives into one attestation, additive (weakens nothing):
 *   WHO         pqseal   — N-of-N multi-family signature (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519), anti-downgrade
 *   WHEN        pqtsa    — threshold post-quantum timestamp over the artifact hash (multi-TSA)
 *   WHERE-LOGGED pqsign  — RFC-6962 transparency-log inclusion proof + signed tree head
 *
 * COUNCIL FIX (10-seat review, unanimous): binding all three to the same artifact hash is NECESSARY but NOT
 * SUFFICIENT — that allows a downgrade by swapping in a different valid timestamp/log entry for the same hash. So the
 * SEAL is computed LAST and signs a COMPOSITE that commits to the timestamp + the signed tree head + the policy +
 * the threshold (Sigstore "countersign the signature, not the artifact"). Swapping the tst, the STH, the threshold,
 * the policy, or the index breaks the multi-family seal. This is the construction that makes pqattest downgrade-detecting under the stated trust model.
 *
 * HONESTY (council): NOT an eIDAS "qualified" timestamp (we are not an accredited QTSP); NOT a legal/court
 * determination; NOT "maximal" / "military-grade". The crypto is the (independently-audited) @noble primitives;
 * pqattest + pqseal are the (UNAUDITED) composition layer. Self-test: node pqattest.mjs
 */
import * as pqseal from './pqseal.mjs';
import * as pqtsa from './pqtsa.mjs';
import { PQTransparencyLog } from './pqsign.mjs';
import { makeWitness, verifyWitnessedSTH } from './pqkt.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const ATTEST_V = 'pqattest-1';
const h512 = (obj) => bytesToHex(sha512(utf8ToBytes(canon(obj))));

// The composite the SEAL commits to — binds WHO to WHAT (artifact) + WHEN (full tst incl. all cosigs) + WHERE-LOGGED
// (the exact signed tree head) + POLICY + THRESHOLD + the seal suite. Any swap of any component changes this.
function bindingBytes({ policy_id, artifact_sha256, artifact_sha512, tst, sth, anchor_index, min_tsa, min_witness = 0, suite }) {
  return utf8ToBytes(canon({
    v: ATTEST_V, policy_id,
    artifact_sha512,                // STRONG artifact binding (SHA-512; ~256-bit quantum collision). The seal binds this.
    artifact_sha256,                // secondary — ties to the TSA token's native content_sha256 field
    tst_sha512: h512(tst),          // full timestamp incl. every cosigner → dropping one breaks the seal
    sth_sha512: h512(sth),          // the exact logged tree state
    anchor_index, min_tsa, min_witness, seal_suite: suite,  // min_witness sealed → can't drop below the anchored count
  }));
}

/** attest(artifactBytes, {signers, tsas, log, logSk, logPub?, witnesses?, policy_id?, min_tsa?, ts?}). Pass `witnesses`
 *  (pqkt.makeWitness objects) + `logPub` to add equivocation-resistant WITNESS co-signatures on the tree head. */
export function attest(artifactBytes, { signers, tsas, log, logSk, logPub = null, witnesses = [], policy_id = 'trelyan-pqattest-baseline', min_tsa = null, ts = null }) {
  if (!signers || !signers.length || !tsas || !tsas.length || !log || !logSk) throw new Error('pqattest: signers, tsas, log, logSk required');
  const threshold = min_tsa ?? tsas.length;
  const artifact_sha256 = bytesToHex(sha256(artifactBytes));   // for the TSA token's content_sha256 field
  const artifact_sha512 = bytesToHex(sha512(artifactBytes));   // the STRONG binding the seal commits to
  // WHEN: timestamp the artifact hash; every extra TSA cosigns the SAME token body (threshold)
  let tst = pqtsa.timestamp({ content_sha256: artifact_sha256 }, tsas[0].sk, tsas[0].pub, { ts });
  for (let i = 1; i < tsas.length; i++) tst = pqtsa.cosignTimestamp(tst, tsas[i].sk, tsas[i].pub);
  // WHERE-LOGGED: anchor the (now final) tst → inclusion proof + signed tree head
  const { index, entry } = pqtsa.anchor(log, tst);
  const inclusion = log.inclusion(index);
  const sth = log.signedTreeHead(logSk, { ts: ts ?? 0 });
  // WITNESSED (optional, equivocation resistance): independent witnesses co-sign the SAME tree head
  const witness_cosigs = (witnesses && witnesses.length && logPub)
    ? witnesses.map((w) => { const r = w.cosign(sth, logPub, []); return r && r.ok ? r.cosig : null; }).filter(Boolean) : [];
  const min_witness = witness_cosigs.length;
  const suite = 'trelyan-seal/' + signers.map((s) => s.alg).join('+');
  // WHO: SEAL LAST over the composite — the multi-family signature countersigns the timestamp + tree state + policy +
  // both thresholds (min_tsa, min_witness), so neither the timestamp set nor the witness set can be downgraded.
  const seal = pqseal.seal(bindingBytes({ policy_id, artifact_sha256, artifact_sha512, tst, sth, anchor_index: index, min_tsa: threshold, min_witness, suite }), signers);
  return { v: ATTEST_V, policy_id, artifact_sha256, artifact_sha512, min_tsa: threshold, min_witness, suite, tst, anchor: { entry, inclusion, sth, witness_cosigs }, seal };
}

/** verifyAttest(artifactBytes, att, {trusted, requireSuite, tsaPubs, logPub}) — ALL must pass (AND). For authenticity,
 *  pass trusted (pqseal per-family pins) + tsaPubs (the expected TSAs) + logPub (the pinned log key). */
export function verifyAttest(artifactBytes, att, opts = {}) {
  try {
    if (!att || att.v !== ATTEST_V || !att.anchor || !att.tst || !att.seal) return failA();
    const artifact_sha256 = bytesToHex(sha256(artifactBytes));
    const artifact_sha512 = bytesToHex(sha512(artifactBytes));
    const hashOk = artifact_sha512 === att.artifact_sha512 && artifact_sha256 === att.artifact_sha256; // STRONG = SHA-512
    const tstBindOk = att.tst.content_sha256 === att.artifact_sha256;                    // tst commits to THIS artifact
    const tstRes = pqtsa.verifyTimestampThreshold(att.tst, opts.tsaPubs || [], att.min_tsa); // min_tsa is sealed below
    const anchorRes = pqtsa.verifyAnchor(att.anchor, opts.logPub);                        // real STH sig + Merkle inclusion
    // WITNESS (equivocation resistance): if the seal anchored >=1 witness, require that many DISTINCT trusted witnesses
    // to have co-signed THIS tree head. min_witness is sealed, so it cannot be lowered; dropping a cosig drops the count.
    const mw = att.min_witness || 0;
    const witnessRes = mw > 0 ? verifyWitnessedSTH(att.anchor.sth, opts.logPub, att.anchor.witness_cosigs, opts.trustedWitnessPubs || [], mw) : { verified: true, witness_count: 0 };
    // recompute the composite the seal MUST cover — any swap of tst/sth/threshold(s)/policy/index/suite breaks this
    const binding = bindingBytes({ policy_id: att.policy_id, artifact_sha256: att.artifact_sha256, artifact_sha512: att.artifact_sha512, tst: att.tst, sth: att.anchor.sth, anchor_index: att.anchor.inclusion.index, min_tsa: att.min_tsa, min_witness: mw, suite: att.suite });
    const sealRes = pqseal.openSeal(binding, att.seal, { trusted: opts.trusted, requireSuite: opts.requireSuite });
    const verified = !!(hashOk && tstBindOk && tstRes.verified && anchorRes.verified && witnessRes.verified && sealRes.verified);
    return { verified, hashOk, tstBindOk, timestampOk: tstRes.verified, anchorOk: anchorRes.verified, witnessOk: witnessRes.verified, witnessCount: witnessRes.witness_count, sealOk: sealRes.verified, sealTrustAnchored: sealRes.fullyAnchored, signerCount: tstRes.signer_count, kinds: sealRes.kinds };
  } catch { return failA(); }
}
function failA() { return { verified: false, hashOk: false, tstBindOk: false, timestampOk: false, anchorOk: false, witnessOk: false, sealOk: false, sealTrustAnchored: false }; }

/* ---------- self-test: node pqattest.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const seed = (n, len = 32) => new Uint8Array(len).fill(n);
  const A = (() => { const k = ml_dsa87.keygen(seed(11)); return { alg: 'ML-DSA-87', secretKey: k.secretKey, publicKey: k.publicKey }; })();
  const B = (() => { const k = slh_dsa_sha2_256f.keygen(seed(22, 96)); return { alg: 'SLH-DSA-256f', secretKey: k.secretKey, publicKey: k.publicKey }; })();
  const E = (() => { const sk = seed(33); return { alg: 'Ed25519', secretKey: sk, publicKey: ed25519.getPublicKey(sk) }; })();
  const tsa1 = (() => { const k = pqtsa.genTsaKey(seed(41)); return { sk: k.secretKey, pub: k.publicKey }; })();
  const tsa2 = (() => { const k = pqtsa.genTsaKey(seed(42)); return { sk: k.secretKey, pub: k.publicKey }; })();
  const logKp = ml_dsa87.keygen(seed(51));
  const artifact = utf8ToBytes('the PQC Migration Evidence Pack core bytes');

  const fresh = () => new PQTransparencyLog();
  const mkAtt = (log) => attest(artifact, { signers: [A, B, E], tsas: [tsa1, tsa2], log, logSk: logKp.secretKey, ts: 1000 });
  const trusted = { 'ML-DSA-87': A.publicKey, 'SLH-DSA-256f': B.publicKey, 'Ed25519': E.publicKey };
  const vopts = { trusted, tsaPubs: [tsa1.pub, tsa2.pub], logPub: logKp.publicKey };

  let log = fresh(); const att = mkAtt(log);
  const v = verifyAttest(artifact, att, vopts);
  ok(v.verified && v.sealTrustAnchored && v.signerCount === 2 && v.kinds.includes('lattice') && v.kinds.includes('hash-based') && v.kinds.includes('classical'),
    'round-trip: signed N-ways ∧ threshold-timestamped ∧ logged verifies (anchored, 2 TSAs, 3 families)');

  // tamper the artifact
  ok(verifyAttest(utf8ToBytes('different artifact'), att, vopts).verified === false, 'tampered artifact -> FAILS (hash)');

  // *** THE COUNCIL ATTACK ***: swap the TST for a DIFFERENT valid TST of the same hash (different time) — must FAIL
  const tst2 = pqtsa.cosignTimestamp(pqtsa.timestamp({ content_sha256: att.artifact_sha256 }, tsa1.sk, tsa1.pub, { ts: 9999 }), tsa2.sk, tsa2.pub);
  const swapped = JSON.parse(JSON.stringify(att)); swapped.tst = tst2;
  ok(verifyAttest(artifact, swapped, vopts).verified === false, 'COUNCIL FIX: swap in a different same-hash TST -> FAILS (seal countersigns the exact timestamp)');

  // drop a TSA cosigner -> tst changes (seal binding) AND threshold drops
  const dropped = JSON.parse(JSON.stringify(att)); dropped.tst = { ...dropped.tst, cosigs: [] };
  ok(verifyAttest(artifact, dropped, vopts).verified === false, 'drop a TSA cosigner -> FAILS (sealed tst hash + threshold)');

  // swap the signed tree head -> seal binding breaks
  let log2 = fresh(); log2.append({ kind: 'noise' }); const sthOther = log2.signedTreeHead(logKp.secretKey, { ts: 0 });
  const sthSwap = JSON.parse(JSON.stringify(att)); sthSwap.anchor.sth = sthOther;
  ok(verifyAttest(artifact, sthSwap, vopts).verified === false, 'swap the signed tree head -> FAILS (seal countersigns the STH)');

  // lower the sealed threshold (min_tsa) -> seal binding breaks
  const thr = JSON.parse(JSON.stringify(att)); thr.min_tsa = 1;
  ok(verifyAttest(artifact, thr, vopts).verified === false, 'lower the sealed threshold -> FAILS (min_tsa is in the seal)');

  // wrong seal pin / wrong TSA pin / wrong log pin each fail
  ok(verifyAttest(artifact, att, { ...vopts, trusted: { 'ML-DSA-87': ml_dsa87.keygen(seed(99)).publicKey } }).verified === false, 'wrong seal pin -> FAILS');
  ok(verifyAttest(artifact, att, { ...vopts, tsaPubs: [tsa1.pub] }).verified === false, 'only 1 of 2 required TSAs trusted -> FAILS threshold');
  ok(verifyAttest(artifact, att, { ...vopts, logPub: ml_dsa87.keygen(seed(98)).publicKey }).verified === false, 'wrong log pin -> FAILS anchor');

  // unpinned -> self-consistent but NOT trust-anchored (honest validity-vs-trust)
  const un = verifyAttest(artifact, att, {});
  ok(un.sealTrustAnchored === false, 'unpinned verify -> sealTrustAnchored=false (self-consistent only, not authenticity)');

  // WITNESSED attestation (equivocation resistance): independent witnesses co-sign the tree head
  const w1 = makeWitness(seed(61)), w2 = makeWitness(seed(62));
  const watt = attest(artifact, { signers: [A, B, E], tsas: [tsa1, tsa2], log: fresh(), logSk: logKp.secretKey, logPub: logKp.publicKey, witnesses: [w1, w2], ts: 1000 });
  const trustedWit = [w1.publicKey, w2.publicKey];
  const wv = verifyAttest(artifact, watt, { ...vopts, trustedWitnessPubs: trustedWit });
  ok(wv.verified && wv.witnessOk && wv.witnessCount === 2, 'witnessed: 2 trusted witnesses co-signed the tree head -> verifies');
  ok(verifyAttest(artifact, watt, vopts).verified === false, 'witnessed pack but NO trusted witness pubs supplied -> FAILS (threshold unmet)');
  const wdrop = JSON.parse(JSON.stringify(watt)); wdrop.anchor.witness_cosigs = wdrop.anchor.witness_cosigs.slice(0, 1);
  ok(verifyAttest(artifact, wdrop, { ...vopts, trustedWitnessPubs: trustedWit }).verified === false, '0-DOWNGRADE: drop a witness cosig -> FAILS (sealed min_witness=2 unmet)');
  const wlower = JSON.parse(JSON.stringify(watt)); wlower.min_witness = 1;
  ok(verifyAttest(artifact, wlower, { ...vopts, trustedWitnessPubs: trustedWit }).verified === false, 'lower the sealed min_witness -> FAILS (min_witness is in the seal binding)');

  console.log('pqattest self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqattest\.mjs$/.test(process.argv[1] || '')) selfTest();
