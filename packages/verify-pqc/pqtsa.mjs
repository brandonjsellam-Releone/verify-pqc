/*!
 * pqtsa — Quantum-Safe Timestamping Authority + legacy-signature re-stamping (reference, DRAFT, standalone).
 *
 * The eIDAS-2.0 gap product: an RFC-3161-style TSA that ML-DSA-87-signs timestamp tokens (TSTs) over a content
 * hash, and — the key piece — RE-STAMPS legacy classical signatures (RSA/ECDSA/Ed25519) into a post-quantum-
 * anchored proof. Why it matters: under "harvest-now / forge-later", a classical signature could be forged once
 * the scheme breaks. A PQ timestamp that attests "this classical signature over this content was VERIFIED and
 * existed at time T" preserves its long-term legal validity even after the classical scheme falls — because the
 * proof predates any future break and is itself post-quantum. TSTs are anchored in the pqsign transparency log.
 *
 * HONEST LIMITS (incl. Mistral review):
 *  - A re-stamp attests EXISTENCE-AT-TIME (+ that the legacy sig verified when stamped) — NOT that the legacy
 *    scheme is unbroken now. The TRUST/TIMING assumption: the stamp must occur BEFORE the legacy break AND the
 *    TSA key must be uncompromised at stamp time.
 *  - KEY-COMPROMISE / forward secrecy: if the TSA's ML-DSA-87 key leaks, past tokens become forgeable. Mitigate
 *    with (a) multi-TSA THRESHOLD co-signing (`cosignTimestamp`/`verifyTimestampThreshold` — added), (b) anchoring
 *    each token in the transparency log (done), and (c) a forward-secure/key-evolving signer (XMSS/LMS) or frequent
 *    key-epoch rotation with per-epoch pubkeys logged (ROADMAP).
 *  - NOT a qualified eIDAS QTSA: lacks QTSA accreditation, an accredited UTC-traceable time source, the ASN.1
 *    RFC-3161 TST format, and LTV/ERS long-term evidence records (RFC 4998). This is the PQ-TSA CORE; qualification
 *    is an owner/accreditation step. ML-DSA-87 is not yet an eIDAS-mandated alg → consider a hybrid ML-DSA+Ed25519 token.
 *  - GDPR: timestamp only SALTED hashes, never raw PII (a reversible content hash could re-identify). Self-test: node pqtsa.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { PQTransparencyLog, verifySTH, leafHash, entryLeafHash, verifyInclusionRFC } from './pqsign.mjs';

const TST_CTX = utf8ToBytes('trelyan-pqtsa-token-v1');
const sha = (s) => bytesToHex(sha512(typeof s === 'string' ? utf8ToBytes(s) : s)); // Grover-hardened 512-bit
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

export const genTsaKey = (seed) => ml_dsa87.keygen(seed);

/* ---------- plain timestamp token over a content hash ---------- */
export function timestamp({ content_sha256, serial, nonce, policy }, tsaSk, tsaPub, opts = {}) {
  const core = { v: '0.1', kind: 'tst', content_sha256, tsa_time: opts.ts ?? null, serial: serial ?? null, nonce: nonce ?? null, policy: policy || 'trelyan-pqtsa-baseline', alg: 'ML-DSA-87' };
  return { ...core, tsa_pub: bytesToHex(tsaPub), sig: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), tsaSk, { context: TST_CTX })) };
}
export function verifyTimestamp(tst, trustedTsaPub) {
 try { // TOTAL (fuzz): throwing getter/Proxy/BigInt field fails CLOSED, never DoS
  if (!tst || typeof tst !== 'object' || Array.isArray(tst)) return { verified: false, pinned: false, sigOk: false, claims: null };
  const { sig, tsa_pub, cosigs, ...core } = tst; // cosigs excluded from the signed body
  // pinned = a TSA key was SUPPLIED and it MATCHES — so a caller can't read pinned:true as "authentic" when they
  // didn't pin (validity-vs-trust). verified is unchanged: unpinned -> sigOk (self-consistent); pinned -> match && sigOk.
  const pinned = !!trustedTsaPub && String(tsa_pub).toLowerCase() === bytesToHex(trustedTsaPub).toLowerCase();
  let sigOk = false;
  try { sigOk = ml_dsa87.verify(hexToBytes(sig), utf8ToBytes(canon(core)), trustedTsaPub ? trustedTsaPub : hexToBytes(tsa_pub), { context: TST_CTX }); } catch { sigOk = false; }
  return { verified: (trustedTsaPub ? pinned : true) && sigOk, pinned, sigOk, claims: core };
 } catch { return { verified: false, pinned: false, sigOk: false, claims: null }; }
}

/* ---------- multi-TSA threshold co-signing (mitigates the single-trusted-TSA weak point) ---------- */
// an independent TSA co-signs the SAME token body; verifyTimestampThreshold requires >= minSigners distinct trusted TSAs.
export function cosignTimestamp(tst, tsaSk, tsaPub) {
  const { sig, tsa_pub, cosigs, ...core } = tst;
  tst.cosigs = (tst.cosigs || []).concat([{ tsa_pub: bytesToHex(tsaPub), sig: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), tsaSk, { context: TST_CTX })) }]);
  return tst;
}
export function verifyTimestampThreshold(tst, trustedTsaPubs, minSigners = 1) {
 try { // TOTAL (3rd sweep): null tst / malformed pin list fails CLOSED, never throws
  if (!tst || typeof tst !== 'object' || Array.isArray(tst)) return { verified: false, signer_count: 0, threshold: minSigners };
  const trusted = (trustedTsaPubs || []).map((p) => bytesToHex(p).toLowerCase());
  const { sig, tsa_pub, cosigs, ...core } = tst;
  const body = utf8ToBytes(canon(core));
  const signers = new Set();
  for (const a of [{ tsa_pub, sig }].concat(cosigs || [])) {
    let ok = false; try { ok = ml_dsa87.verify(hexToBytes(a.sig), body, hexToBytes(a.tsa_pub), { context: TST_CTX }); } catch { ok = false; }
    if (ok && trusted.includes(a.tsa_pub.toLowerCase())) signers.add(a.tsa_pub.toLowerCase());
  }
  return { verified: signers.size >= Math.max(1, minSigners), signer_count: signers.size, threshold: minSigners };
 } catch { return { verified: false, signer_count: 0, threshold: minSigners }; }
}

/* ---------- legacy-signature re-stamping ---------- */
// verifies the legacy sig at stamp time (Ed25519 inline; other algs via the caller's `legacy_verified`), then
// PQ-timestamps the bundle so its existence + validity-at-T is provable post-quantum.
export function restampLegacy({ content, content_sha256, legacy_alg, legacy_sig, legacy_pub, legacy_verified }, tsaSk, tsaPub, opts = {}) {
  const cHash = content_sha256 || (content ? sha(content) : null);
  let verified = !!legacy_verified;
  if (legacy_alg === 'Ed25519' && legacy_sig && legacy_pub && content) {
    try { verified = ed25519.verify(legacy_sig, content, legacy_pub); } catch { verified = false; }
  }
  const bundle_sha256 = sha(canon({ content_sha256: cHash, legacy_alg, legacy_sig_sha256: legacy_sig ? sha(legacy_sig) : null, legacy_pub_sha256: legacy_pub ? sha(legacy_pub) : null }));
  const core = { v: '0.1', kind: 'legacy-restamp', bundle_sha256, content_sha256: cHash, legacy_alg, legacy_verified_at_stamp: verified, tsa_time: opts.ts ?? null, policy: 'trelyan-pqtsa-restamp', alg: 'ML-DSA-87' };
  return { ...core, tsa_pub: bytesToHex(tsaPub), sig: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), tsaSk, { context: TST_CTX })) };
}
export function verifyRestamp(rt, trustedTsaPub, opts = {}) {
 try { // TOTAL (fuzz): throwing getter/Proxy/BigInt field fails CLOSED, never DoS
  if (!rt || typeof rt !== 'object' || Array.isArray(rt)) return { verified: false, sigOk: false, pinned: false, bundleOk: false, claims: null, note: 'malformed re-stamp' };
  const v = verifyTimestamp(rt, trustedTsaPub);
  const bundleOk = !opts.expectedBundle || rt.bundle_sha256 === opts.expectedBundle;
  return {
    verified: v.verified && bundleOk, sigOk: v.sigOk, pinned: v.pinned, bundleOk, claims: v.claims,
    note: 'attests the ' + rt.legacy_alg + ' signature EXISTED at tsa_time and verified=' + rt.legacy_verified_at_stamp + ' WHEN STAMPED — NOT that the legacy scheme is unbroken now. Validity survives a future break because this PQ proof predates it.',
  };
 } catch { return { verified: false, sigOk: false, pinned: false, bundleOk: false, claims: null, note: 'malformed re-stamp' }; }
}

/* ---------- anchor a TST in the pqsign transparency log (third-party verifiable) ---------- */
export function anchor(log, tst) { const entry = { kind: 'pqtsa-tst', tsa_pub: tst.tsa_pub, sig_sha256: sha(tst.sig) }; return { index: log.append(entry), entry }; }
export function verifyAnchor({ entry, inclusion, sth }, logPub) {
 try { // TOTAL (3rd sweep): a malformed anchor proof fails CLOSED, never throws (fuzz-robustness)
  if (!entry || typeof entry !== 'object' || !inclusion || typeof inclusion !== 'object' || !sth || typeof sth !== 'object') return { verified: false, sthOk: false, incOk: false, leafBound: false, treeSizeOk: false };
  const sthOk = verifySTH(sth, logPub);
  const expectedLeaf = entryLeafHash(entry);
  const leafBound = bytesToHex(expectedLeaf) === bytesToHex(inclusion.leaf);
  // HARDENING (RFC-6962 §2.1.1): bind the proof to (index, tree_size) and require tree_size to match the signed STH.
  const treeSizeOk = inclusion.tree_size === sth.tree_size;
  const incOk = leafBound && treeSizeOk && verifyInclusionRFC(expectedLeaf, inclusion.index, sth.tree_size, (inclusion.proof || []).map((p) => p.sibling), hexToBytes(sth.root_hex));
  return { verified: sthOk && incOk, sthOk, incOk, leafBound, treeSizeOk };
 } catch { return { verified: false, sthOk: false, incOk: false, leafBound: false, treeSizeOk: false }; }
}

/* ---------- self-test: node pqtsa.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const tsa = genTsaKey(new Uint8Array(32).fill(91));
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(92));

  // 1. plain timestamp token
  const cHash = sha(utf8ToBytes('the document contents'));
  const tst = timestamp({ content_sha256: cHash, serial: '0001', nonce: 'abcd' }, tsa.secretKey, tsa.publicKey, { ts: 1000 });
  ok(verifyTimestamp(tst, tsa.publicKey).verified === true, 'timestamp token verifies under the pinned TSA key');
  const tamp = { ...tst, content_sha256: sha(utf8ToBytes('different')) };
  ok(verifyTimestamp(tamp, tsa.publicKey).verified === false, 'tampered content hash -> timestamp FAILS');
  ok(verifyTimestamp(tst, ml_dsa87.keygen(new Uint8Array(32).fill(7)).publicKey).verified === false, 'token under a non-TSA key -> NOT verified');

  // 2. legacy re-stamp: a REAL Ed25519 signature is verified at stamp time, then PQ-timestamped
  const legSk = ed25519.utils.randomSecretKey ? ed25519.utils.randomSecretKey() : ed25519.utils.randomPrivateKey();
  const legPub = ed25519.getPublicKey(legSk);
  const doc = utf8ToBytes('legacy-signed contract v1');
  const legSig = ed25519.sign(doc, legSk);
  const rt = restampLegacy({ content: doc, legacy_alg: 'Ed25519', legacy_sig: legSig, legacy_pub: legPub }, tsa.secretKey, tsa.publicKey, { ts: 1001 });
  ok(rt.legacy_verified_at_stamp === true, 're-stamp actually verified the Ed25519 signature at stamp time');
  ok(verifyRestamp(rt, tsa.publicKey, { expectedBundle: rt.bundle_sha256 }).verified === true, 'legacy re-stamp verifies (PQ proof of the classical sig existing+valid at T)');
  // a forged/invalid legacy sig is recorded as NOT verified
  const badSig = legSig.slice(); badSig[0] ^= 1;
  const rtBad = restampLegacy({ content: doc, legacy_alg: 'Ed25519', legacy_sig: badSig, legacy_pub: legPub }, tsa.secretKey, tsa.publicKey, { ts: 1002 });
  ok(rtBad.legacy_verified_at_stamp === false, 'an invalid legacy signature is stamped as legacy_verified=false (honest)');

  // 3. anchor the TST in the transparency log -> third-party verifiable inclusion
  const log = new PQTransparencyLog();
  [0, 1].forEach((i) => log.append({ kind: 'other', i }));
  const { index, entry } = anchor(log, tst);
  log.append({ kind: 'other', i: 9 });
  const sth = log.signedTreeHead(logKey.secretKey, { ts: 2000 });
  const inc = log.inclusion(index);
  ok(verifyAnchor({ entry, inclusion: inc, sth }, logKey.publicKey).verified === true, 'TST is anchored + included in the transparency log');

  // 4. multi-TSA threshold co-signing (mitigates single-TSA compromise — Mistral)
  const tsa2 = genTsaKey(new Uint8Array(32).fill(93));
  const tst2 = timestamp({ content_sha256: cHash, serial: '0002' }, tsa.secretKey, tsa.publicKey, { ts: 1003 });
  cosignTimestamp(tst2, tsa2.secretKey, tsa2.publicKey);
  ok(verifyTimestamp(tst2, tsa.publicKey).verified === true, 'primary signature still verifies after co-signing (cosigs excluded from body)');
  ok(verifyTimestampThreshold(tst2, [tsa.publicKey, tsa2.publicKey], 2).verified === true, '2-of-2 TSA threshold met');
  ok(verifyTimestampThreshold(tst2, [tsa.publicKey], 2).verified === false, 'only 1 trusted TSA present -> 2-of-2 threshold NOT met');
  ok(verifyTimestampThreshold(tst2, [tsa.publicKey, ml_dsa87.keygen(new Uint8Array(32).fill(5)).publicKey], 2).verified === false, 'an untrusted co-signer does not count toward the threshold');

  console.log('pqtsa self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqtsa\.mjs$/.test(process.argv[1] || '')) selfTest();
