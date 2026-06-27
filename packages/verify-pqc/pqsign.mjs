/*!
 * pqsign — PQ code-signing + supply-chain transparency notary (reference, DRAFT, standalone).
 *
 * Tier-1 product #2. A Sigstore/cosign-shaped flow, post-quantum:
 *   - ML-DSA-87 (FIPS 204) signs a release ATTESTATION over the artifact digest + metadata.
 *   - An RFC-6962-style append-only Merkle TRANSPARENCY LOG records each attestation.
 *   - The log publishes an ML-DSA-87-signed Signed Tree Head (STH) + inclusion proofs.
 *   - A verifier confirms: artifact signature + Merkle inclusion + STH signature (fail-closed).
 *
 * Pairs with polarseek.mjs (the signing key can be POLARSEEK-custody-sealed) and the PQEF
 * evidence model. New, self-contained reference code; touches no production key. Self-test: node pqsign.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils.js';

const SIGN_CTX = utf8ToBytes('trelyan-pqsign-attestation-v1');
const STH_CTX = utf8ToBytes('trelyan-pqsign-sth-v1');

/* ---------- RFC-6962-style Merkle (leaf=H(0x00||d), node=H(0x01||l||r)) ---------- */
const H = (...p) => sha256(concatBytes(...p));
const leafHash = (data) => H(Uint8Array.of(0), data);
const nodeHash = (l, r) => H(Uint8Array.of(1), l, r);
// CANONICAL leaf serialization (full-council unanimous: leaves MUST be canonical for cross-impl determinism, like the
// STH — recursively sorted keys, minimal separators). entryLeafHash is the ONE leaf fn the spine + all consumers use.
function canon(v) { if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v); if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']'; return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'; }
const entryLeafHash = (entry) => leafHash(utf8ToBytes(canon(entry)));

function merkleRoot(leaves) {
  if (!leaves.length) return sha256(new Uint8Array());
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return level[0];
}
// Inclusion proof: list of { sibling, right } where `right` means H is the LEFT input.
function inclusionProof(leaves, index) {
  const proof = []; let idx = index, level = leaves;
  while (level.length > 1) {
    const pairStart = idx - (idx % 2);
    if (pairStart + 1 < level.length) proof.push({ sibling: level[idx % 2 === 0 ? idx + 1 : idx - 1], right: idx % 2 === 0 });
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    idx = Math.floor(idx / 2); level = next;
  }
  return proof;
}
function verifyInclusion(leaf, proof, root) {
  let h = leaf;
  for (const p of proof) h = p.right ? nodeHash(h, p.sibling) : nodeHash(p.sibling, h);
  return bytesToHex(h) === bytesToHex(root);
}
// HARDENED inclusion verification — RFC-6962 §2.1.1. Directions are DERIVED from (leaf_index, tree_size), NOT
// trusted from the proof, and the proof length is checked (sn==0) — so a proof is bound to one position in a tree
// of exactly that size. auditPath = the bare sibling hashes (leaf→root order). 32-bit index math (reference scale).
function verifyInclusionRFC(leaf, index, treeSize, auditPath, root) {
  if (!(index >= 0 && index < treeSize)) return false;
  if (treeSize > 0xFFFFFFFF) return false; // fail-closed above 2^32 leaves: 32-bit shift math would truncate (NVIDIA) — production needs BigInt
  let fn = index, sn = treeSize - 1, r = leaf;
  for (const p of auditPath) {
    if (sn === 0) return false; // proof longer than the tree allows
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      while ((fn & 1) === 0 && fn !== 0) { fn >>>= 1; sn >>>= 1; } // rightmost-node case (fn==sn, fn even)
    } else {
      r = nodeHash(r, p);
    }
    fn >>>= 1; sn >>>= 1;
  }
  return sn === 0 && bytesToHex(r) === bytesToHex(root);
}

/* ---------- RFC-6962 §2.1.2 CONSISTENCY proof (append-only / no-rewrite guarantee) ---------- */
const largestPow2Below = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; }; // largest power of 2 strictly < n (n>=2)
function subProof(m, leaves, b) {
  const n = leaves.length;
  if (m === n) return b ? [] : [merkleRoot(leaves)];
  const k = largestPow2Below(n);
  if (m <= k) return subProof(m, leaves.slice(0, k), b).concat([merkleRoot(leaves.slice(k))]);
  return subProof(m - k, leaves.slice(k), false).concat([merkleRoot(leaves.slice(0, k))]);
}
function consistencyProof(leaves, m) {
  const n = leaves.length;
  if (m < 1 || m > n) return null;
  return m === n ? [] : subProof(m, leaves, true);
}
// verify that tree@m (root1) is a PREFIX of tree@n (root2) — proves the log only appended, never rewrote history.
function verifyConsistency(m, n, root1, root2, proof) {
  if (m < 1 || m > n) return false;
  if (n > 0xFFFFFFFF) return false; // fail-closed above 2^32 leaves (32-bit shift math) — production needs BigInt
  if (m === n) return proof.length === 0 && bytesToHex(root1) === bytesToHex(root2);
  const isPow2 = (m & (m - 1)) === 0;
  const path = isPow2 ? [root1, ...proof] : proof.slice();
  if (!path.length) return false;
  let fn = m - 1, sn = n - 1;
  while (fn & 1) { fn >>>= 1; sn >>>= 1; }
  let fr = path[0], sr = path[0];
  for (let i = 1; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      while (!(fn & 1) && fn !== 0) { fn >>>= 1; sn >>>= 1; }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>>= 1; sn >>>= 1;
  }
  return sn === 0 && bytesToHex(fr) === bytesToHex(root1) && bytesToHex(sr) === bytesToHex(root2);
}

/* ---------- artifact attestation ---------- */
// canonical (sorted-key) — matches entryLeafHash/STH/pqseal so a second conformant verifier
// re-serializing `meta` in a different key order recomputes identical signed bytes (cross-impl determinism).
const attCore = (a) => utf8ToBytes(canon({ artifact_sha256: a.artifact_sha256, meta: a.meta, suite: a.suite, ts: a.ts }));

export function signArtifact(artifactBytes, signerSecret, meta = {}, opts = {}) {
  const att = { artifact_sha256: bytesToHex(sha256(artifactBytes)), meta, suite: 'ML-DSA-87', ts: opts.ts ?? Date.now() };
  att.sig = bytesToHex(ml_dsa87.sign(attCore(att), signerSecret, { context: SIGN_CTX }));
  return att;
}
export function verifyArtifact(att, signerPub) {
  try { return ml_dsa87.verify(hexToBytes(att.sig), attCore(att), signerPub, { context: SIGN_CTX }); } catch { return false; }
}

/* ---------- transparency log ---------- */
export class PQTransparencyLog {
  constructor() { this.entries = []; }
  append(att) { this.entries.push(att); return this.entries.length - 1; }
  _leaves() { return this.entries.map((a) => entryLeafHash(a)); }
  signedTreeHead(logSecret, opts = {}) {
    const root = merkleRoot(this._leaves());
    const sth = { tree_size: this.entries.length, root_hex: bytesToHex(root), ts: opts.ts ?? Date.now() };
    const core = utf8ToBytes(JSON.stringify({ tree_size: sth.tree_size, root: sth.root_hex, ts: sth.ts }));
    sth.sig = bytesToHex(ml_dsa87.sign(core, logSecret, { context: STH_CTX }));
    return sth;
  }
  inclusion(index) { return { index, tree_size: this.entries.length, proof: inclusionProof(this._leaves(), index), leaf: entryLeafHash(this.entries[index]) }; }
  consistency(m) { return { first_size: m, second_size: this.entries.length, proof: consistencyProof(this._leaves(), m) }; }
}
// exported so other reference modules (e.g. pqinduct) verify inclusion against the SAME leaf/Merkle scheme
export { leafHash, entryLeafHash, verifyInclusion, verifyInclusionRFC, verifyConsistency, merkleRoot };
export function verifySTH(sth, logPub) {
  if (!sth || typeof sth !== 'object' || Array.isArray(sth)) return false; // TOTAL: fail-closed on malformed STH (fuzz-robustness)
  try {
    const core = utf8ToBytes(JSON.stringify({ tree_size: sth.tree_size, root: sth.root_hex, ts: sth.ts }));
    return ml_dsa87.verify(hexToBytes(sth.sig), core, logPub, { context: STH_CTX });
  } catch { return false; }
}

/* ---------- full bundle verify (fail-closed) ---------- */
export function verifyBundle(bundle, signerPub, logPub) {
  const FAIL = { verified: false, artifactOk: false, sthOk: false, incOk: false, leafBound: false, treeSizeOk: false };
  try { // TOTAL: fail-closed on any malformed bundle, never throw (fuzz-robustness)
    const { att, inclusion, sth } = bundle || {};
    if (!att || !inclusion || !sth) return FAIL;
    const artifactOk = verifyArtifact(att, signerPub);
    const sthOk = verifySTH(sth, logPub);
    // SECURITY (council fix): RECOMPUTE the leaf from att — never trust the caller-supplied leaf. Otherwise a valid
    // signed att could be paired with an inclusion proof for a DIFFERENT logged leaf and still "verify".
    const expectedLeaf = entryLeafHash(att);
    const leafBound = bytesToHex(expectedLeaf) === bytesToHex(inclusion.leaf);
    // HARDENING: require the inclusion's tree_size to match the SIGNED STH tree_size, and verify via RFC-6962
    // (directions derived from index/tree_size, length-checked) — a proof can't be replayed at another position/state.
    const treeSizeOk = inclusion.tree_size === sth.tree_size;
    const auditPath = (inclusion.proof || []).map((p) => p.sibling);
    const incOk = leafBound && treeSizeOk && verifyInclusionRFC(expectedLeaf, inclusion.index, sth.tree_size, auditPath, hexToBytes(sth.root_hex));
    return { verified: artifactOk && sthOk && incOk, artifactOk, sthOk, incOk, leafBound, treeSizeOk };
  } catch { return FAIL; }
}

/* ---------- self-test: node pqsign.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const signer = ml_dsa87.keygen(new Uint8Array(32).fill(1));
  const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(2));

  // sign 4 releases (power of two -> clean Merkle), log them
  const log = new PQTransparencyLog();
  const arts = [0, 1, 2, 3].map((i) => utf8ToBytes('release-binary-v1.' + i + ' contents'));
  const atts = arts.map((a, i) => signArtifact(a, signer.secretKey, { name: 'trelyan-cli', version: '1.0.' + i }, { ts: 1000 + i }));
  atts.forEach((a) => log.append(a));
  const sth = log.signedTreeHead(logKey.secretKey, { ts: 5000 });

  ok(verifyArtifact(atts[2], signer.publicKey) === true, 'artifact attestation verifies (ML-DSA-87)');
  ok(verifySTH(sth, logKey.publicKey) === true, 'signed tree head verifies');
  const inc = log.inclusion(2);
  const bundle = { att: atts[2], inclusion: inc, sth };
  ok(verifyBundle(bundle, signer.publicKey, logKey.publicKey).verified === true, 'full bundle verifies (sig + inclusion + STH)');

  // tamper the artifact -> digest changes -> attestation no longer matches a re-signed thing; verify the SIGNED att still binds the ORIGINAL digest
  const tamperedArt = signArtifact(utf8ToBytes('release-binary-v1.2 TAMPERED'), signer.secretKey, atts[2].meta, { ts: 1002 });
  ok(tamperedArt.artifact_sha256 !== atts[2].artifact_sha256, 'tampered artifact -> different digest (the signed digest pins the real bytes)');

  // forged signer (attacker key) -> attestation fails under the real signer pub
  const evil = ml_dsa87.keygen(new Uint8Array(32).fill(9));
  const forged = signArtifact(arts[2], evil.secretKey, atts[2].meta, { ts: 1002 });
  ok(verifyArtifact(forged, signer.publicKey) === false, 'attacker-signed attestation rejected under the real signer key');

  // forged STH (attacker log key) -> rejected
  const forgedSth = log.signedTreeHead(evil.secretKey, { ts: 5000 });
  ok(verifySTH(forgedSth, logKey.publicKey) === false, 'attacker-signed STH rejected under the real log key');

  // tamper the inclusion proof -> fails closed
  const badInc = { index: inc.index, leaf: inc.leaf, proof: inc.proof.map((p, i) => i === 0 ? { sibling: randomBytes(32), right: p.right } : p) };
  ok(verifyBundle({ att: atts[2], inclusion: badInc, sth }, signer.publicKey, logKey.publicKey).verified === false, 'tampered inclusion proof -> bundle FAILS');

  // an entry NOT in the log cannot produce a valid inclusion against this STH
  const outsider = signArtifact(utf8ToBytes('never-logged'), signer.secretKey, {}, { ts: 9999 });
  const outsiderLeaf = entryLeafHash(outsider);
  ok(verifyInclusion(outsiderLeaf, inc.proof, hexToBytes(sth.root_hex)) === false, 'unlogged artifact cannot forge inclusion');

  // CROSS-LEAF ATTACK (council regression): a valid att paired with a DIFFERENT member's
  // inclusion proof must FAIL because verifyBundle recomputes the leaf from att.
  const crossBundle = { att: atts[2], inclusion: log.inclusion(0), sth };
  const crossRes = verifyBundle(crossBundle, signer.publicKey, logKey.publicKey);
  ok(crossRes.verified === false && crossRes.leafBound === false, "valid att + another leaf's inclusion proof -> FAILS (leaf rebound to att)");

  // RFC-6962 INDEX/TREE-SIZE BINDING (hardening): the proof is bound to (index, tree_size).
  const ap = inc.proof.map((p) => p.sibling);
  ok(verifyInclusionRFC(inc.leaf, 2, sth.tree_size, ap, hexToBytes(sth.root_hex)) === true, 'RFC inclusion verifies at the correct (index=2, tree_size=4)');
  ok(verifyInclusionRFC(inc.leaf, 1, sth.tree_size, ap, hexToBytes(sth.root_hex)) === false, 'RFC inclusion FAILS at a wrong index (proof bound to position)');
  ok(verifyInclusionRFC(inc.leaf, 2, 3, ap, hexToBytes(sth.root_hex)) === false, 'RFC inclusion FAILS at a wrong tree_size (proof bound to tree state)');
  const tsMismatch = { att: atts[2], inclusion: { ...inc, tree_size: 3 }, sth };
  ok(verifyBundle(tsMismatch, signer.publicKey, logKey.publicKey).treeSizeOk === false, 'bundle rejects an inclusion tree_size != the signed STH tree_size');

  // non-power-of-two tree (5 leaves) exercises the lone-node/rightmost path — every member still verifies via RFC
  const log5 = new PQTransparencyLog();
  const atts5 = [0, 1, 2, 3, 4].map((i) => signArtifact(utf8ToBytes('art-' + i), signer.secretKey, { v: i }, { ts: 2000 + i }));
  atts5.forEach((a) => log5.append(a));
  const sth5 = log5.signedTreeHead(logKey.secretKey, { ts: 6000 });
  let all5 = true;
  for (let i = 0; i < 5; i++) { const b = { att: atts5[i], inclusion: log5.inclusion(i), sth: sth5 }; if (!verifyBundle(b, signer.publicKey, logKey.publicKey).verified) all5 = false; }
  ok(all5 === true, 'every member of a 5-leaf (non-power-of-2) tree verifies under RFC index/tree_size binding');

  // RFC-6962 §2.1.2 CONSISTENCY (append-only / no-rewrite): every prefix size m<=n is provably consistent with n
  const rootAt = (kk) => merkleRoot(log5.entries.slice(0, kk).map((a) => entryLeafHash(a)));
  let allCons = true;
  for (let m = 1; m <= 5; m++) { const c = log5.consistency(m); if (!verifyConsistency(m, 5, rootAt(m), rootAt(5), c.proof)) allCons = false; }
  ok(allCons === true, 'consistency proof verifies for every prefix m in 1..5 of a 5-leaf log (append-only)');
  // a FORKED history (different older root) must NOT verify as consistent
  ok(verifyConsistency(2, 5, sha256(utf8ToBytes('forged-old-root')), rootAt(5), log5.consistency(2).proof) === false, 'a forged older root -> consistency FAILS (rewrite/equivocation caught)');
  ok(verifyConsistency(3, 5, rootAt(3), sha256(utf8ToBytes('forged-new-root')), log5.consistency(3).proof) === false, 'a forged newer root -> consistency FAILS');
  ok(verifyConsistency(1, 0x100000000 + 1, rootAt(1), rootAt(5), []) === false, '32-bit guard: tree_size > 2^32 -> fail-closed (no silent truncation)');

  console.log('pqsign self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqsign\.mjs$/.test(process.argv[1] || '')) selfTest();
