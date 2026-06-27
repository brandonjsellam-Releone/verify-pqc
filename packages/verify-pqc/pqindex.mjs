/*!
 * pqindex — QDS-Ω verifiable post-quantum search-index core (reference, DRAFT, standalone).
 *
 * The ownable trust foundation of a decentralized PQ search engine: you can't be served a FORGED index.
 *   - hybridKEM      — ML-KEM-1024 + X25519, HKDF-SHA512 combiner (the QDS-Ω blueprint's KEM; sound).
 *   - signed index   — an inverted-index shard committed to a Merkle-DAG (SHA-512, Grover-hardened ≥512-bit)
 *                      and signed with ML-DSA-87 (FIPS 204) over the RECOMPUTED root (never the stored one).
 *   - inclusion proof— a client verifies that a term's exact postings are in the signed root WITHOUT trusting
 *                      the serving peer (the anti-forgery / search-result-provenance guarantee).
 *
 * BLUEPRINT CORRECTION (honest): the spec's dual_aead = AES-GCM ct XOR ChaCha20 ct is UNSOUND (XOR-ing two
 * independent AEAD outputs destroys both tags and isn't decryptable). The sound "dual" is a CASCADE
 * (encrypt-then-encrypt) or one AEAD keyed by the PQ-derived secret — use `dualSeal`/`dualOpen` below.
 * HONEST SCOPE: the browser-engine fusion, Tor onion routing, libp2p P2P, and internet-scale crawler are a
 * massive multi-team buildout; THIS module is the cryptographic index-integrity core. Self-test: node pqindex.mjs
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes, bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const KEM_INFO = utf8ToBytes('QDS-Omega-KEM-v1');
const SIG_CTX = utf8ToBytes('trelyan-qds-omega-index-root-v1'); // namespaced (council hygiene: all contexts trelyan-*)
const H = (...p) => sha512(concatBytes(...p));               // Grover-hardened 512-bit
const leafHash = (d) => H(Uint8Array.of(0), d);
const nodeHash = (l, r) => H(Uint8Array.of(1), l, r);
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const termLeaf = (t) => leafHash(utf8ToBytes(canon({ term: t.term, postings: t.postings })));

/* ---------- hybrid KEM: ML-KEM-1024 + X25519, HKDF-SHA512 (QDS-Ω blueprint) ---------- */
export function hybridKeygen() { const pq = ml_kem1024.keygen(); const cl = randomBytes(32); return { pq, cl: { sk: cl, pk: x25519.getPublicKey(cl) } }; }
export function hybridPub(kp) { return { pq_pk: bytesToHex(kp.pq.publicKey), cl_pk: bytesToHex(kp.cl.pk) }; }
export function hybridEncapsulate(peerPub) {
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(hexToBytes(peerPub.pq_pk));
  const eph = randomBytes(32), ephPub = x25519.getPublicKey(eph);
  const cl_ss = x25519.getSharedSecret(eph, hexToBytes(peerPub.cl_pk));
  const salt = randomBytes(64);
  const key = hkdf(sha512, concatBytes(sharedSecret, cl_ss), salt, KEM_INFO, 64); // attacker must break BOTH legs
  return { ct: { pq_ct: bytesToHex(cipherText), eph_pk: bytesToHex(ephPub), salt: bytesToHex(salt) }, key };
}
export function hybridDecapsulate(kp, ct) {
  const pq_ss = ml_kem1024.decapsulate(hexToBytes(ct.pq_ct), kp.pq.secretKey);
  const cl_ss = x25519.getSharedSecret(kp.cl.sk, hexToBytes(ct.eph_pk));
  return hkdf(sha512, concatBytes(pq_ss, cl_ss), hexToBytes(ct.salt), KEM_INFO, 64);
}

/* ---------- sound dual-AEAD: CASCADE (ChaCha20-Poly1305 then AES-256-GCM), not XOR ---------- */
export function dualSeal(key64, nonce24, aad, plaintext) {
  const k1 = key64.slice(0, 32), k2 = key64.slice(32, 64), n1 = nonce24.slice(0, 12), n2 = nonce24.slice(12, 24);
  const inner = chacha20poly1305(k1, n1, aad).encrypt(typeof plaintext === 'string' ? utf8ToBytes(plaintext) : plaintext);
  return gcm(k2, n2, aad).encrypt(inner); // encrypt-then-encrypt: an attacker must break BOTH ciphers
}
export function dualOpen(key64, nonce24, aad, ct) {
  const k1 = key64.slice(0, 32), k2 = key64.slice(32, 64), n1 = nonce24.slice(0, 12), n2 = nonce24.slice(12, 24);
  return chacha20poly1305(k1, n1, aad).decrypt(gcm(k2, n2, aad).decrypt(ct));
}

/* ---------- Merkle-DAG over the inverted-index shard ---------- */
function merkleRoot(leaves) {
  if (!leaves.length) return sha512(new Uint8Array());
  let lvl = leaves;
  while (lvl.length > 1) { const nx = []; for (let i = 0; i < lvl.length; i += 2) nx.push(i + 1 < lvl.length ? nodeHash(lvl[i], lvl[i + 1]) : lvl[i]); lvl = nx; }
  return lvl[0];
}
function inclusion(leaves, index) {
  const proof = []; let idx = index, lvl = leaves;
  while (lvl.length > 1) {
    const ps = idx - (idx % 2);
    if (ps + 1 < lvl.length) proof.push({ sib: bytesToHex(lvl[idx % 2 === 0 ? idx + 1 : idx - 1]), right: idx % 2 === 0 });
    const nx = []; for (let i = 0; i < lvl.length; i += 2) nx.push(i + 1 < lvl.length ? nodeHash(lvl[i], lvl[i + 1]) : lvl[i]);
    idx = Math.floor(idx / 2); lvl = nx;
  }
  return proof;
}
function verifyIncl(leaf, proof, root) {
  let h = leaf;
  for (const p of proof) h = p.right ? nodeHash(h, hexToBytes(p.sib)) : nodeHash(hexToBytes(p.sib), h);
  return bytesToHex(h) === bytesToHex(root);
}
// HARDENED (RFC-6962 §2.1.1): directions DERIVED from (index, treeSize), proof length checked — binds the proof to
// one position in a tree of exactly that size (a forged-position proof mismatches the signed root). auditPath = hex sibs.
function verifyInclRFC(leaf, index, treeSize, auditPath, root) {
  if (!(index >= 0 && index < treeSize)) return false;
  if (treeSize > 0xFFFFFFFF) return false; // fail-closed above 2^32 leaves (32-bit shift math) — production needs BigInt
  let fn = index, sn = treeSize - 1, r = leaf;
  for (const sibHex of auditPath) {
    if (sn === 0) return false;
    const sib = hexToBytes(sibHex);
    if ((fn & 1) === 1 || fn === sn) { r = nodeHash(sib, r); while ((fn & 1) === 0 && fn !== 0) { fn >>>= 1; sn >>>= 1; } }
    else { r = nodeHash(r, sib); }
    fn >>>= 1; sn >>>= 1;
  }
  return sn === 0 && bytesToHex(r) === bytesToHex(root);
}
const sortedTerms = (terms) => terms.slice().sort((a, b) => (a.term < b.term ? -1 : a.term > b.term ? 1 : 0));

/* ---------- build + sign + verify the shard ---------- */
// COMPARATOR (council/DeepSeek): canonical order = byte-wise comparison of the UTF-16-code-unit JS string (`<`), used
// IDENTICALLY by builder + verifier — an independent impl MUST match it (no locale/Unicode-normalization collation).
// The signature binds {merkle_root, tree_size, version, term_range, ts} (council/DeepSeek #5: anti-replay + tree-size +
// cross-shard confusion; tamper-binding harness: `ts` MUST be signed — an unsigned timestamp is malleable). HONEST
// SCOPE (DeepSeek+Grok): signing `ts` gives INTEGRITY (the timestamp can't be rewritten), NOT anti-rollback by itself —
// a whole older, still-validly-signed shard can be replayed. Anti-rollback needs an EXTERNAL fresh checkpoint (a
// trusted signed head / fresh STH / gossip-checked `version` monotonicity), same freshness obligation as pqkt/pqvault.
const SHARD_CORE = (s) => canon({ v: 'pqindex-shard-v1', merkle_root: s.merkle_root, tree_size: s.tree_size, version: s.version, term_range: s.term_range, ts: s.ts ?? null });
const hasDupTerm = (sorted) => { for (let i = 1; i < sorted.length; i++) if (sorted[i].term === sorted[i - 1].term) return true; return false; };
export function buildSignedShard({ term_range, terms, version = 1 }, indexSecret, indexPub, opts = {}) {
  const sorted = sortedTerms(terms);
  if (hasDupTerm(sorted)) throw new Error('duplicate term in shard (inverted-index terms must be unique; merge postings first)'); // council/Grok
  const meta = { term_range, version, tree_size: sorted.length, merkle_root: bytesToHex(merkleRoot(sorted.map(termLeaf))), ts: opts.ts ?? null };
  const sig = ml_dsa87.sign(utf8ToBytes(SHARD_CORE(meta)), indexSecret, { context: SIG_CTX });
  return { ...meta, terms: sorted, signer_pub: bytesToHex(indexPub), sig: bytesToHex(sig) };
}
// verify: RECOMPUTE the root from RE-SORTED terms (enforces the SORTED invariant + binds postings), check no dups,
// tree_size matches, and the signature over the bound metadata under the pinned signer. This is what makes absence
// proofs sound (a malicious indexer can't sign an out-of-order tree — the recompute wouldn't match).
export function verifyShard(shard, trustedSignerPub) {
  try { // TOTAL (fuzz): fail-closed on any malformed shard
    if (!shard || typeof shard !== 'object' || !Array.isArray(shard.terms) || typeof shard.merkle_root !== 'string' || typeof shard.sig !== 'string' || typeof shard.signer_pub !== 'string') return { verified: false, reason: 'malformed shard' };
    const sorted = sortedTerms(shard.terms);
    const dupOk = !hasDupTerm(sorted);
    const recomputed = bytesToHex(merkleRoot(sorted.map(termLeaf)));
    const rootBound = recomputed === shard.merkle_root && shard.tree_size === sorted.length && dupOk;
    const pinned = !trustedSignerPub || shard.signer_pub.toLowerCase() === bytesToHex(trustedSignerPub).toLowerCase();
    let sigOk = false;
    try { sigOk = ml_dsa87.verify(hexToBytes(shard.sig), utf8ToBytes(SHARD_CORE(shard)), hexToBytes(shard.signer_pub), { context: SIG_CTX }); } catch { sigOk = false; }
    const verified = rootBound && pinned && sigOk;
    return { verified, rootBound, pinned, sigOk, dupOk, reason: verified ? 'shard verified (sorted root recomputed + tree_size/version/range bound, pinned signer)' : !dupOk ? 'duplicate terms' : !rootBound ? 'root/tree_size mismatch (tampered/unsorted)' : !pinned ? 'not the pinned index key' : 'ML-DSA-87 signature invalid' };
  } catch { return { verified: false, reason: 'malformed shard' }; }
}
// a client proves a term's exact postings are in the signed root WITHOUT trusting the serving peer.
export function termInclusionProof(shard, term) {
  const ts = sortedTerms(shard.terms); const idx = ts.findIndex((t) => t.term === term);
  if (idx < 0) return null;
  // index + tree_size carried so the verifier can RFC-bind the proof to this exact position/tree size
  return { term, postings: ts[idx].postings, index: idx, tree_size: ts.length, leaf: bytesToHex(termLeaf(ts[idx])), proof: inclusion(ts.map(termLeaf), idx) };
}
export function verifyTermInclusion(merkleRootHex, proofObj) {
  try { // TOTAL (fuzz): fail-closed on any malformed proof
    if (!proofObj || typeof proofObj !== 'object' || typeof merkleRootHex !== 'string') return false;
    const leaf = termLeaf({ term: proofObj.term, postings: proofObj.postings });
    if (bytesToHex(leaf) !== proofObj.leaf) return false;
    const auditPath = (proofObj.proof || []).map((p) => p.sib);
    return verifyInclRFC(leaf, proofObj.index, proofObj.tree_size, auditPath, hexToBytes(merkleRootHex));
  } catch { return false; }
}

/* ---------- ABSENCE / non-omission proof: "no results for this term" can't be a lie ---------- */
// The index is a Merkle tree over LEXICOGRAPHICALLY SORTED terms. A term's absence is proven by its two present
// neighbors being ADJACENT (consecutive indices ⇒ nothing sorts between them) and the term sorting strictly between.
// Combined with the can't-forge inclusion proof, this gives "can't forge AND can't omit/censor".
export function absenceProof(shard, term) {
  const ts = sortedTerms(shard.terms);
  if (ts.some((t) => t.term === term)) return null; // present — no absence proof exists
  const leaves = ts.map(termLeaf);
  let predIdx = -1, succIdx = -1;
  for (let i = 0; i < ts.length; i++) { if (ts[i].term < term) predIdx = i; else { succIdx = i; break; } }
  const mk = (idx) => (idx < 0 ? null : { term: ts[idx].term, postings: ts[idx].postings, index: idx, tree_size: ts.length, leaf: bytesToHex(termLeaf(ts[idx])), proof: inclusion(leaves, idx) });
  return { term, tree_size: ts.length, pred: mk(predIdx), succ: succIdx < 0 ? null : mk(succIdx) };
}
export function verifyAbsence(merkleRootHex, proofObj) {
 try { // TOTAL (fuzz): a throwing getter/Proxy on a proof field fails CLOSED (false), never DoS
  const { term, pred, succ, tree_size } = proofObj || {};
  if (typeof term !== 'string' || typeof tree_size !== 'number' || tree_size < 1) return false; // empty index: verify tree_size 0 separately
  const inclOk = (nb) => !!nb && nb.tree_size === tree_size && verifyTermInclusion(merkleRootHex, nb);
  if (pred && succ) return succ.index === pred.index + 1 && pred.term < term && term < succ.term && inclOk(pred) && inclOk(succ); // adjacent neighbors bracket the term
  if (!pred && succ) return succ.index === 0 && term < succ.term && inclOk(succ);             // term sorts before the first entry
  if (pred && !succ) return pred.index === tree_size - 1 && pred.term < term && inclOk(pred);  // term sorts after the last entry
  return false;
 } catch { return false; }
}
// SOUND absence (council/Grok): ties the proof to a verifyShard-validated shard — which RECOMPUTES the root from the
// SORTED terms (so the global sort order is cryptographically enforced) + binds tree_size (anti-replay). Use THIS in
// production; bare verifyAbsence(root, …) only holds atop an already-validated sorted root.
export function verifyAbsenceInShard(shard, proofObj, trustedSignerPub) {
 try { // TOTAL (fuzz): a throwing getter/Proxy on a proof field fails CLOSED (false), never DoS
  if (!verifyShard(shard, trustedSignerPub).verified) return false;
  if (!proofObj || proofObj.tree_size !== shard.tree_size) return false;
  if (proofObj.pred && proofObj.pred.tree_size !== shard.tree_size) return false;
  if (proofObj.succ && proofObj.succ.tree_size !== shard.tree_size) return false;
  return verifyAbsence(shard.merkle_root, proofObj);
 } catch { return false; }
}

/* ---------- self-test: node pqindex.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // 1. hybrid KEM round-trip (ML-KEM-1024 + X25519) -> both sides derive the same 64-byte key
  const bob = hybridKeygen();
  const { ct, key } = hybridEncapsulate(hybridPub(bob));
  const key2 = hybridDecapsulate(bob, ct);
  ok(bytesToHex(key) === bytesToHex(key2) && key.length === 64, 'hybrid KEM: encaps/decaps derive the same key');
  const other = hybridKeygen();
  ok(bytesToHex(hybridDecapsulate(other, ct)) !== bytesToHex(key), 'hybrid KEM: a different keypair derives a different key');

  // 2. sound dual-AEAD cascade round-trips; tamper fails
  const dk = randomBytes(64), dn = randomBytes(24);
  const sealed = dualSeal(dk, dn, utf8ToBytes('aad'), 'index payload');
  ok(new TextDecoder().decode(dualOpen(dk, dn, utf8ToBytes('aad'), sealed)) === 'index payload', 'dual-AEAD cascade: seal/open round-trip');
  let tamperFail = false; const bad = sealed.slice(); bad[0] ^= 1; try { dualOpen(dk, dn, utf8ToBytes('aad'), bad); } catch { tamperFail = true; }
  ok(tamperFail, 'dual-AEAD: tampered ciphertext rejected (both tags intact, unlike the XOR blueprint)');

  // 3. signed index shard
  const idx = ml_dsa87.keygen(new Uint8Array(32).fill(7));
  const terms = [
    { term: 'quantum', postings: [{ doc_cid: 'bafy...a', tf: 5, pagerank: 0.9 }, { doc_cid: 'bafy...b', tf: 2, pagerank: 0.4 }] },
    { term: 'cryptography', postings: [{ doc_cid: 'bafy...c', tf: 3, pagerank: 0.7 }] },
    { term: 'search', postings: [{ doc_cid: 'bafy...d', tf: 8, pagerank: 0.6 }] },
    { term: 'lattice', postings: [{ doc_cid: 'bafy...e', tf: 1, pagerank: 0.3 }] },
  ];
  const shard = buildSignedShard({ term_range: ['a', 'z'], terms }, idx.secretKey, idx.publicKey, { ts: 1000 });
  ok(verifyShard(shard, idx.publicKey).verified === true, 'signed shard verifies (root recomputed + ML-DSA-87 sig + pinned key)');

  // 4. tampered postings -> recomputed root mismatch -> FAIL
  const tampered = JSON.parse(JSON.stringify(shard)); tampered.terms.find((t) => t.term === 'quantum').postings[0].tf = 999;
  ok(verifyShard(tampered, idx.publicKey).rootBound === false, 'tampered postings -> rootBound false (forged index caught)');

  // 5. wrong signer pinned -> FAIL
  ok(verifyShard(shard, ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey).verified === false, 'shard under a non-pinned index key -> NOT verified');

  // 6. term inclusion proof: a client verifies a term's postings against the signed root without trusting the peer
  const pf = termInclusionProof(shard, 'cryptography');
  ok(pf && verifyTermInclusion(shard.merkle_root, pf) === true, 'term inclusion proof verifies against the signed root');
  // 7. a peer that forges a posting cannot produce a valid inclusion proof
  const forged = { ...pf, postings: [{ doc_cid: 'evil', tf: 1, pagerank: 1 }] };
  ok(verifyTermInclusion(shard.merkle_root, forged) === false, 'forged postings -> inclusion proof FAILS (cannot serve a forged result)');

  // 7b. RFC index/tree_size BINDING: a position/size-substituted proof fails (proof bound to its slot)
  ok(verifyTermInclusion(shard.merkle_root, { ...pf, index: (pf.index + 1) % 4 }) === false, 'wrong index in the proof -> FAILS (RFC position binding)');
  ok(verifyTermInclusion(shard.merkle_root, { ...pf, tree_size: pf.tree_size + 1 }) === false, 'wrong tree_size in the proof -> FAILS (RFC tree-state binding)');

  // 7c. non-power-of-2 shard (5 terms) — every term still proves inclusion under RFC binding
  const terms5 = ['alpha', 'bravo', 'charlie', 'delta', 'echo'].map((t, i) => ({ term: t, postings: [{ doc_cid: 'd' + i, tf: i + 1, pagerank: 0.1 * i }] }));
  const shard5 = buildSignedShard({ term_range: ['a', 'z'], terms: terms5 }, idx.secretKey, idx.publicKey, { ts: 1001 });
  let all5 = true; for (const t of terms5) { const p = termInclusionProof(shard5, t.term); if (!verifyTermInclusion(shard5.merkle_root, p)) all5 = false; }
  ok(all5 === true, 'every term of a 5-term (non-power-of-2) shard verifies under RFC binding');

  // 8. ABSENCE / non-omission via the SOUND path (verifyAbsenceInShard ties to verifyShard's sorted-root + sig + pin)
  const ap = absenceProof(shard, 'matrix'); // sorts between lattice(1) and quantum(2)
  ok(ap && verifyAbsenceInShard(shard, ap, idx.publicKey) === true, 'absence of "matrix" proven (sound, shard-validated) via lattice<matrix<quantum');
  ok(verifyAbsenceInShard(shard, absenceProof(shard, 'aardvark'), idx.publicKey) === true, 'absence before the first term (succ index 0) verifies');
  ok(verifyAbsenceInShard(shard, absenceProof(shard, 'zzz'), idx.publicKey) === true, 'absence after the last term (pred index tree_size-1) verifies');
  ok(absenceProof(shard, 'quantum') === null, 'no absence proof exists for a PRESENT term');
  // 8b. CENSORSHIP attack: prove a PRESENT term ("quantum") absent via NON-adjacent neighbors -> rejected (adjacency)
  const lattice = termInclusionProof(shard, 'lattice'), search = termInclusionProof(shard, 'search'); // indices 1 and 3 (not adjacent)
  ok(verifyAbsenceInShard(shard, { term: 'quantum', tree_size: 4, pred: lattice, succ: search }, idx.publicKey) === false, 'forged absence of a present term (non-adjacent neighbors) -> REJECTED');
  // 8c. tampered neighbor -> absence FAILS
  const tamperedAbs = JSON.parse(JSON.stringify(ap)); tamperedAbs.succ.index = 3;
  ok(verifyAbsenceInShard(shard, tamperedAbs, idx.publicKey) === false, 'tampered neighbor (broken adjacency) -> absence FAILS');
  // 8d. council/Grok: duplicate terms rejected at build
  let dupThrew = false; try { buildSignedShard({ term_range: ['a', 'z'], terms: [{ term: 'x', postings: [] }, { term: 'x', postings: [] }] }, idx.secretKey, idx.publicKey); } catch { dupThrew = true; }
  ok(dupThrew, 'duplicate terms in a shard -> buildSignedShard THROWS (absence-adjacency invariant preserved)');
  // 8e. council/DeepSeek: tree_size is SIGNED -> tampering it (replay/confusion) fails verifyShard
  ok(verifyShard({ ...shard, tree_size: shard.tree_size + 1 }, idx.publicKey).verified === false, 'tampered tree_size -> verifyShard FAILS (tree_size is bound into the signature)');

  console.log('pqindex self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqindex\.mjs$/.test(process.argv[1] || '')) selfTest();
