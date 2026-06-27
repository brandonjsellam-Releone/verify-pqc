/*!
 * spine-vectors — reproducible, PINNED test vectors for the TRELYAN transparency SPINE (audit-turnkey).
 *
 * The spine (pqsign RFC-6962 Merkle log: leaf=SHA-256(0x00‖data), node=SHA-256(0x01‖L‖R); STH=ML-DSA-87 over
 * {tree_size,root,ts}; inclusion §2.1.1 + consistency §2.1.2, index/tree_size-bound) is the shared root of trust for
 * pqtsa / pqkt / pqvault / pqinduct. These vectors freeze its byte-level outputs over a fixed 7-leaf (non-power-of-2)
 * tree so an INDEPENDENT auditor implementation must reproduce the same hex — and any drift in ours fails CI.
 *
 * Vectors are PINNED (computed once, then frozen). The self-test (a) recomputes from pqsign and asserts equality with
 * the pinned hex, and (b) checks inclusion+consistency verify for every index/prefix. Self-test: node spine-vectors.mjs
 */
import { PQTransparencyLog, verifySTH, leafHash, entryLeafHash, verifyInclusionRFC, verifyConsistency, merkleRoot } from './pqsign.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// fixed inputs (deterministic): 7 leaves "spine-leaf-0".."spine-leaf-6"; STH key seeded with 0x2A*32; STH ts=1700000000.
const N = 7;
const ENTRIES = Array.from({ length: N }, (_, i) => ({ v: 'spine-leaf-' + i }));
const STH_SEED = new Uint8Array(32).fill(0x2a);
const STH_TS = 1700000000;

function buildLog() { const log = new PQTransparencyLog(); ENTRIES.forEach((e) => log.append(e)); return log; }
const leafHexOf = (e) => bytesToHex(entryLeafHash(e));
const rootAt = (k) => bytesToHex(merkleRoot(ENTRIES.slice(0, k).map((e) => entryLeafHash(e))));

// ---- PINNED VECTORS (frozen; an independent RFC-6962 impl over the same leaves MUST reproduce these) ----
const PINNED = {
  leaf0: '78446ff5824bbf7dd6588ce5302c486d4c257a17aa069feb72ab3ae40679e2b9', // SHA-256(0x00 ‖ JSON({"v":"spine-leaf-0"}))
  root3: 'e5f07204a1ec94dc8455da4ddc1baa5d284183c6f56f5b753c152dd7036770b3',
  root4: 'a4bbdc3e740a5221ec12f3f89985d3e3cbe0fc09175e7a6f385b7acc27c3d47c',
  root7: '85d5836f9c9ef2cadecebe28ac90ac9f8c2d5ec889418465504faefdbd2d3bc6', // == the signed STH root @ tree_size 7
  // PROOF-BYTE vectors (council: pin the actual arrays, not just roots) — index-3 audit path + 3→7 consistency proof:
  incProof3: ['1c46cb1319f06e3792e1d1aca26f83725fc7b593aef3339fc670ad217b196b36', 'f1c2f94135dbd97f74283f7325058661ef1702abe5c40e7c0a40b473926fca47', 'ea1cc25387dbe6ea4f59718cd2ad12bfd63e0c99ca5564a2a1e89c05273bac94'],
  consProof3to7: ['1c46cb1319f06e3792e1d1aca26f83725fc7b593aef3339fc670ad217b196b36', 'f85a2961a464cb195bd91b2b12664b86a77e85324694c6f61776095fc796d45b', 'f1c2f94135dbd97f74283f7325058661ef1702abe5c40e7c0a40b473926fca47', 'ea1cc25387dbe6ea4f59718cd2ad12bfd63e0c99ca5564a2a1e89c05273bac94'],
};

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const log = buildLog();
  const sth = log.signedTreeHead(ml_dsa87.keygen(STH_SEED).secretKey, { ts: STH_TS });
  const root7 = rootAt(7);

  // (a) inclusion verifies for EVERY index under the signed STH
  let incAll = true;
  for (let i = 0; i < N; i++) {
    const inc = log.inclusion(i);
    const expectedLeaf = entryLeafHash(ENTRIES[i]);
    if (!verifyInclusionRFC(expectedLeaf, inc.index, sth.tree_size, inc.proof.map((p) => p.sibling), Uint8Array.from(sth.root_hex.match(/../g).map((h) => parseInt(h, 16))))) incAll = false;
  }
  ok(incAll, 'inclusion proof verifies for every index 0..6 of the 7-leaf tree');

  // (b) consistency verifies for every prefix m -> 7
  let consAll = true;
  for (let m = 1; m <= N; m++) {
    const c = log.consistency(m);
    if (!verifyConsistency(m, N, Uint8Array.from(rootAt(m).match(/../g).map((h) => parseInt(h, 16))), Uint8Array.from(root7.match(/../g).map((h) => parseInt(h, 16))), c.proof)) consAll = false;
  }
  ok(consAll, 'consistency proof verifies for every prefix m=1..7 -> 7');

  // (c) STH signature verifies under the pinned seed key
  ok(verifySTH(sth, ml_dsa87.keygen(STH_SEED).publicKey) === true, 'STH (tree_size 7) verifies under the seed-pinned key');

  // (d) PINNED equality — drift detection + cross-impl anchor
  if (PINNED.root7 !== 'PIN_ME') {
    ok(root7 === PINNED.root7, 'root@7 matches the pinned vector');
    ok(rootAt(3) === PINNED.root3, 'root@3 matches the pinned vector');
    ok(rootAt(4) === PINNED.root4, 'root@4 matches the pinned vector');
    ok(leafHexOf(ENTRIES[0]) === PINNED.leaf0, 'leaf[0] hash matches the pinned vector');
  }

  const hx = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
  const r7b = hx(root7);

  // (e) PROOF-BYTE vectors (council: roots alone are insufficient — pin the actual audit-path + consistency arrays).
  const inc3 = log.inclusion(3);
  const incProof3 = inc3.proof.map((p) => bytesToHex(p.sibling));   // index-3 audit path, leaf→root
  const consProof3to7 = log.consistency(3).proof.map((p) => bytesToHex(p)); // 3→7 consistency proof
  if (PINNED.incProof3) {
    ok(JSON.stringify(incProof3) === JSON.stringify(PINNED.incProof3), 'index-3 inclusion audit-path matches the pinned byte vector');
    ok(JSON.stringify(consProof3to7) === JSON.stringify(PINNED.consProof3to7), '3→7 consistency proof matches the pinned byte vector');
  }

  // (f) NEGATIVE vectors — a wrong index / tampered sibling / wrong tree_size MUST fail (fail-closed).
  ok(verifyInclusionRFC(entryLeafHash(ENTRIES[3]), 2, 7, inc3.proof.map((p) => p.sibling), r7b) === false, 'NEG: index-3 leaf claimed at index 2 -> inclusion FAILS');
  const tamperedPath = inc3.proof.map((p, i) => (i === 0 ? hx('00'.repeat(32)) : p.sibling));
  ok(verifyInclusionRFC(entryLeafHash(ENTRIES[3]), 3, 7, tamperedPath, r7b) === false, 'NEG: tampered audit-path sibling -> inclusion FAILS');
  ok(verifyConsistency(3, 7, hx(rootAt(3)), r7b, []) === false, 'NEG: consistency with an empty proof (m≠n) -> FAILS');

  // (g) EDGE tree sizes 1, 2, 8 (power-of-two + minimal) — every index inclusion + every prefix consistency verifies.
  let edgeAll = true;
  for (const sz of [1, 2, 8]) {
    const lg = new PQTransparencyLog(); for (let i = 0; i < sz; i++) lg.append({ v: 'edge-' + sz + '-' + i });
    const er = hx(bytesToHex(merkleRoot(lg.entries.map((e) => entryLeafHash(e)))));
    for (let i = 0; i < sz; i++) { const inc = lg.inclusion(i); if (!verifyInclusionRFC(entryLeafHash(lg.entries[i]), i, sz, inc.proof.map((p) => p.sibling), er)) edgeAll = false; }
    for (let m = 1; m <= sz; m++) { const pr = lg.consistency(m).proof; const rm = hx(bytesToHex(merkleRoot(lg.entries.slice(0, m).map((e) => entryLeafHash(e))))); if (!verifyConsistency(m, sz, rm, er, pr)) edgeAll = false; }
  }
  ok(edgeAll, 'edge tree sizes 1, 2, 8 (incl. power-of-two): inclusion + consistency verify for every index/prefix');

  // emit the vectors (so they can be frozen + handed to an auditor)
  console.log('VECTORS ' + JSON.stringify({ leaf0: leafHexOf(ENTRIES[0]), root3: rootAt(3), root4: rootAt(4), root7, sth_root: sth.root_hex, incProof3, consProof3to7 }));
  console.log('spine-vectors self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /spine-vectors\.mjs$/.test(process.argv[1] || '')) selfTest();
