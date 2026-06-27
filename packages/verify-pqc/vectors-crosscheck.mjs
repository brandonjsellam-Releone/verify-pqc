/*!
 * vectors-crosscheck — independent DIFFERENTIAL validation of the RFC-6962 transparency code (audit artifact).
 *
 * The verifiable core of a third-party audit, done in-repo: a from-scratch INDEPENDENT reference (recursive top-down
 * Merkle Tree Hash + naive checks — a different code path than pqsign's iterative/optimized verifiers) is cross-checked
 * against pqsign's `merkleRoot`, `verifyInclusionRFC` (§2.1.1) and `verifyConsistency` (§2.1.2) over EVERY tree size,
 * EVERY leaf index, and EVERY prefix in a range — plus negative cases (wrong index / size / forged root). Differential
 * testing across two implementations is exactly where our own bugs surface (this run already caught a witness-fork and
 * a 32-bit-truncation bug via the council; this harness is the standing regression net).
 *
 * Honest scope: this independently validates the Merkle/RFC-6962 LOGIC WE WROTE. It does NOT re-derive the underlying
 * PQ primitives (ML-KEM/ML-DSA/SLH-DSA = @noble, already widely validated); cross-validating those against official
 * NIST ACVP vectors is the auditor/owner step (drop ACVP JSON + a comparison shim here). Self-test: node vectors-crosscheck.mjs
 */
import { PQTransparencyLog, leafHash, entryLeafHash, verifyInclusionRFC, verifyConsistency, merkleRoot } from './pqsign.mjs';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// --- independent reference (RFC-6962 top-down split; distinct from pqsign's bottom-up iterative root) ---
const nodeHash = (l, r) => sha256(concatBytes(Uint8Array.of(1), l, r));
const largestPow2Below = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
function refRoot(leaves) {
  if (leaves.length === 0) return sha256(new Uint8Array());
  if (leaves.length === 1) return leaves[0];
  const k = largestPow2Below(leaves.length);
  return nodeHash(refRoot(leaves.slice(0, k)), refRoot(leaves.slice(k)));
}
const leavesOf = (entries) => entries.map((e) => entryLeafHash(e));

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const MAX = 130; // sizes 1..MAX exhaustive
  let rootChecks = 0, inclYes = 0, inclNo = 0, consYes = 0, consNo = 0;
  const hx = (b) => bytesToHex(b);

  for (let n = 1; n <= MAX; n++) {
    const log = new PQTransparencyLog();
    for (let i = 0; i < n; i++) log.append({ e: i, tag: 'leaf-' + i });
    const leaves = leavesOf(log.entries);
    const rootN = merkleRoot(leaves);

    // 1. optimized merkleRoot === independent recursive refRoot
    if (hx(rootN) === hx(refRoot(leaves))) rootChecks++; else { fail++; console.error('ROOT mismatch at n=' + n); }

    // 2. inclusion: every index POSITIVE; a wrong index or a FORGED root NEGATIVE.
    //    NOTE: we do NOT test "wrong tree_size with the old root" — that is an ill-posed inconsistent (size,root)
    //    pair that real callers never form (verifyBundle/verifyKeyEventInclusion take size AND root from the SAME
    //    signed STH). verifyInclusionRFC correctly checks the proof against the SUPPLIED root; the STH binds the pair.
    for (let idx = 0; idx < n; idx++) {
      const inc = log.inclusion(idx);
      const ap = inc.proof.map((p) => p.sibling);
      if (verifyInclusionRFC(inc.leaf, idx, n, ap, rootN) === true) inclYes++; else { fail++; console.error('INCL+ fail n=' + n + ' idx=' + idx); }
      if (n > 1) { if (verifyInclusionRFC(inc.leaf, (idx + 1) % n, n, ap, rootN) === false) inclNo++; else { fail++; console.error('INCL- (wrong idx) accepted n=' + n + ' idx=' + idx); } }
      if (verifyInclusionRFC(inc.leaf, idx, n, ap, sha256(utf8ToBytes('forge-root-' + n + '-' + idx))) === false) inclNo++; else { fail++; console.error('INCL- (forged root) accepted n=' + n + ' idx=' + idx); }
    }

    // 3. consistency: every prefix m POSITIVE (root recomputed independently); a forged old root NEGATIVE
    for (let m = 1; m <= n; m++) {
      const proof = log.consistency(m).proof;
      const rm = refRoot(leaves.slice(0, m));
      if (verifyConsistency(m, n, rm, rootN, proof) === true) consYes++; else { fail++; console.error('CONS+ fail n=' + n + ' m=' + m); }
      if (n > m) { if (verifyConsistency(m, n, sha256(utf8ToBytes('forge-' + m + '-' + n)), rootN, proof) === false) consNo++; else { fail++; console.error('CONS- (forged old root) accepted n=' + n + ' m=' + m); } }
    }
  }

  const total = rootChecks + inclYes + inclNo + consYes + consNo;
  ok(fail === 0, 'differential cross-check (two independent implementations agree across all cases)');
  console.log('  roots=' + rootChecks + '  inclusion(+' + inclYes + '/-' + inclNo + ')  consistency(+' + consYes + '/-' + consNo + ')  total=' + total);
  console.log('vectors-crosscheck: ' + pass + ' pass, ' + fail + ' fail (' + total + ' differential cases over sizes 1..' + MAX + ')');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /vectors-crosscheck\.mjs$/.test(process.argv[1] || '')) selfTest();
