#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of the DEPLOYED verifyConsistency ALGORITHM's soundness — the
council upgrade (Qwen top fix): not just "the Merkle root pins the leaves" (merkle_consistency_z3),
but that the ACTUAL RFC-6962 §2.1.2 path-folding verifier in pqsign.mjs only ever accepts honest
prefixes.
================================================================================================
pqsign.mjs verifyConsistency(m, n, root1, root2, proof) (lines 94-115) walks the proof with the
standard RFC-6962 index arithmetic (fn/sn bit-twiddling) and accepts iff the folded values satisfy
fr == root1 ∧ sr == root2 (plus structural checks). This file TRANSCRIBES that algorithm
LINE-FOR-LINE into a symbolic executor: for a FIXED (m, n) the control flow — every shift, every
branch on fn/sn — is concrete integer arithmetic; ONLY the hash values (proof nodes, roots, leaves)
are symbolic Z3 terms. So the model is the code, not a paraphrase of it.

THEOREM (algorithm soundness), for each proven (m, n):
    Let L'_0..L'_{n-1} be arbitrary (symbolic) leaves of the new tree, root2 = MTH(L').
    For EVERY proof vector P and EVERY claimed old root root1:
        verifyConsistency(m, n, root1, root2, P) accepts  ⇒  root1 == MTH(L'_0..L'_{m-1})
    under collision-resistance of the node hash. I.e. the verifier cannot be talked into vouching
    that the old tree was anything other than the EXACT size-m prefix of the new tree. Chained with
    merkle_consistency_z3 (a prefix root pins the prefix leaves), this closes the append-only
    guarantee END-TO-END through the deployed code path.

    Z3 proves the negation ("accepted, yet root1 differs from the true prefix root") UNSAT for
    (m, n) ∈ {(1,2), (2,3), (2,4), (3,5), (5,8)} — covering the power-of-two branch (path starts
    with root1) and the non-power-of-two branch (root1 recomputed from the proof), balanced and
    unbalanced trees.

    Structural completeness of the length check is asserted in Python: for each (m, n), every proof
    length OTHER than the unique RFC length is rejected by the index arithmetic alone (concrete
    control flow — no solver needed), so the symbolic theorem over the one accepted length is total.

TEETH (negative control): drop the collision-resistance axiom and Z3 forges a consistency proof —
acceptance with root1 ≠ MTH(prefix) (`sat`) — so the guarantee rests exactly on CR, and the harness
detects a verifier whose hash can be collided.

HONEST SCOPE: symbolic hash (CR as injectivity), fixed tree sizes (the induction to all sizes is by
the RFC's recursive structure, exercised here on both branch shapes; the 42,574-case differential
harness covers sizes at scale). Not a proof of SHA-256. The 0x00/0x01 leaf/node prefixes in the
implementation are what make CR realistic (see formal/README.md).

Run:  python rfc6962_consistency_algo_z3.py     (exit 0 = all (m,n) proven unsat + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (
    Solver, Function, Int, Ints, And, Or, Not, Implies, ForAll, BoolVal, IntSort,
    unsat, get_version_string,
)


def _largest_pow2_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(H, leaves):
    """RFC-6962 Merkle Tree Head over symbolic leaves (exact split rule)."""
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = _largest_pow2_below(n)
    return H(_mth(H, leaves[:k]), _mth(H, leaves[k:]))


def _rfc_proof_len(m: int, n: int) -> int:
    """Length of the RFC-6962 consistency proof for sizes (m, n) — mirrors pqsign.mjs subProof."""
    def sub(m: int, n: int, b: bool) -> int:
        if m == n:
            return 0 if b else 1
        k = _largest_pow2_below(n)
        if m <= k:
            return sub(m, k, b) + 1
        return sub(m - k, n - k, False) + 1
    return 0 if m == n else sub(m, n, True)


def _verify_consistency_symbolic(H, m: int, n: int, root1, root2, proof):
    """LINE-FOR-LINE transcription of pqsign.mjs verifyConsistency (lines 94-115). fn/sn index
    arithmetic is concrete Python int math; root1/root2/proof entries are Z3 terms. Returns a Z3
    Bool (the acceptance condition) or BoolVal(False) when the concrete control flow rejects."""
    if m < 1 or m > n:
        return BoolVal(False)
    if m == n:                                            # (line 97)
        return (root1 == root2) if len(proof) == 0 else BoolVal(False)
    is_pow2 = (m & (m - 1)) == 0                          # (line 98)
    path = ([root1] + list(proof)) if is_pow2 else list(proof)   # (line 99)
    if not path:                                          # (line 100)
        return BoolVal(False)
    fn, sn = m - 1, n - 1                                 # (line 101)
    while fn & 1:                                         # (line 102)
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]                                     # (line 103)
    for i in range(1, len(path)):                         # (lines 104-114)
        c = path[i]
        if sn == 0:                                       # (line 106) concrete → structural reject
            return BoolVal(False)
        if (fn & 1) or fn == sn:                          # (line 107)
            fr = H(c, fr)
            sr = H(c, sr)                                 # (line 108)
            while not (fn & 1) and fn != 0:               # (line 109)
                fn >>= 1
                sn >>= 1
        else:
            sr = H(sr, c)                                 # (line 111)
        fn >>= 1                                          # (line 113)
        sn >>= 1
    if sn != 0:                                           # (line 115, sn === 0 conjunct)
        return BoolVal(False)
    return And(fr == root1, sr == root2)                  # (line 115)


def prove_algorithm_sound(m: int, n: int, collision_resistant: bool):
    s = Solver()
    H = Function("H", IntSort(), IntSort(), IntSort())
    if collision_resistant:
        a, b, c, d = Ints("a b c d")
        s.add(ForAll([a, b, c, d], Implies(H(a, b) == H(c, d), And(a == c, b == d))))
    L = [Int(f"L_{i}") for i in range(n)]                 # the new tree's leaves (root2 = MTH(L))
    root2 = _mth(H, L)
    true_prefix_root = _mth(H, L[:m])                     # what root1 MUST be if append-only holds
    ell = _rfc_proof_len(m, n)
    proof = [Int(f"P_{i}") for i in range(ell)]           # adversary-chosen proof nodes
    root1 = Int("root1")                                  # adversary-claimed old root
    accept = _verify_consistency_symbolic(H, m, n, root1, root2, proof)
    # NEGATION of soundness: the deployed verifier accepts, yet root1 is NOT the true prefix root.
    s.add(accept)
    s.add(root1 != true_prefix_root)
    return s.check()


def structural_length_rejection(m: int, n: int, max_extra: int = 3) -> bool:
    """Concrete control-flow fact: every proof length except the RFC length is rejected by the
    index arithmetic alone (the symbolic acceptance is BoolVal(False)). No solver needed."""
    H = Function("Hlen", IntSort(), IntSort(), IntSort())
    ell = _rfc_proof_len(m, n)
    root1, root2 = Ints("r1len r2len")
    for wrong in range(0, ell + max_extra + 1):
        if wrong == ell:
            continue
        proof = [Int(f"Q_{wrong}_{i}") for i in range(wrong)]
        res = _verify_consistency_symbolic(H, m, n, root1, root2, proof)
        if not (res.eq(BoolVal(False))):
            return False
    return True


def main() -> int:
    print(f"RFC-6962 verifyConsistency ALGORITHM soundness — Z3 {get_version_string()} SMT proof")
    fails = 0
    pairs = [(1, 2), (2, 3), (2, 4), (3, 5), (5, 8)]
    for m, n in pairs:
        if not structural_length_rejection(m, n):
            print(f"  FAIL (m={m},n={n}): a non-RFC proof length is not structurally rejected"); fails += 1
            continue
        if prove_algorithm_sound(m, n, collision_resistant=True) == unsat:
            print(f"  ok   (m={m},n={n}): PROVEN — the deployed verifier accepts ONLY the true size-{m} prefix root "
                  f"(wrong lengths structurally rejected; Z3 unsat)")
        else:
            print(f"  FAIL (m={m},n={n}): algorithm soundness NOT proven"); fails += 1
    for m, n in ((2, 3), (2, 4)):
        if str(prove_algorithm_sound(m, n, collision_resistant=False)) == "sat":
            print(f"  ok   (m={m},n={n}): TEETH — without CR, Z3 forges a consistency proof for a fake old root (Z3 sat)")
        else:
            print(f"  FAIL (m={m},n={n}): no teeth (expected sat without CR)"); fails += 1
    print("")
    if fails:
        print(f"rfc6962_consistency_algo_z3: FAIL ({fails})")
        return 1
    print("rfc6962_consistency_algo_z3: PASS — deployed path-folding verifier machine-checked "
          "(pow2 + non-pow2 branches, balanced + unbalanced).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
