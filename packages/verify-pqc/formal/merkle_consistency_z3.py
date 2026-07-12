#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of the MTH PREFIX-BINDING LEMMA — a committed size-m root pins all m
committed leaves. (Council-review precision, 10 Jul: this lemma alone is NOT a proof of the
consistency-checking ALGORITHM — that is rfc6962_consistency_algo_z3.py, which proves the deployed
verifyConsistency path-folding code accepts only the true prefix root; CHAINED with this lemma the
append-only guarantee holds end-to-end: verifier accepts ⇒ root1 == MTH(prefix) [algo proof] ⇒ the
committed leaves are unchanged [this lemma].)
================================================================================================
An RFC-6962 log commits to size-m data by a signed tree head R_m = MTH(D[0..m-1]), where MTH is the
Merkle Tree Head computed by the RFC-6962 split rule

        MTH([d]) = leaf                                   (a single leaf)
        MTH(D[0..n-1]) = H( MTH(D[0..k-1]), MTH(D[k..n-1]) ),   k = largest power of two < n

A consistency proof convinces a client that a later size-n head (n > m) is an APPEND-ONLY extension:
its left size-m prefix still hashes to the SAME committed R_m. This file models MTH EXACTLY by that
split rule (distinct construction from the inclusion proof's single audit path) and proves:

  NO HISTORY REWRITE — under collision-resistance of the node hash H, if the presented new head's
  size-m prefix root equals the committed R_m, then EVERY one of the m committed leaves is unchanged.
  You can append freely (the tail leaves m..n-1 are unconstrained), but you cannot alter, remove, or
  reorder anything already committed without producing a hash collision.

  Z3 proves it by showing "the size-m prefix root still equals R_m, yet some committed leaf differs"
  is UNSAT — for m = 1,2,3,4,5,8 (balanced and unbalanced trees).

TEETH (negative control): drop the collision-resistance axiom (a broken/weak H) and Z3 exhibits a
rewrite — two different committed prefixes sharing the same root (`sat`, m = 2,3,4). So the append-
only guarantee rests exactly on CR of H.

HONEST SCOPE:
  - Symbolic model: H is an uninterpreted function assumed collision-resistant (injective); this is
    NOT a proof of SHA-256 itself, nor a bit-for-bit verification of the verifyConsistency proof-
    walking code (that is covered by the RFC-6962 differential cross-validation harness). What is
    proven is the algebraic invariant the whole scheme depends on: the committed root binds the
    committed leaves, so an append-only extension provably preserves history.
  - RFC-6962 does NOT fold the tree SIZE into the node hash; two different-size trees could in
    principle share a root. That gap is closed by the STH SIGNING (tree_size, root) together and the
    monitor's size-monotonicity / equivocation checks (pqkt.monitorUpdate) — not by this proof.

Run:  python merkle_consistency_z3.py     (exit 0 = no-rewrite proven unsat + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (
    Solver, Function, Int, Ints, Or, And, Implies, ForAll, IntSort, unsat, get_version_string,
)


def _split(n: int) -> int:
    """RFC-6962: the largest power of two STRICTLY less than n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(H, leaves):
    """Merkle Tree Head over `leaves`, by the exact RFC-6962 split rule."""
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = _split(n)
    return H(_mth(H, leaves[:k]), _mth(H, leaves[k:]))


def prove_no_rewrite(m: int, collision_resistant: bool):
    s = Solver()
    H = Function("H", IntSort(), IntSort(), IntSort())
    if collision_resistant:  # CR of the node hash, encoded as injectivity on pairs
        a, b, c, d = Ints("a b c d")
        s.add(ForAll([a, b, c, d], Implies(H(a, b) == H(c, d), And(a == c, b == d))))
    L = [Int(f"L_{i}") for i in range(m)]    # the committed history (first m leaves)
    Lp = [Int(f"Lp_{i}") for i in range(m)]  # the presented prefix in the later (size-n>m) head
    Rm = _mth(H, L)                          # the signed committed size-m root
    # A valid consistency proof asserts the new head's size-m prefix still hashes to the committed Rm:
    s.add(_mth(H, Lp) == Rm)
    # ...yet the adversary rewrote at least one already-committed leaf:
    s.add(Or(*[Lp[i] != L[i] for i in range(m)]))
    return s.check()


def main() -> int:
    print(f"RFC-6962 consistency / no-history-rewrite — Z3 {get_version_string()} SMT proof")
    fails = 0
    for m in (1, 2, 3, 4, 5, 8):
        if prove_no_rewrite(m, collision_resistant=True) == unsat:
            print(f"  ok   m={m}: PROVEN — a committed size-{m} root pins all {m} committed leaves; appends can't rewrite them (Z3 unsat)")
        else:
            print(f"  FAIL m={m}: no-history-rewrite NOT proven"); fails += 1
    # Teeth: without CR, a rewrite that preserves the committed root exists (m=1 is trivial: no hash).
    for m in (2, 3, 4):
        if str(prove_no_rewrite(m, collision_resistant=False)) == "sat":
            print(f"  ok   m={m}: TEETH — a non-CR hash admits a history rewrite under the same root (Z3 sat)")
        else:
            print(f"  FAIL m={m}: no teeth (expected sat without CR)"); fails += 1
    print("")
    if fails:
        print(f"merkle_consistency_z3: FAIL ({fails})")
        return 1
    print("merkle_consistency_z3: PASS — append-only / no-history-rewrite machine-checked (m=1-5,8).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
