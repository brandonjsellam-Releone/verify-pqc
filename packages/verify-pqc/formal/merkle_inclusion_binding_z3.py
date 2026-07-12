#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of MERKLE INCLUSION-PROOF BINDING — the tamper-evidence core of the
RFC-6962 transparency log (pqsign / pqtsa / pqindex / pqinduct all rely on it).
================================================================================================
An inclusion proof recomputes the tree root from a leaf and an audit path (sibling hashes + a
left/right direction at each level). This proves that, under collision-resistance of the node hash,
that recomputation is **injective in the leaf**: a given (root, audit-path) can be produced by only
ONE leaf. Consequence: you cannot swap the leaf a proof "proves" without producing a hash collision
— i.e. the log is tamper-evident, and inclusion proofs are sound.

MODEL:
  - `H : (Int, Int) -> Int` is the node compression function, assumed COLLISION-RESISTANT
    (encoded as injectivity on pairs: `H(a,b) == H(c,d)  =>  a==c AND b==d`).
  - `root(leaf)` folds the leaf up the audit path: at level i, `H(sibling_i, h)` if the node is a
    right-child else `H(h, sibling_i)` — exactly the RFC-6962 inclusion recomputation.

THEOREM: for a fixed audit path, `root(leaf1) == root(leaf2)  =>  leaf1 == leaf2`. Z3 proves it by
showing the NEGATION ("two DISTINCT leaves recompute to the SAME root along the SAME path") is UNSAT
— for tree depths 1..4.

TEETH (negative control): drop the collision-resistance axiom (a broken/weak hash) and Z3 finds a
collision — two distinct leaves sharing a root (`sat`). So the binding rests exactly on CR of H.

Run:  python merkle_inclusion_binding_z3.py     (exit 0 = proven unsat + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (
    Solver, Function, Int, Ints, Bool, If, ForAll, Implies, And, IntSort, BoolSort,
    unsat, get_version_string,
)


def _root(H, leaf, sib, dr, depth):
    h = leaf
    for i in range(depth):
        h = If(dr[i], H(sib[i], h), H(h, sib[i]))  # right-child vs left-child at level i
    return h


def prove_binding(depth: int, collision_resistant: bool):
    s = Solver()
    H = Function("H", IntSort(), IntSort(), IntSort())
    if collision_resistant:
        a, b, c, d = Ints("a b c d")
        s.add(ForAll([a, b, c, d], Implies(H(a, b) == H(c, d), And(a == c, b == d))))
    leaf1, leaf2 = Ints("leaf1 leaf2")
    sib = [Int(f"sib_{i}") for i in range(depth)]
    dr = [Bool(f"dir_{i}") for i in range(depth)]
    # NEGATION of the theorem: two distinct leaves, same audit path, same recomputed root.
    s.add(_root(H, leaf1, sib, dr, depth) == _root(H, leaf2, sib, dr, depth))
    s.add(leaf1 != leaf2)
    return s.check()


def main() -> int:
    print(f"Merkle inclusion-proof binding — Z3 {get_version_string()} SMT proof")
    fails = 0
    for depth in (1, 2, 3, 4):
        if prove_binding(depth, collision_resistant=True) == unsat:
            print(f"  ok   depth={depth}: PROVEN — a (root, path) is produced by exactly one leaf (Z3 unsat)")
        else:
            print(f"  FAIL depth={depth}: inclusion binding NOT proven"); fails += 1
    # Teeth: without collision-resistance, two leaves CAN share a root.
    for depth in (2, 3):
        if str(prove_binding(depth, collision_resistant=False)) == "sat":
            print(f"  ok   depth={depth}: TEETH — a non-CR hash admits a leaf-substitution collision (Z3 sat)")
        else:
            print(f"  FAIL depth={depth}: no teeth (expected sat without CR)"); fails += 1
    print("")
    if fails:
        print(f"merkle_inclusion_binding_z3: FAIL ({fails})")
        return 1
    print("merkle_inclusion_binding_z3: PASS — inclusion-proof binding machine-checked (depths 1-4).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
