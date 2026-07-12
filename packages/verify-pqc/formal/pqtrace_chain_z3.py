#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of pqtrace CHAIN BINDING — the sealed head pins the ENTIRE step
sequence (no edit / insert / delete / reorder / truncate without detection).
================================================================================================
pqtrace.mjs: step_hash_i = SHA-512(canon(core_i)) where core_i embeds prev_hash = step_hash_{i-1}
(null for seq 0), and the pqseal'd HEAD binds (count, final_hash). Abstractly the chain is
        h_0 = F(p_0, NIL),   h_i = F(p_i, h_{i-1})
with p_i the step payload (everything in the core except prev_hash) and F injective — which is what
SHA-512 collision-resistance + canon's injective serialization (prev_hash sits at a fixed key)
provide, and NIL structurally distinct from any real hash (null vs a hex string in canon).

THEOREM (chain binding): if a presented payload sequence p'_0..p'_{n-1} chain-verifies and reaches
the SAME final hash with the SAME count n (both sealed in the HEAD), then p'_i == p_i for EVERY i —
the honest sequence is the only one. Z3 proves the negation ("same final hash + count, some payload
differs") UNSAT for n = 1..5. Edit/reorder/substitute anywhere = some p'_i != p_i = broken.
Truncation/extension change count (or, via the NIL axiom, cannot re-reach the final hash) = broken.

TEETH (negative control): a BROKEN design that hashes each step's payload WITHOUT the prev link
(step_hash = G(p_i); "final hash" = G(p_{n-1})) binds only the LAST step — Z3 exhibits a history
rewrite: a presented sequence differing in an earlier step passes with the same final hash (`sat`).
So the prev_hash link is exactly the load-bearing mechanism.

HONEST SCOPE: symbolic (CR-as-injectivity + injective serialization assumed; both discharged in the
implementation by SHA-512 + canon + the null/hex type split). Proves the CHAIN construction; the
seal on the head is pqseal (its own Z3 proofs), and runner honesty at recording time is the stated
v1 trust boundary — this proof is about tampering AFTER sealing, not lying BEFORE it.

Run:  python pqtrace_chain_z3.py     (exit 0 = chain binding unsat n=1..5 + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (
    Solver, Function, Int, Ints, And, Or, Implies, ForAll, IntSort, unsat, get_version_string,
)


def prove_chain_binding(n: int):
    s = Solver()
    F = Function("F", IntSort(), IntSort(), IntSort())   # F(payload, prev) -> step hash
    a, b, c, d = Ints("a b c d")
    s.add(ForAll([a, b, c, d], Implies(F(a, b) == F(c, d), And(a == c, b == d))))  # CR + canon injectivity
    NIL = Int("NIL")
    p, h = Ints("p h")
    s.add(ForAll([p, h], F(p, h) != NIL))                # a real hash never equals the no-previous sentinel

    P = [Int(f"p_{i}") for i in range(n)]                # honest payloads
    Q = [Int(f"q_{i}") for i in range(n)]                # presented payloads (same count — head binds it)

    def chain(xs):
        acc = NIL
        for x in xs:
            acc = F(x, acc)
        return acc

    s.add(chain(Q) == chain(P))                          # same final hash (sealed in the head)
    s.add(Or(*[Q[i] != P[i] for i in range(n)]))         # ...yet some step differs
    return s.check()


def broken_no_prev_link(n: int):
    """TEETH: step hashes do not chain (G of payload only); the 'final hash' binds only step n-1.
    The attacker keeps the LAST step identical (so no hash collision is even needed — a perfect
    hash does not save this design) and rewrites an earlier step: acceptance anyway = the attack."""
    s = Solver()
    G = Function("G", IntSort(), IntSort())
    P = [Int(f"bp_{i}") for i in range(n)]
    Q = [Int(f"bq_{i}") for i in range(n)]
    s.add(Q[n - 1] == P[n - 1])                           # same last step ⇒ same G, even for perfect G
    s.add(G(Q[n - 1]) == G(P[n - 1]))                     # final 'hash' matches (binds last step only)
    s.add(Or(*[Q[i] != P[i] for i in range(n - 1)]))      # ...and an EARLIER step was rewritten
    return s.check()


def main() -> int:
    print(f"pqtrace chain binding — Z3 {get_version_string()} SMT proof")
    fails = 0
    for n in (1, 2, 3, 4, 5):
        if prove_chain_binding(n) == unsat:
            print(f"  ok   n={n}: PROVEN — same (count, final_hash) ⇒ the entire {n}-step sequence is the honest one (Z3 unsat)")
        else:
            print(f"  FAIL n={n}: chain binding NOT proven"); fails += 1
    for n in (2, 3):
        if str(broken_no_prev_link(n)) == "sat":
            print(f"  ok   n={n}: TEETH — without the prev_hash link, an earlier step rewrites under the same final hash (Z3 sat)")
        else:
            print(f"  FAIL n={n}: no teeth (expected sat without the chain link)"); fails += 1
    print("")
    if fails:
        print(f"pqtrace_chain_z3: FAIL ({fails})")
        return 1
    print("pqtrace_chain_z3: PASS — sealed-head chain binding machine-checked (n=1-5).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
