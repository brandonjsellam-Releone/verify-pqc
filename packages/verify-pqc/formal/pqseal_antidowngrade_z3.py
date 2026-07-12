#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of the pqseal N-of-N AND-composition ANTI-DOWNGRADE property.
================================================================================================
This is a *formal* result, not a test: Z3 exhaustively proves the property holds in the symbolic
model (returns `unsat` for the negation = no counterexample exists), rather than checking examples.

WHAT pqseal DOES (see pqseal.mjs): an envelope carries N legs across distinct algorithm families
(e.g. ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519). Each leg signs SEAL_CTX = H(v, suite, ALL-leg-pubkeys,
payload_sha512) — i.e. every leg's message binds the FULL set of legs. openSeal accepts iff EVERY
present leg's signature verifies over the context computed from the presented leg-set.

SYMBOLIC MODEL (standard Dolev-Yao / EUF-CMA assumptions, stated precisely so the claim is honest):
  (A1) Collision resistance of the context hash: ctx : leg-set → digest is INJECTIVE
       (distinct leg-sets ⇒ distinct context digests). Modelled exactly over all 2^N leg-sets.
  (A2) EUF-CMA, no honest-key compromise: an honest leg i's signature verifies for a digest d
       IFF the honest signer actually signed d. The honest signer signed ONLY ctx(FULL) (once,
       over the full N-leg set). The adversary holds no honest secret key, so it cannot make any
       other (leg, digest) pair verify.

THEOREM (anti-downgrade): starting from a seal honestly produced over the full N-leg set, NO
proper sub-set of the legs (a DOWNGRADE: drop one or more legs) is accepted by openSeal — because
each surviving honest signature is bound to ctx(FULL) ≠ ctx(subset). Z3 proves this by showing the
NEGATION ("some non-full, non-empty leg-set is accepted") is UNSAT, for N = 2, 3, 4.

SCOPE (council-review precision, 10 Jul): the presented legs here are drawn from the HONEST leg set
— this is the leg-DROP adversary. A seal that swaps in adversary-controlled keys is the separate
theorem in pqseal_legswap_z3.py; a seal with NO honest leg at all is a different signer entirely,
rejected operationally by requireSuite / pinning (not by the binding). FAITHFULNESS of the subset
abstraction: canon() preserves ARRAY ORDER, so the code binds the ordered leg vector; a drop yields
a distinct subsequence ⇒ a distinct canon string ⇒ a distinct digest — which is exactly (A1) on the
subset space. Orderings/duplicates/foreign keys lie outside the drop space and are covered by the
leg-swap proof + openSeal's requireDistinctLegs / suite checks.

HONEST CLAIM this earns (claim-hygiene-clean — a precise property, never "unbreakable"):
  "pqseal's N-of-N anti-downgrade binding is MACHINE-CHECKED with the Z3 SMT solver: under
   collision-resistance of the context hash and EUF-CMA of each leg, no leg-set downgrade produces
   a verifying seal without forging an honest leg's signature."

Run:  python pqseal_antidowngrade_z3.py    (exit 0 = every theorem proven `unsat`)
"""
from __future__ import annotations
import itertools
import sys

from z3 import (
    Solver, Function, Bool, BoolVal, BoolSort, IntSort, And, Or, Implies, Not, unsat,
    get_version_string,
)


def prove_anti_downgrade(n: int):
    """Return (result, solver). result == unsat  ⇔  anti-downgrade holds for N=n legs."""
    s = Solver()

    # present[i] : leg i is in the candidate (adversary-presented) leg-set L.
    present = [Bool(f"present_{i}") for i in range(n)]

    # ctx : (present-vector) → digest.  Uninterpreted function ⇒ Z3 reasons over ALL possible hashes.
    ctx = Function("ctx", *([BoolSort()] * n), IntSort())

    all_vecs = list(itertools.product([False, True], repeat=n))
    def digest_of(vec):
        return ctx(*[BoolVal(b) for b in vec])

    # (A1) collision resistance: distinct leg-sets ⇒ distinct context digests.
    for a in range(len(all_vecs)):
        for b in range(a + 1, len(all_vecs)):
            s.add(digest_of(all_vecs[a]) != digest_of(all_vecs[b]))

    FULL = tuple([True] * n)
    d_full = digest_of(FULL)

    # signed(leg, digest) : honest leg's signature verifies for `digest`.
    signed = Function("signed", IntSort(), IntSort(), BoolSort())

    # (Honest signing) the honest signer signed ctx(FULL) with EVERY leg — exactly once, full set.
    for i in range(n):
        s.add(signed(i, d_full) == True)
    # (A2, no forgery) an honest leg verifies for NO OTHER digest than ctx(FULL).
    for i in range(n):
        for vec in all_vecs:
            if vec != FULL:
                s.add(signed(i, digest_of(vec)) == False)

    # openSeal(L) accepts iff every PRESENT leg's signature verifies over ctx(L).
    ctx_L = ctx(*present)
    accepted = And([Implies(present[i], signed(i, ctx_L)) for i in range(n)])

    # NEGATION of the theorem: a non-empty leg-set L ≠ FULL is accepted.
    s.add(Or(present))                                   # non-empty (an actual seal)
    s.add(Not(And([present[i] for i in range(n)])))      # L ≠ FULL  (some leg dropped)
    s.add(accepted)                                      # ...yet openSeal accepts it

    return s.check(), s


def broken_is_attackable(n: int):
    """NEGATIVE CONTROL (teeth): model a BROKEN pqseal where each leg signs ONLY the payload
    (the context does NOT bind the leg-set). Z3 must find the downgrade attack (`sat`) — proving
    the leg-set binding is exactly what makes the real design safe, and that this harness can
    distinguish a secure design from an insecure one (a vacuous proof would pass both)."""
    s = Solver()
    present = [Bool(f"present_{i}") for i in range(n)]
    ctx = Function("ctx", *([BoolSort()] * n), IntSort())
    all_vecs = list(itertools.product([False, True], repeat=n))
    def digest_of(vec):
        return ctx(*[BoolVal(b) for b in vec])
    # BROKEN: the context is the SAME for every leg-set (no leg-set binding — signs payload only).
    d_payload = digest_of(tuple([True] * n))
    for vec in all_vecs:
        s.add(digest_of(vec) == d_payload)
    signed = Function("signed", IntSort(), IntSort(), BoolSort())
    for i in range(n):
        s.add(signed(i, d_payload) == True)   # honest legs signed the payload digest
    ctx_L = ctx(*present)
    accepted = And([Implies(present[i], signed(i, ctx_L)) for i in range(n)])
    s.add(Or(present))
    s.add(Not(And([present[i] for i in range(n)])))   # a proper subset (downgrade)
    s.add(accepted)
    return s.check(), s


def main() -> int:
    print(f"pqseal anti-downgrade — Z3 {get_version_string()} SMT proof")
    failures = 0
    for n in (2, 3, 4):
        result, s = prove_anti_downgrade(n)
        if result == unsat:
            print(f"  ok   N={n}: PROVEN — no downgraded leg-set is accepted (Z3 unsat)")
        else:
            print(f"  FAIL N={n}: NOT proven — Z3 returned {result}")
            if result.r == 1:  # sat → a counterexample exists (would be a real bug)
                print("       counterexample:", s.model())
            failures += 1
    # Teeth: the same harness on a BROKEN (no-binding) design must FIND the attack.
    for n in (2, 3):
        result, _ = broken_is_attackable(n)
        if str(result) == "sat":
            print(f"  ok   N={n}: TEETH — broken (payload-only) design IS downgradable (Z3 sat, as it must be)")
        else:
            print(f"  FAIL N={n}: harness has NO teeth — broken design returned {result} (expected sat)")
            failures += 1
    print("")
    if failures:
        print(f"pqseal_antidowngrade_z3: FAIL ({failures})")
        return 1
    print("pqseal_antidowngrade_z3: PASS — anti-downgrade machine-checked for N=2,3,4.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
