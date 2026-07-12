#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of the WITNESS-QUORUM RECONCILIATION SOUNDNESS of pqgovern-witness
(gossipReconcile). It proves that the multi-party split-view detector reports a quorum CONSISTENT only
when the witnesses' signed tree heads are genuinely a coherent, fully-checked append-only view — and
that it DETECTS every fork it is designed to catch. Extends the transparency-tier formal frontier: the
RFC-6962 consistency ALGORITHM is proven separately (rfc6962_consistency_algo_z3); this proves the
RECONCILIATION LOGIC layered on top (how pairwise checks aggregate into consistent / equivocation /
unresolved), including the council-hardened `consistent = no-equivocation AND no-unresolved` semantics.
================================================================================================
Model (N=3 trusted, already-signature-verified witnesses; the crypto validity of each observation is
discharged by verifyWitnessObservation + the ML-DSA/consistency proofs, taken as given here — as in the
admission proof). Each witness i publishes (size_i, root_i). For an ordered different-size pair (i<j),
`present_ij` = a consistency proof was supplied, and `prefix_ij` = the smaller root is GENUINELY a prefix
of the larger (the ground-truth relation; verifyConsistency returns true on a supplied proof IFF prefix
holds — RFC-6962 soundness+completeness, proven separately). Per pair the reconciler decides:

  same size:        equiv = (root_i != root_j)                      # exact-size fork
  different size:   if present:  equiv = NOT prefix ; unresolved = False   # prefix violation if proof fails
                    else:        equiv = False       ; unresolved = True   # abstain — cannot conclude
  consistent  = (no equiv over all pairs) AND (no unresolved over all pairs)   # <- COUNCIL-HARDENED
  equivocation = (any equiv)

THEOREMS (negation UNSAT over all inputs):
  (W1) CONSISTENT => NO EXACT-SIZE FORK: no two witnesses hold different roots at the same size.
  (W2) CONSISTENT => NO PREFIX VIOLATION: every proof-checked different-size pair has a true prefix.
  (W3) CONSISTENT => NOTHING UNRESOLVED: a different-size pair with NO proof can NEVER yield consistent
       (the CRITICAL council fix — "missing proof is not 'safe'"; `consistent` is a POSITIVE verdict).
  (W4) DETECTION (same-size): an exact-size fork ALWAYS raises equivocation (=> not consistent).
  (W5) DETECTION (prefix): a supplied-but-non-binding proof (present AND not prefix) ALWAYS raises equiv.
  (R)  NON-VACUITY / 0-REGRESSION: an honest agreeing quorum (Ra: all same head; Rb: ascending sizes with
       valid proofs) IS reported CONSISTENT (SAT).

TEETH (negative controls, expected SAT — each fix is load-bearing):
  (HW1) THE PRE-FIX BUG: a reconciler computing `consistent = no-equivocation` (dropping the no-unresolved
        term) reports CONSISTENT while a different-size pair is UNRESOLVED — the exact split-view a log
        could hide by withholding a proof. Z3 exhibits it; adding the no-unresolved term removes it.
  (HW2) A reconciler that SKIPS the same-size-fork check reports CONSISTENT on a real exact-size fork.
  (HW3) A reconciler that ASSUMES a prefix without a proof reports CONSISTENT over a genuinely forked
        different-size pair (prefix false, no proof).

Run:  python pqgovern_witness_z3.py   (exit 0 = W1-W5 unsat + R sat + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (Solver, Ints, Bool, BoolVal, If, And, Or, Not, unsat, sat, get_version_string)

PAIRS = [(0, 1), (0, 2), (1, 2)]


def _vars():
    sizes = Ints('s0 s1 s2')
    roots = Ints('r0 r1 r2')
    present = {(i, j): Bool(f'present_{i}{j}') for (i, j) in PAIRS}
    prefix = {(i, j): Bool(f'prefix_{i}{j}') for (i, j) in PAIRS}
    return sizes, roots, present, prefix


def build(sizes, roots, present, prefix, *,
          broken_ignore_unresolved=False, broken_skip_samesize=False, broken_assume_prefix=False):
    """Returns (consistent, equivocation, any_unresolved) as Z3 Bool exprs."""
    equivs, unresolveds = [], []
    for (i, j) in PAIRS:
        same_size = sizes[i] == sizes[j]
        same_root = roots[i] == roots[j]
        p, pref = present[(i, j)], prefix[(i, j)]
        eq_same = BoolVal(False) if broken_skip_samesize else And(same_size, Not(same_root))
        # different-size branch: a supplied proof verifies IFF the prefix genuinely holds.
        eq_diff = And(Not(same_size), p, Not(pref))                 # proof present but prefix violated -> fork
        # honest: a different-size pair with no proof is UNRESOLVED (abstain). broken_assume_prefix: treat as OK.
        unres = BoolVal(False) if broken_assume_prefix else And(Not(same_size), Not(p))
        equivs.append(If(same_size, eq_same, eq_diff))
        unresolveds.append(unres)
    any_equiv = Or(*equivs)
    any_unres = Or(*unresolveds)
    consistent = Not(any_equiv) if broken_ignore_unresolved else And(Not(any_equiv), Not(any_unres))
    return consistent, any_equiv, any_unres


def _fork_exists(sizes, roots):
    return Or(*[And(sizes[i] == sizes[j], roots[i] != roots[j]) for (i, j) in PAIRS])


def prove(theorem):
    s = Solver()
    sizes, roots, present, prefix = _vars()
    consistent, equivocation, any_unres = build(sizes, roots, present, prefix)
    if theorem == 'W1':
        s.add(consistent, _fork_exists(sizes, roots))
    elif theorem == 'W2':
        s.add(consistent, Or(*[And(sizes[i] != sizes[j], present[(i, j)], Not(prefix[(i, j)])) for (i, j) in PAIRS]))
    elif theorem == 'W3':
        s.add(consistent, any_unres)
    elif theorem == 'W4':
        s.add(_fork_exists(sizes, roots), Not(equivocation))
    elif theorem == 'W5':
        s.add(Or(*[And(sizes[i] != sizes[j], present[(i, j)], Not(prefix[(i, j)])) for (i, j) in PAIRS]), Not(equivocation))
    return s.check()


def reachable(which):
    s = Solver()
    sizes, roots, present, prefix = _vars()
    consistent, _, _ = build(sizes, roots, present, prefix)
    if which == 'Ra':      # all three witnesses on the SAME head -> consistent
        s.add(sizes[0] == sizes[1], sizes[1] == sizes[2], roots[0] == roots[1], roots[1] == roots[2], consistent)
    else:                  # Rb: distinct ascending sizes, every proof supplied + prefix genuinely holds -> consistent
        s.add(sizes[0] != sizes[1], sizes[0] != sizes[2], sizes[1] != sizes[2],
              *[present[(i, j)] for (i, j) in PAIRS], *[prefix[(i, j)] for (i, j) in PAIRS], consistent)
    return s.check()


def teeth(which):
    s = Solver()
    sizes, roots, present, prefix = _vars()
    if which == 'HW1':     # pre-fix: consistent = no-equivocation (drops no-unresolved) -> consistent WITH an unresolved pair
        consistent_b, _, any_unres_b = build(sizes, roots, present, prefix, broken_ignore_unresolved=True)
        s.add(consistent_b, any_unres_b)
    elif which == 'HW2':   # skips same-size check -> consistent over a real exact-size fork
        consistent_b, _, _ = build(sizes, roots, present, prefix, broken_skip_samesize=True)
        s.add(consistent_b, _fork_exists(sizes, roots))
    else:                  # HW3: assumes prefix without a proof -> consistent over a genuine different-size fork
        consistent_b, _, _ = build(sizes, roots, present, prefix, broken_assume_prefix=True)
        s.add(consistent_b, sizes[0] != sizes[1], Not(present[(0, 1)]), Not(prefix[(0, 1)]))
    return s.check()


def main() -> int:
    print(f"pqgovern-witness RECONCILIATION SOUNDNESS (transparency quorum) — Z3 {get_version_string()} SMT proof")
    fails = 0
    checks = [('W1', 'CONSISTENT => no exact-size fork (no two witnesses differ at one size)'),
              ('W2', 'CONSISTENT => no prefix violation (every proof-checked pair genuinely nests)'),
              ('W3', 'CONSISTENT => nothing unresolved (missing proof is NOT "safe" — the council fix)'),
              ('W4', 'DETECTION: an exact-size fork always raises equivocation'),
              ('W5', 'DETECTION: a supplied-but-non-binding proof always raises equivocation')]
    for key, desc in checks:
        if prove(key) == unsat:
            print(f"  ok   {key}: PROVEN — {desc} (Z3 unsat)")
        else:
            print(f"  FAIL {key}: NOT proven — {desc}"); fails += 1
    for key, desc in [('Ra', 'an all-same-head quorum is reported CONSISTENT'),
                      ('Rb', 'an honest ascending-size quorum with valid proofs is reported CONSISTENT')]:
        if reachable(key) == sat:
            print(f"  ok   R:{key} — NON-VACUOUS: {desc} (Z3 sat; 0-regression)")
        else:
            print(f"  FAIL R:{key} — the reconciler reports NOTHING consistent (vacuous)"); fails += 1
    for key, desc in [('HW1', 'the pre-fix "consistent = no-equivocation" reports CONSISTENT with an UNRESOLVED pair'),
                      ('HW2', 'a reconciler skipping the same-size check reports CONSISTENT on a real fork'),
                      ('HW3', 'a reconciler assuming a prefix without a proof reports CONSISTENT on a genuine fork')]:
        if str(teeth(key)) == 'sat':
            print(f"  ok   TEETH {key} — {desc} (Z3 sat)")
        else:
            print(f"  FAIL teeth {key} — did not exhibit the break (expected sat)"); fails += 1
    print("")
    if fails:
        print(f"pqgovern_witness_z3: FAIL ({fails})")
        return 1
    print("pqgovern_witness_z3: PASS — a quorum is CONSISTENT only when no witnesses fork AND every different-size "
          "pair is proof-verified; a missing proof can never read as safe, and every designed fork is detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
