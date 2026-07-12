#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of the WITNESSED-ADMISSION composition soundness of
pqgovern-witness.verifyWitnessedAdmission — the k-of-n relying-party CAPSTONE that composes the
anchored-admission check with the witness quorum. Companion to pqgovern_witness_z3 (which proves the
RECONCILIATION logic) and pqgovern_admission_z3 (the admission composition): this proves that the FINAL
"is this admission sufficiently witnessed?" verdict conjoins exactly the right, load-bearing gates.
================================================================================================
Transcribes the decision (the distinct-witness counting is abstracted as an Int `witness_count`, the way
pqgovern_admission_z3 abstracts the grade floors — the count's distinctness/trust/head-binding is checked
by the JS self-test + the per-observation crypto in verifyWitnessObservation):

  verifyWitnessedAdmission:
    admit_anchored = verifyAnchoredAdmission(anchor).admit AND .anchored   # re-derived under the verifier pins
    threshold      = witness_count >= min_witnesses                        # k DISTINCT trusted witnesses of THE head
    no_equiv       = NOT equivocation                                      # no PROVEN fork in the reconciled set
    strict         = require_full => fully_resolved                        # optional: proven GLOBAL consistency
    witnessed      = admit_anchored AND threshold AND no_equiv AND strict
  (min_witnesses is clamped >= 1 by the code; witness_count >= 0.)

THEOREMS (negation UNSAT over all inputs):
  (WA1) WITNESSED => ADMITTED+ANCHORED: no witnessing of a head that did not admit/anchor under the pins.
  (WA2) WITNESSED => k-THRESHOLD MET: witness_count >= min_witnesses (>=1) — never "witnessed" below quorum.
  (WA3) WITNESSED => NO PROVEN EQUIVOCATION: a proven fork anywhere disqualifies (the log key equivocated).
  (WA4) WITNESSED under requireFullyResolved => FULLY RESOLVED: the strict global-consistency bar is honored.
  (R)   NON-VACUITY / 0-REGRESSION: the honest case (admitted+anchored, quorum met, no fork) IS witnessed (SAT).

TEETH (negative controls, expected SAT — each gate is load-bearing):
  (HWA1) dropping the equivocation gate -> WITNESSED over a PROVEN-forked log.
  (HWA2) dropping the k-threshold gate  -> WITNESSED below quorum (too few distinct witnesses).
  (HWA3) dropping the admit/anchor gate -> WITNESSED for a head that never admitted/anchored.

Run:  python pqgovern_witnessed_z3.py   (exit 0 = WA1-WA4 unsat + R sat + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (Solver, Bools, Ints, BoolVal, And, Not, Implies, unsat, sat, get_version_string)


def _vars():
    admit_anchored, equivocation, fully_resolved, require_full = Bools('admit_anchored equivocation fully_resolved require_full')
    witness_count, min_witnesses = Ints('witness_count min_witnesses')
    return (admit_anchored, equivocation, fully_resolved, require_full, witness_count, min_witnesses)


def build(v, *, broken_no_equiv=False, broken_no_threshold=False, broken_no_admit=False):
    admit_anchored, equivocation, fully_resolved, require_full, witness_count, min_witnesses = v
    gate_admit = BoolVal(True) if broken_no_admit else admit_anchored
    gate_threshold = BoolVal(True) if broken_no_threshold else (witness_count >= min_witnesses)
    gate_equiv = BoolVal(True) if broken_no_equiv else Not(equivocation)
    gate_strict = Implies(require_full, fully_resolved)
    return And(gate_admit, gate_threshold, gate_equiv, gate_strict)


def _wellformed(v):
    # the code guarantees: min_witnesses clamped >= 1, witness_count is a set cardinality >= 0.
    _, _, _, _, witness_count, min_witnesses = v
    return [min_witnesses >= 1, witness_count >= 0]


def prove(theorem):
    s = Solver()
    v = _vars()
    s.add(*_wellformed(v))
    witnessed = build(v)
    admit_anchored, equivocation, fully_resolved, require_full, witness_count, min_witnesses = v
    if theorem == 'WA1':
        s.add(witnessed, Not(admit_anchored))
    elif theorem == 'WA2':
        s.add(witnessed, witness_count < min_witnesses)
    elif theorem == 'WA3':
        s.add(witnessed, equivocation)
    elif theorem == 'WA4':
        s.add(witnessed, require_full, Not(fully_resolved))
    return s.check()


def reachable():
    s = Solver()
    v = _vars()
    s.add(*_wellformed(v))
    witnessed = build(v)
    admit_anchored, equivocation, fully_resolved, require_full, witness_count, min_witnesses = v
    # honest: admitted+anchored, quorum met, no fork -> witnessed (require_full free; if set, resolved holds)
    s.add(admit_anchored, witness_count >= min_witnesses, Not(equivocation), Implies(require_full, fully_resolved), witnessed)
    return s.check()


def teeth(which):
    s = Solver()
    v = _vars()
    s.add(*_wellformed(v))
    admit_anchored, equivocation, fully_resolved, require_full, witness_count, min_witnesses = v
    if which == 'HWA1':
        s.add(build(v, broken_no_equiv=True), equivocation)                       # witnessed over a proven fork
    elif which == 'HWA2':
        s.add(build(v, broken_no_threshold=True), witness_count < min_witnesses)   # witnessed below quorum
    else:
        s.add(build(v, broken_no_admit=True), Not(admit_anchored))                # witnessed w/o admit+anchor
    return s.check()


def main() -> int:
    print(f"pqgovern-witness WITNESSED-ADMISSION composition (k-of-n capstone) — Z3 {get_version_string()} SMT proof")
    fails = 0
    checks = [('WA1', 'WITNESSED => admitted + anchored under the verifier pins'),
              ('WA2', 'WITNESSED => k-of-n threshold met (witness_count >= min_witnesses >= 1)'),
              ('WA3', 'WITNESSED => no PROVEN equivocation (a fork anywhere disqualifies)'),
              ('WA4', 'WITNESSED under requireFullyResolved => fully resolved (strict global consistency)')]
    for key, desc in checks:
        if prove(key) == unsat:
            print(f"  ok   {key}: PROVEN — {desc} (Z3 unsat)")
        else:
            print(f"  FAIL {key}: NOT proven — {desc}"); fails += 1
    if reachable() == sat:
        print("  ok   R : NON-VACUOUS — the honest admitted+anchored+quorum case IS witnessed (Z3 sat; 0-regression)")
    else:
        print("  FAIL R : nothing is witnessed (vacuous)"); fails += 1
    for key, desc in [('HWA1', 'dropping the equivocation gate -> WITNESSED over a proven-forked log'),
                      ('HWA2', 'dropping the k-threshold gate -> WITNESSED below quorum'),
                      ('HWA3', 'dropping the admit/anchor gate -> WITNESSED for a non-admitted/anchored head')]:
        if str(teeth(key)) == 'sat':
            print(f"  ok   TEETH {key} — {desc} (Z3 sat)")
        else:
            print(f"  FAIL teeth {key} — did not exhibit the break (expected sat)"); fails += 1
    print("")
    if fails:
        print(f"pqgovern_witnessed_z3: FAIL ({fails})")
        return 1
    print("pqgovern_witnessed_z3: PASS — an admission is WITNESSED only when it admits + anchors, a k-of-n distinct "
          "witness quorum vouched for the head, and no fork was proven; every gate is load-bearing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
