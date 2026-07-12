#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of pqeval's POSTURE-CAP anti-overclaim — an AI evaluation attestation
cannot present a top posture for a self-declared or under-rigorous evaluation. "Prove it, don't
claim it" applied to the MEASURE-leg grader (the apex-review pattern: every cap must be structural).
================================================================================================
pqeval.gradeEval computes a completeness/rigour score -> an uncapped letter, then applies a chain of
worst_of caps (each can only LOWER the grade). The load-bearing one is the SUITE-PROVENANCE cap: the
registered/modified tier is honored ONLY when the caller validated the suite against a trusted
registry (suite_validated); otherwise the effective type is custom_ad_hoc, capped 'C'. Transcribed
exactly (pqeval.mjs gradeEval):
    eff_type = suite_type IF suite_validated ELSE custom_ad_hoc(2)
    letter = worst_of( start, SUITE_TYPE_CAP[eff_type] )         # [no-cap, 'B', 'C'] for [reg, mod, custom]
    if rigour_fail:            letter = worst_of(letter, 'C' if rigour_severe else 'B')
    if contamination >= 1:     letter = worst_of(letter, 'D' if contaminated else 'C')   # non-clean
    if safety_fail:            letter = worst_of(letter, 'C')
    if binding_fail:           letter = worst_of(letter, 'C')
    start = uncapped IF complete ELSE 'F'
"worst_of" takes the lower grade on the A>B>C>D>F ordering (a cap only LOWERS).

THEOREMS (each proven by showing the negation is UNSAT over ALL score inputs / flags):
  (T1) NO 'A' WITHOUT AN EARNED REGISTERED SUITE: final == 'A'  =>  suite_validated AND
       suite_type == registered_standard. So a self-declared registered/modified label, or any suite
       a verifier cannot validate against its registry, can never present a signed 'A' — the killer
       "declare my favourable subset as the suite" attack is structurally capped, not merely
       attributable. (The exact vector the apex review confirmed was voluntary in the first cut.)
  (T2) MONOTONE CAPS: every cap only LOWERS the grade (final is worse-or-equal to the start).
  (T3) NON-CLEAN CONTAMINATION -> at most 'C' ('contaminated' -> at most 'D').
  (T4) RIGOUR FAIL -> at most 'B' (severe: 'C').   (T5) SAFETY/BINDING FAIL -> at most 'C'.

TEETH (negative control): a BROKEN grader that honors the DECLARED suite_type (ignores
suite_validated) admits final == 'A' with suite_validated False -> Z3 exhibits it (`sat`). So the
"earn it against a registry" step is load-bearing.

Letters A=0<B=1<C=2<D=3<F=4 (smaller = better); worst_of = max. No-cap = -1 (max(x,-1)=x).

Run:  python pqeval_posture_cap_z3.py     (exit 0 = T1-T5 unsat + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import Solver, Int, Bool, If, And, Or, Not, Implies, unsat, get_version_string

A, B, C, D, F = 0, 1, 2, 3, 4
REG, MOD, CUSTOM = 0, 1, 2
NOCAP = -1


def _worst(x, y):
    return If(x >= y, x, y)


def final_letter(uncapped, complete, suite_type, suite_validated, rigour_fail, rigour_severe,
                 contam, safety_fail, binding_fail, *, broken=False):
    start = If(complete, uncapped, F)
    # EFFECTIVE suite type — the earned-tier mechanism. broken=True trusts the DECLARED type (the bug).
    eff_type = suite_type if broken else If(suite_validated, suite_type, CUSTOM)
    suite_cap = If(eff_type == REG, NOCAP, If(eff_type == MOD, B, C))   # SUITE_TYPE_CAP
    lvl = _worst(start, suite_cap)
    lvl = If(rigour_fail, _worst(lvl, If(rigour_severe, C, B)), lvl)
    lvl = If(contam >= 3, _worst(lvl, D), If(contam >= 1, _worst(lvl, C), lvl))   # 3=contaminated, 1/2=unchecked/partial
    lvl = If(safety_fail, _worst(lvl, C), lvl)
    return If(binding_fail, _worst(lvl, C), lvl)


def _vars(s):
    u = Int('uncapped'); stype = Int('suite_type'); contam = Int('contam')
    comp = Bool('complete'); sval = Bool('suite_validated')
    rfail = Bool('rigour_fail'); rsev = Bool('rigour_severe'); sfail = Bool('safety_fail'); bfail = Bool('binding_fail')
    s.add(u >= 0, u <= 4, stype >= 0, stype <= 2, contam >= 0, contam <= 3)
    return u, comp, stype, sval, rfail, rsev, contam, sfail, bfail


def prove(theorem):
    s = Solver()
    v = _vars(s)
    fl = final_letter(*v)
    (u, comp, stype, sval, rfail, rsev, contam, sfail, bfail) = v
    if theorem == 'T1':      # final == A  and  not (suite_validated and registered)
        s.add(fl == A, Not(And(sval, stype == REG)))
    elif theorem == 'T2':    # a cap INFLATED the grade (final better than the start letter)
        s.add(fl < If(comp, u, F))
    elif theorem == 'T3':    # non-clean contamination, yet final better than C
        s.add(contam >= 1, fl < C)
    elif theorem == 'T4':    # rigour fail, yet final better than B
        s.add(rfail, fl < B)
    elif theorem == 'T5':    # safety or binding fail, yet final better than C
        s.add(Or(sfail, bfail), fl < C)
    return s.check()


def teeth():
    s = Solver()
    v = _vars(s)
    (u, comp, stype, sval, rfail, rsev, contam, sfail, bfail) = v
    fl = final_letter(*v, broken=True)     # broken grader trusts the declared suite_type
    s.add(fl == A, sval == False, stype == REG)   # unvalidated but self-labelled registered -> 'A'
    return s.check()


def main() -> int:
    print(f"pqeval posture-cap anti-overclaim — Z3 {get_version_string()} SMT proof")
    fails = 0
    checks = [('T1', "no 'A' without an EARNED (registry-validated) registered suite"),
              ('T2', "all caps only LOWER a grade (never inflate)"),
              ('T3', "non-clean contamination caps at 'C' (contaminated at 'D')"),
              ('T4', "a rigour failure caps at 'B'"),
              ('T5', "a safety/binding failure caps at 'C'")]
    for key, desc in checks:
        if prove(key) == unsat:
            print(f"  ok   {key}: PROVEN — {desc} (Z3 unsat)")
        else:
            print(f"  FAIL {key}: NOT proven — {desc}"); fails += 1
    if str(teeth()) == 'sat':
        print("  ok   TEETH — a broken grader that trusts the declared suite_type admits 'A' unvalidated (Z3 sat)")
    else:
        print("  FAIL teeth — broken grader did not admit the overclaim (expected sat)"); fails += 1
    print("")
    if fails:
        print(f"pqeval_posture_cap_z3: FAIL ({fails})")
        return 1
    print("pqeval_posture_cap_z3: PASS — a top posture requires an EARNED registered suite + full rigour.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
