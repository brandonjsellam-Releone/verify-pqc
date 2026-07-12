#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of pqaibom's ANTI-OVERCLAIM grade cap — the product's own grader
CANNOT emit a top grade for a declared level below Bound. "Prove it, don't claim it" applied to the
claim-hygiene mechanism itself.
================================================================================================
pqaibom.gradeAibom computes a completeness score -> an uncapped letter, then applies a chain of SIX
hard caps via worst_of (each can only LOWER the grade). This proof transcribes ALL SIX exactly:
    letter = worst_of( uncapped_letter, LEVEL_LETTER_CAP[assurance_level] )   # (1) L0->'B' L1->'A' L2->'A'
    if any_restrictive_license: letter = worst_of( letter, 'B' )             # (2)
    if mislabeled_model:        letter = worst_of( letter, 'C' )             # (3)
    if known_risk_fail:         letter = worst_of( letter, 'C' )             # (4)
    if integrity_not_pass:      letter = worst_of( letter, 'B' )             # (5)
    if models_with_no_data:     letter = worst_of( letter, 'C' )             # (6) the COMPLETENESS FLOOR
"worst_of" takes the lower grade on the A>B>C>D>F ordering (a cap can only LOWER a grade).

THEOREMS (each proven by showing the negation is UNSAT over ALL possible score inputs / flags):
  (T1) NO 'A' WITHOUT A DECLARED LEVEL >= BOUND: for every completeness score and every flag
       combination, final_letter == 'A'  =>  assurance_level >= 1 (Bound). So a self-declared (L0) BOM
       can never be GRADED 'A'. HONEST SCOPE (apex review): this proves the grader won't emit 'A'
       unless the RECORDED level is >= bound; whether that level was EARNED (hashes actually checked
       via bindManifest) is a separate, caller-asserted fact the signature binds to WHOEVER asserted
       it — the cap makes the overclaim impossible to GRADE, not impossible to ASSERT at the field.
  (T2) NO 'A' WITH AN UNRESOLVED RESTRICTIVE LICENCE: final_letter == 'A' => not any_restrictive.
  (T3) MONOTONE CAPS: all six caps only ever LOWER the grade — final_letter is always worse-or-equal
       to the uncapped letter (a cap can never inflate a grade).
  (T4) MISLABELED -> capped 'C'.  (T6) A FLAGGED HIGH-RISK component -> capped 'C'.
  (T5) COMPLETENESS FLOOR: a BOM declaring a model but NO training data / retrieval corpus can never be
       graded above 'C'. This machine-checks the anti-OMISSION-gaming invariant both council rounds
       kept probing: you cannot raise your grade by declaring LESS — hiding the training data forces
       the floor. (Combined with the honest-scope note above, the recurring dataset-dodge class is
       structurally closed and now formally proven.)

TEETH (negative control): a BROKEN grader that applies the level cap with max_of (a cap that could
RAISE the grade) admits final=='A' at level 0 -> Z3 exhibits it (`sat`). So the worst-of direction
is load-bearing.

Letters are modelled as integers A=0 < B=1 < C=2 < D=3 < F=4 (smaller = better); "worst_of" = max
(numerically) = the lower grade. Fully faithful to the code's capLetter (index compare).

Run:  python pqaibom_grade_cap_z3.py     (exit 0 = T1,T2,T3 unsat + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import Solver, Int, Bool, If, And, Or, Not, Implies, unsat, get_version_string

A, B, C = 0, 1, 2  # letter codes (A best). LEVEL_LETTER_CAP = [B, A, A] for levels [0,1,2].


def _worst(x, y):
    return If(x >= y, x, y)   # numerically larger = worse grade


def final_letter(uncapped, level, restrictive, mislabel, known_risk_fail, integrity_not_pass, models_no_data, *, broken=False):
    """EXACT transcription of gradeAibom's SIX caps (pqaibom.mjs lines 193-198). broken=True flips the
    level cap to a RAISE. Every cap is capLetter(letter, X) = _worst — it can only ever LOWER the grade."""
    cap_for_level = If(level == 0, B, If(level == 1, A, A))          # (1) LEVEL_LETTER_CAP [B,A,A]
    lvl = (If(uncapped <= cap_for_level, uncapped, cap_for_level)) if broken else _worst(uncapped, cap_for_level)
    lvl = If(restrictive, _worst(lvl, B), lvl)                       # (2) restrictive/copyleft cap -> B
    lvl = If(mislabel, _worst(lvl, C), lvl)                          # (3) mislabeled model cap -> C
    lvl = If(known_risk_fail, _worst(lvl, C), lvl)                   # (4) flagged high-risk component -> C
    lvl = If(integrity_not_pass, _worst(lvl, B), lvl)               # (5) unhashed components -> B
    return If(models_no_data, _worst(lvl, C), lvl)                  # (6) model w/o training data/corpus -> C


def prove(theorem):
    s = Solver()
    uncapped = Int('uncapped'); level = Int('level')
    restrictive = Bool('restrictive'); mislabel = Bool('mislabel')
    known_risk_fail = Bool('known_risk_fail'); integrity_not_pass = Bool('integrity_not_pass'); models_no_data = Bool('models_no_data')
    s.add(uncapped >= 0, uncapped <= 4)            # a valid letter code A..F
    s.add(level >= 0, level <= 2)                  # a valid assurance level
    fl = final_letter(uncapped, level, restrictive, mislabel, known_risk_fail, integrity_not_pass, models_no_data)
    if theorem == 'T1':      # final == A  and  level < 1   (an 'A' at a declared level below Bound)
        s.add(fl == A, level < 1)
    elif theorem == 'T2':    # final == A  and  restrictive
        s.add(fl == A, restrictive == True)
    elif theorem == 'T3':    # a cap INFLATED the grade (final better than uncapped)
        s.add(fl < uncapped)
    elif theorem == 'T4':    # final <= B  and  mislabel   (a mislabeled model still graded A or B)
        s.add(fl <= B, mislabel == True)
    elif theorem == 'T5':    # final <= B  and  models_no_data  (the COMPLETENESS FLOOR — closes omission-gaming)
        s.add(fl <= B, models_no_data == True)
    elif theorem == 'T6':    # final <= B  and  known_risk_fail  (a flagged high-risk component graded A/B)
        s.add(fl <= B, known_risk_fail == True)
    return s.check()


def teeth():
    s = Solver()
    uncapped = Int('uncapped'); level = Int('level')
    restrictive = Bool('restrictive'); mislabel = Bool('mislabel')
    known_risk_fail = Bool('known_risk_fail'); integrity_not_pass = Bool('integrity_not_pass'); models_no_data = Bool('models_no_data')
    s.add(uncapped >= 0, uncapped <= 4, level >= 0, level <= 2)
    fl = final_letter(uncapped, level, restrictive, mislabel, known_risk_fail, integrity_not_pass, models_no_data, broken=True)
    s.add(fl == A, level < 1)                       # broken grader: 'A' at level 0
    return s.check()


def main() -> int:
    print(f"pqaibom grade-cap anti-overclaim — Z3 {get_version_string()} SMT proof")
    fails = 0
    checks = [('T1', "no 'A' at a declared level below Bound"),
              ('T2', "no 'A' with an unresolved restrictive licence"),
              ('T3', "all SIX caps only LOWER a grade (never inflate)"),
              ('T4', "a mislabeled model is capped at 'C' (never A or B)"),
              ('T5', "COMPLETENESS FLOOR: a model with NO training data/corpus caps at 'C' — omission-gaming (declare less to grade higher) is structurally impossible"),
              ('T6', "a flagged high-risk component (unsandboxed egress / unlicensed+unprovenanced model) caps at 'C'")]
    for key, desc in checks:
        if prove(key) == unsat:
            print(f"  ok   {key}: PROVEN — {desc} (Z3 unsat)")
        else:
            print(f"  FAIL {key}: NOT proven — {desc}"); fails += 1
    if str(teeth()) == 'sat':
        print("  ok   TEETH — a broken (max->raise) level cap admits 'A' at level 0 (Z3 sat)")
    else:
        print("  FAIL teeth — broken cap did not admit the overclaim (expected sat)"); fails += 1
    print("")
    if fails:
        print(f"pqaibom_grade_cap_z3: FAIL ({fails})")
        return 1
    print("pqaibom_grade_cap_z3: PASS — the grader cannot emit 'A' for a declared level below Bound, or a restrictive declaration.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
