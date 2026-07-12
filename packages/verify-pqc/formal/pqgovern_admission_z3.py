#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of the GOVERN-leg ADMISSION SOUNDNESS of pqgovern-policy +
pqgovernance-gate: an AI model can be ADMITTED only under an OWNER-AUTHENTICATED, in-scope signed
policy AND an owner-pinned, cross-bound record that meets the SIGNED criteria — and the CALLER cannot
shadow those criteria. Completes the formal frontier over the NIST AI RMF quartet (MAP/MEASURE/MANAGE
proven separately; this is GOVERN).
================================================================================================
This transcribes the FIXED decision logic (after the council + apex-team review that forced owner
authentication ON at the admission layer AND made the signed policy the SOLE criteria authority):

  pqgovern-policy.evaluateUnderPolicy(record, verifyOpts, signedPolicy, opts):
    policy_verified = policy_pinned AND policy_seal_valid          # verifyPolicy fails closed w/o pins;
                      AND policy_canonical AND version_ok          #   allowUnpinnedSeal is FORCED false here
    window_gate     = window_required => (window_checked AND window_ok)   # requireWindow (opt-in)
    record_verified = aibom_ok AND eval_ok AND trace_ok AND cross_bound  # gate forces allowUnpinnedSeal
    criteria_met    = other_criteria_met AND (signed_strict => record_distinct)   # caller flag STRIPPED
    gate_pass       = record_verified AND criteria_met
    admit           = policy_verified AND window_gate AND gate_pass

Two caller-controlled escape hatches are DELIBERATELY absent from `admit` (that removal is what the
TEETH prove is load-bearing): (a) `allow_unpinned_policy` is not plumbed into policy authentication;
(b) `caller_strict` (verifyOpts.requireDistinctSigners) is stripped, so the distinct-signer
requirement comes SOLELY from the signed policy. The record's grade/posture floors (`other_criteria_met`)
stay opaque here — their monotone-cap soundness is proven separately in pqaibom_grade_cap_z3 /
pqeval_posture_cap_z3; this proof covers the ADMISSION COMPOSITION + the patched criteria-fidelity.

THEOREMS (each proven by showing the negation is UNSAT over ALL boolean inputs):
  (T1) NO ADMIT WITHOUT AN OWNER-AUTHENTICATED POLICY: admit => policy_pinned AND policy_seal_valid.
  (T2) NO ADMIT WITHOUT ALL THREE RECORD LEGS OWNER-PINNED-VERIFIED + cross-bound.
  (T3) NO ADMIT ON A SUPERSEDED/WRONG POLICY WHEN PINNED: admit => version_ok.
  (T4) NO ADMIT OUT-OF-WINDOW WHEN REQUIRED: admit AND window_required => window_checked AND window_ok.
  (T5) NO ADMIT WITHOUT THE SIGNED CRITERIA MET: admit => other_criteria_met AND
       (signed_strict => record_distinct) — the SIGNED distinct-signer requirement is honored.
  (T6) CALLER CANNOT SHADOW THE CRITERIA (signed policy is SOLE authority): admit is INVARIANT to
       caller_strict — admit|caller=True <=> admit|caller=False for every other input. Formally locks
       the verifyOpts-stripping fix: a caller flag can neither weaken nor alter the enforced decision.
  (R)  NON-VACUITY / 0-REGRESSION: the honest all-good assignment is still ADMITTED (SAT).

TEETH (negative controls, each expected SAT — the corresponding fix is load-bearing):
  (H1) A BROKEN layer plumbing allow_unpinned_policy ADMITS an UNAUTHENTICATED policy.
  (H2) A BROKEN layer ignoring requireWindow ADMITS an expired policy.
  (H3) A BROKEN gate that OR's the caller flag into the criteria (eff_strict = signed OR caller) makes
       admit DEPEND on caller_strict — Z3 exhibits an input where flipping the unsigned caller flag
       flips the admission decision (the requireDistinctSigners-shadow the fix removed).

Run:  python pqgovern_admission_z3.py   (exit 0 = T1-T6 unsat + R sat + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (Solver, Bools, BoolVal, If, And, Or, Not, Implies, unsat, sat,
                get_version_string)


def build_admit(v, caller_strict, *, broken_unpinned=False, broken_window=False, shadow_criteria=False):
    (policy_pinned, policy_seal_valid, policy_canonical, version_ok,
     window_required, window_checked, window_ok,
     aibom_ok, eval_ok, trace_ok, cross_bound,
     other_criteria_met, signed_strict, record_distinct,
     allow_unpinned_policy, policy_self_consistent) = v
    # POLICY AUTHENTICATION. FIXED: owner pins REQUIRED; the caller flag is not honored on this path.
    if broken_unpinned:
        policy_authok = Or(And(policy_pinned, policy_seal_valid),
                           And(allow_unpinned_policy, policy_self_consistent))   # pre-fix bypass
    else:
        policy_authok = And(policy_pinned, policy_seal_valid)
    policy_verified = And(policy_authok, policy_canonical, version_ok)
    # requireWindow is opt-in; when set, a bounded policy must be time-checked IN-window. broken=ignore.
    window_gate = If(broken_window, BoolVal(True), Implies(window_required, And(window_checked, window_ok)))
    # gate over the record legs: allowUnpinnedSeal forced false -> each leg verifies under its pins.
    record_verified = And(aibom_ok, eval_ok, trace_ok, cross_bound)
    # CRITERIA. FIXED: the distinct-signer requirement comes SOLELY from the signed policy (caller stripped).
    #   BROKEN(shadow): a future dev OR's the caller flag back in -> it shadows the signed decision.
    eff_strict = Or(signed_strict, caller_strict) if shadow_criteria else signed_strict
    criteria_met = And(other_criteria_met, Implies(eff_strict, record_distinct))
    gate_pass = And(record_verified, criteria_met)
    return And(policy_verified, window_gate, gate_pass)


def _vars():
    return Bools('policy_pinned policy_seal_valid policy_canonical version_ok '
                 'window_required window_checked window_ok '
                 'aibom_ok eval_ok trace_ok cross_bound '
                 'other_criteria_met signed_strict record_distinct '
                 'allow_unpinned_policy policy_self_consistent')


def prove(theorem):
    s = Solver()
    v = _vars()
    caller = Bools('caller_strict')[0]
    admit = build_admit(v, caller)
    (policy_pinned, policy_seal_valid, policy_canonical, version_ok,
     window_required, window_checked, window_ok,
     aibom_ok, eval_ok, trace_ok, cross_bound,
     other_criteria_met, signed_strict, record_distinct,
     allow_unpinned_policy, policy_self_consistent) = v
    if theorem == 'T1':
        s.add(admit, Not(And(policy_pinned, policy_seal_valid)))
    elif theorem == 'T2':
        s.add(admit, Not(And(aibom_ok, eval_ok, trace_ok, cross_bound)))
    elif theorem == 'T3':
        s.add(admit, Not(version_ok))
    elif theorem == 'T4':
        s.add(admit, window_required, Not(And(window_checked, window_ok)))
    elif theorem == 'T5':
        s.add(admit, Not(And(other_criteria_met, Implies(signed_strict, record_distinct))))
    elif theorem == 'T6':    # admit must NOT depend on the unsigned caller flag (signed = sole authority)
        admit_T = build_admit(v, BoolVal(True))
        admit_F = build_admit(v, BoolVal(False))
        s.add(admit_T != admit_F)
    return s.check()


def reachable():
    """R: the honest all-good assignment still ADMITS (guards against a vacuous 'admit => X')."""
    s = Solver()
    v = _vars()
    admit = build_admit(v, BoolVal(False))
    (policy_pinned, policy_seal_valid, policy_canonical, version_ok,
     window_required, window_checked, window_ok,
     aibom_ok, eval_ok, trace_ok, cross_bound,
     other_criteria_met, signed_strict, record_distinct,
     allow_unpinned_policy, policy_self_consistent) = v
    s.add(policy_pinned, policy_seal_valid, policy_canonical, version_ok,
          window_required, window_checked, window_ok,
          aibom_ok, eval_ok, trace_ok, cross_bound,
          other_criteria_met, record_distinct, admit)   # signed_strict free; record_distinct true so it holds
    return s.check()


def teeth(which):
    s = Solver()
    v = _vars()
    (policy_pinned, policy_seal_valid, policy_canonical, version_ok,
     window_required, window_checked, window_ok,
     aibom_ok, eval_ok, trace_ok, cross_bound,
     other_criteria_met, signed_strict, record_distinct,
     allow_unpinned_policy, policy_self_consistent) = v
    if which == 'H1':        # broken: allow_unpinned_policy plumbed -> admit with UNauthenticated policy
        admit = build_admit(v, BoolVal(False), broken_unpinned=True)
        s.add(admit, Not(policy_pinned), Not(policy_seal_valid),
              allow_unpinned_policy, policy_self_consistent)
    elif which == 'H2':      # broken: requireWindow ignored -> admit an EXPIRED policy
        admit = build_admit(v, BoolVal(False), broken_window=True)
        s.add(admit, window_required, Not(window_ok))
    else:                    # H3 broken: caller flag OR'd into criteria -> admit DEPENDS on caller_strict
        admit_T = build_admit(v, BoolVal(True), shadow_criteria=True)
        admit_F = build_admit(v, BoolVal(False), shadow_criteria=True)
        s.add(admit_T != admit_F)
    return s.check()


def main() -> int:
    print(f"pqgovern-policy ADMISSION SOUNDNESS (GOVERN leg) — Z3 {get_version_string()} SMT proof")
    fails = 0
    checks = [('T1', 'no ADMIT without an OWNER-AUTHENTICATED policy (pins + valid seal)'),
              ('T2', 'no ADMIT without all three record legs owner-pinned-verified + cross-bound'),
              ('T3', 'no ADMIT on a superseded/wrong policy when a version/hash is pinned'),
              ('T4', 'no ADMIT out-of-window when requireWindow is set'),
              ('T5', 'no ADMIT without the SIGNED criteria met (signed distinct-signer req honored)'),
              ('T6', 'the unsigned CALLER flag cannot shadow the decision (signed policy = sole authority)')]
    for key, desc in checks:
        if prove(key) == unsat:
            print(f"  ok   {key}: PROVEN — {desc} (Z3 unsat)")
        else:
            print(f"  FAIL {key}: NOT proven — {desc}"); fails += 1
    if reachable() == sat:
        print("  ok   R : NON-VACUOUS — the honest all-good record still ADMITS (Z3 sat; 0-regression)")
    else:
        print("  FAIL R : the fixed gate admits NOTHING (vacuous soundness)"); fails += 1
    for key, desc in [('H1', 'a broken layer plumbing allowUnpinnedPolicy ADMITS an unauthenticated policy'),
                      ('H2', 'a broken layer ignoring requireWindow ADMITS an expired policy'),
                      ('H3', 'a broken gate OR-ing the caller flag lets it SHADOW the signed criteria')]:
        if str(teeth(key)) == 'sat':
            print(f"  ok   TEETH {key} — {desc} (Z3 sat)")
        else:
            print(f"  FAIL teeth {key} — did not exhibit the break (expected sat)"); fails += 1
    print("")
    if fails:
        print(f"pqgovern_admission_z3: FAIL ({fails})")
        return 1
    print("pqgovern_admission_z3: PASS — admission requires an owner-authenticated in-scope policy over an "
          "owner-pinned, criteria-meeting record; the caller cannot shadow the signed criteria.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
