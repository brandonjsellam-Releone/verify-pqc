#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of the AI PROVENANCE RECORD binding — a runtime trace binds to
EXACTLY ONE declared AIBOM (no BOM-substitution). This is the load-bearing property of the
pqaibom ∧ pqtrace composition (pqai-provenance-e2e.mjs).
================================================================================================
A provenance record ties a pqtrace execution log to a pqaibom static inventory by committing, in the
trace's step-0 config, the AIBOM's runtime_binding = H(canon({v, subject, assurance_level, ids})),
where `ids` is the ordered list of (type, name, version, primary-hash) of every declared component.
verifyProvenanceRecord accepts only if the trace's step-0 opens to record.runtime_binding AND that
value equals the presented AIBOM's runtime_binding.

MODEL:
  - B : id-set -> binding, the runtime-binding hash, assumed COLLISION-RESISTANT (injective).
  - a trace is built for a specific inventory idsA; its committed binding is B(idsA).
  - a verifier is handed the trace + SOME presented AIBOM with inventory idsP; it accepts only if
    B(idsP) == committed == B(idsA).

THEOREM (no substitution): if the record verifies, the presented AIBOM's inventory is EXACTLY the
one the trace was built for — idsP == idsA. So an attacker cannot pair an honest run's trace with a
DIFFERENT (e.g. cleaner-looking, higher-graded, or benign-model) AIBOM. Z3 proves the negation
("verifies, yet idsP != idsA") UNSAT — over inventories of 1..4 components.

TEETH (negative control): drop collision-resistance of B (a weak/truncated binding) and Z3 exhibits
a substitution — idsP != idsA sharing a binding, accepted (`sat`). So the whole no-substitution
guarantee rests on CR of the binding hash.

COMPLEMENTS pqtrace_chain_z3 (the trace itself is tamper-evident) and pqaibom_grade_cap_z3 (the grade
can't overclaim). This proof is the JOIN: the tamper-evident trace is bound to the honest inventory,
so BOM-reality drift (runtime != declaration) is the only remaining gap — and that is caught
operationally by checkBomRealityDrift, not by substitution. Symbolic scope: CR-as-injectivity
assumed (discharged by SHA-512 over canon in the code); not a proof of SHA-512.

Run:  python pqai_provenance_binding_z3.py    (exit 0 = no-substitution unsat 1..4 + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (
    Solver, Function, Int, Ints, And, Or, Implies, ForAll, IntSort, unsat, get_version_string,
)


def prove_no_substitution(n: int, collision_resistant: bool):
    s = Solver()
    B = Function("B", *([IntSort()] * n), IntSort())          # binding over an n-component id vector
    if collision_resistant:                                   # injective: equal binding => equal id vector
        a = [Int(f"a_{i}") for i in range(n)]
        b = [Int(f"b_{i}") for i in range(n)]
        s.add(ForAll(a + b, Implies(B(*a) == B(*b), And(*[a[i] == b[i] for i in range(n)]))))
    idsA = [Int(f"idsA_{i}") for i in range(n)]               # the inventory the trace was built for
    idsP = [Int(f"idsP_{i}") for i in range(n)]               # the inventory of the PRESENTED AIBOM
    committed = B(*idsA)                                      # the trace's step-0 committed binding
    # verifier accepts iff the presented AIBOM's binding equals the trace's committed binding.
    s.add(B(*idsP) == committed)
    # NEGATION of no-substitution: accepted, yet the presented inventory differs somewhere.
    s.add(Or(*[idsP[i] != idsA[i] for i in range(n)]))
    return s.check()


def main() -> int:
    print(f"AI provenance-record binding (no BOM substitution) — Z3 {get_version_string()} SMT proof")
    fails = 0
    for n in (1, 2, 3, 4):
        if prove_no_substitution(n, collision_resistant=True) == unsat:
            print(f"  ok   n={n}: PROVEN — a verifying record's AIBOM is EXACTLY the inventory the trace bound (Z3 unsat)")
        else:
            print(f"  FAIL n={n}: no-substitution NOT proven"); fails += 1
    for n in (2, 3):
        if str(prove_no_substitution(n, collision_resistant=False)) == "sat":
            print(f"  ok   n={n}: TEETH — a non-CR binding admits a BOM substitution (Z3 sat)")
        else:
            print(f"  FAIL n={n}: no teeth (expected sat without CR)"); fails += 1
    print("")
    if fails:
        print(f"pqai_provenance_binding_z3: FAIL ({fails})")
        return 1
    print("pqai_provenance_binding_z3: PASS — no-BOM-substitution machine-checked (n=1-4).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
