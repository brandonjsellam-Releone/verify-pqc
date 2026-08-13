#!/usr/bin/env python3
"""Run every machine-checked formal proof in this directory. Exit 0 iff all pass.

Wire into CI:  python packages/verify-pqc/formal/run_all.py
Requires:      pip install z3-solver
"""
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# every Z3 proof + the code-level companion checks that discharge their assumptions (e.g. the
# context-registry prefix-freeness check behind domain_separation_z3's injective-encoding axiom).
proofs = sorted(glob.glob(os.path.join(HERE, "*_z3.py"))) + sorted(glob.glob(os.path.join(HERE, "*_check.py")))

# 0-DOWNGRADE RATCHET, same law test-all.mjs applies to the module suite (MIN_MODULES = 93).
# Proofs may be ADDED, never silently removed -- raise this floor upward when you add one.
#
# Without it this script is discovery-only: on an empty directory it prints
#     formal suite: 0/0 machine-checked proofs PASS
# and exits 0. A rename, a moved directory, or a glob that stops matching therefore turns the
# machine-checked formal suite -- the strongest assurance evidence this package has -- into a
# green check that proved nothing, and nothing downstream could tell the difference.
MIN_PROOFS = 17
if len(proofs) < MIN_PROOFS:
    print(
        f"formal suite: FAIL -- discovered {len(proofs)} proofs, floor is {MIN_PROOFS}.\n"
        "Proofs are never removed silently. If one was deliberately retired, lower MIN_PROOFS in "
        "the same commit so the diff shows a reviewer that formal coverage shrank.",
        file=sys.stderr,
    )
    sys.exit(1)

fails = 0
for p in proofs:
    print(f"=== {os.path.basename(p)} ===")
    r = subprocess.run([sys.executable, p], env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    if r.returncode != 0:
        fails += 1
    print("")
print(f"formal suite: {len(proofs) - fails}/{len(proofs)} machine-checked proofs PASS")
sys.exit(1 if fails else 0)
