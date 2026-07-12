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
fails = 0
for p in proofs:
    print(f"=== {os.path.basename(p)} ===")
    r = subprocess.run([sys.executable, p], env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    if r.returncode != 0:
        fails += 1
    print("")
print(f"formal suite: {len(proofs) - fails}/{len(proofs)} machine-checked proofs PASS")
sys.exit(1 if fails else 0)
