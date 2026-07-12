#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of pqseal LEG-SWAP resistance — the follow-on the anti-downgrade
proof (pqseal_antidowngrade_z3.py) explicitly deferred: not leg-DROP, but leg-SWAP with an
adversary-controlled key.
================================================================================================
pqseal binds every leg to SEAL_CTX = H(v, suite, ALL-leg-public-keys, payload). The first proof
showed you cannot DROP a leg. This proves the stronger mixing property:

    A seal that reuses ANY honest leg's public key verifies ONLY if the ENTIRE (leg-vector, payload)
    is exactly the honest one. Equivalently: you cannot mix ≥1 honest leg with ≥1 swapped
    (adversary-key) leg — the honest leg signed a DIFFERENT context and its signature will not verify.

Why: swapping leg i's public key K_i changes the leg-vector, hence (H injective) changes SEAL_CTX.
The honest legs signed the honest ctx, not the swapped ctx, so their signatures fail — and the
adversary cannot forge them (EUF-CMA). The only way to make every leg verify while reusing an honest
key is to reproduce the honest seal verbatim.

SYMBOLIC MODEL (honest scope):
  - Honest leg owners are keys 1..N; the honest seal fixes leg-vector (1,…,N) over payload pH=0, and
    those honest owners signed EXACTLY that one context ctxH (single-seal model — stated, not hidden).
  - An adversary-controlled key can sign ANY context (it holds its own secret key): verifies(adv,·)=T.
  - An honest key verifies a context IFF that context == ctxH (EUF-CMA + honest-key-not-compromised).
  - SEAL_CTX = C(K_1,…,K_N, payload), with C COLLISION-RESISTANT — modelled by instantiating CR at the
    one pair that matters (presented ctx vs honest ctx): if they collide, their pre-images are equal.
    General over the symbolic seal variables, so UNSAT covers ALL adversary inputs.

THEOREM: no seal that (a) verifies on every leg and (b) reuses at least one honest public key is
anything OTHER than the exact honest seal. Z3 proves the NEGATION UNSAT for N = 2, 3.

TEETH (negative control): a BROKEN binding that folds only the payload into the context (SEAL_CTX =
C(payload), leg-vector NOT bound) admits a mixed swap — keep one honest leg, swap another to an
adversary key, same payload — Z3 returns `sat`. So binding the full leg-vector is load-bearing.

NOTE (out of crypto scope, stated honestly): a seal with NO honest leg — every leg an adversary key —
trivially "verifies" among those keys; that is not a downgrade of an honest seal but a wholly
different signer, and is rejected operationally by pinning the expected suite/leg-set (requireSuite).

Run:  python pqseal_legswap_z3.py     (exit 0 = theorem proven unsat for N=2,3 + teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (
    Solver, Function, Int, If, And, Or, Not, Implies, BoolVal, IntSort,
    unsat, get_version_string,
)


def prove_swap(n: int, bind_legs: bool = True):
    s = Solver()
    hkeys = [i + 1 for i in range(n)]   # honest leg owners 1..n
    pH = 0                              # honest payload

    if bind_legs:                       # SEAL_CTX = C(K_1..K_n, payload)
        C = Function("C", *([IntSort()] * (n + 1)), IntSort())
        ctx = lambda keys, p: C(*keys, p)
    else:                              # BROKEN: context folds ONLY the payload (leg-vector unbound)
        Cp = Function("Cp", IntSort(), IntSort())
        ctx = lambda keys, p: Cp(p)

    ctxH = ctx(hkeys, pH)
    k = [Int(f"k_{i}") for i in range(n)]   # the presented seal's leg public keys
    p = Int("p")                            # the presented payload
    c = ctx(k, p)

    # Collision-resistance, INSTANTIATED at the one pair that matters (the presented ctx vs the honest
    # ctx): if they collide, their pre-images are equal. This is exactly the CR assumption applied —
    # general over the symbolic seal variables (k, p), so the UNSAT below holds for ALL adversary
    # inputs — and avoids an expensive universal injectivity quantifier over the uninterpreted C.
    if bind_legs:  # equal pre-image = equal leg-vector AND equal payload
        s.add(Implies(c == ctxH, And(*[k[i] == hkeys[i] for i in range(n)], p == pH)))
    else:          # BROKEN context sees only the payload: a collision fixes only the payload
        s.add(Implies(c == ctxH, p == pH))

    is_honest = lambda key: Or(*[key == h for h in hkeys])
    # honest key verifies iff the context is the one honest ctx; an adversary key verifies anything.
    verifies = lambda key: If(is_honest(key), c == ctxH, BoolVal(True))

    accept = And(*[verifies(k[i]) for i in range(n)])
    reuses_honest_key = Or(*[is_honest(k[i]) for i in range(n)])
    is_honest_seal = And(*[k[i] == hkeys[i] for i in range(n)], p == pH)

    s.add(accept)                # every leg verifies...
    s.add(reuses_honest_key)     # ...the seal reuses at least one honest public key...
    s.add(Not(is_honest_seal))   # ...and it is NOT the exact honest seal  (= a mixed swap)
    return s.check()


def main() -> int:
    print(f"pqseal leg-swap resistance — Z3 {get_version_string()} SMT proof")
    fails = 0
    for n in (2, 3):
        if prove_swap(n, bind_legs=True) == unsat:
            print(f"  ok   N={n}: PROVEN — reusing any honest leg forces the EXACT honest seal; no mixed swap verifies (Z3 unsat)")
        else:
            print(f"  FAIL N={n}: leg-swap was NOT proven impossible"); fails += 1
    for n in (2, 3):
        if str(prove_swap(n, bind_legs=False)) == "sat":
            print(f"  ok   N={n}: TEETH — a payload-only (leg-unbound) context admits a mixed swap (Z3 sat)")
        else:
            print(f"  FAIL N={n}: no teeth (expected sat without leg-vector binding)"); fails += 1
    print("")
    if fails:
        print(f"pqseal_legswap_z3: FAIL ({fails})")
        return 1
    print("pqseal_legswap_z3: PASS — leg-swap resistance machine-checked for N=2,3.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
