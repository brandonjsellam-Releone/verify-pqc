#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of pqkt ROTATION AUTHORIZATION — the crypto layer beneath the state
machine. (pqkt_no_rebind_z3.py proved the state-machine CONTROL FLOW is sound with signatures
abstracted as booleans; this proves the SIGNATURE-AUTHORIZATION gate those booleans stand for.)
================================================================================================
pqkt accepts a key rotation (ACTIVE key H -> new key) ONLY if BOTH:
    (auth)        auth_sig verifies under the CURRENT key H over the AUTH context  (authorizes the change)
    (possession)  possession_sig verifies under the NEW key over the POSS context  (proves key control)
with AUTH and POSS being DISTINCT contexts (pqkt.mjs AUTH_CTX vs POSS_CTX). Two theorems:

  (T1) NO ROGUE ROTATION — under EUF-CMA of the current key H, an operator who does NOT hold H's
       secret (even one who controls the whole log) cannot get a rotation accepted unless H actually
       authorized it. ADAPTIVE model: H's signing history is UNCONSTRAINED (the adversary may have
       obtained arbitrary other H signatures, in any context, over any message) — the sole assumption
       is that H never signed THIS rotation core in the AUTH context. Acceptance anyway -> UNSAT.
       Teeth: a design that accepts on possession ALONE (no auth-under-current requirement) lets the
       attacker self-rotate -> `sat`.

  (T2) CONTEXT SEPARATION (no signature confusion) — a signature H produced in the POSSESSION context
       can NEVER satisfy the AUTHORIZATION check. Modelled from a no-forgery axiom pinning H's signed
       set to exactly {(POSS, core)}: the auth check needs (AUTH, core), and AUTH != POSS -> UNSAT.
       Teeth: collapse the two contexts (AUTH == POSS) and the possession signature is accepted as an
       authorization -> `sat`. This is the machine-checked form of the self-test's "auth/possession
       swapped -> rotation REJECTED".

SYMBOLIC MODEL (Dolev-Yao / EUF-CMA): `signed(key, ctx, msg)` is the ground truth of what each key's
owner actually signed. An attacker-controlled key may sign anything (its own secret). The honest
current key H is constrained by an explicit no-forgery axiom — the only assumption used, stated
openly. Not a proof of ML-DSA-87 itself.

Run:  python pqkt_rotation_auth_z3.py     (exit 0 = T1,T2 proven unsat + both teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (
    Solver, Function, Int, ForAll, And, Not, Implies, BoolSort, IntSort, unsat, get_version_string,
)

H = 100    # the honest CURRENT issuer key (attacker does NOT hold its secret)
A = 200    # an attacker-controlled key (attacker DOES hold its secret)
CORE = 7   # the rotation event's signed core (prev=H, new=A, seq=cur+1, ... — all bound inside)


def prove_no_rogue_rotation(require_auth: bool):
    """T1 with an ADAPTIVE adversary (council upgrade — DeepSeek): H's owner may have signed
    ARBITRARY other (ctx, msg) pairs (any signing history the adversary managed to obtain) — the
    ONLY constraint is that H never authorized THIS rotation core in the AUTH context. unsat then
    means: no amount of other H signatures lets a rogue operator rotate the issuer key."""
    s = Solver()
    AUTH, POSS = 1, 2
    signed = Function("signed", IntSort(), IntSort(), IntSort(), BoolSort())
    c, m = Int("c"), Int("m")
    # EUF-CMA, adaptive: everything else H may or may not have signed is FREE (adversary-chosen);
    # only the single fact "H did not sign (AUTH, CORE)" is assumed.
    s.add(ForAll([c, m], Implies(And(c == AUTH, m == CORE), Not(signed(H, c, m)))))
    # The attacker controls A and supplies a valid possession signature under its own new key.
    s.add(signed(A, POSS, CORE))
    auth_ok = signed(H, AUTH, CORE)        # auth_sig verifies under the CURRENT key
    poss_ok = signed(A, POSS, CORE)        # possession_sig verifies under the NEW key
    accept = And(auth_ok, poss_ok) if require_auth else poss_ok   # teeth: possession-only design
    s.add(accept)
    return s.check()


def prove_context_separation(distinct_ctx: bool):
    s = Solver()
    AUTH, POSS = (1, 2) if distinct_ctx else (1, 1)
    signed = Function("signed", IntSort(), IntSort(), IntSort(), BoolSort())
    c, m = Int("c"), Int("m")
    # No-forgery: H signed EXACTLY one thing — a POSSESSION-context signature over CORE (e.g. acting as
    # a new key in some other event). It never produced an AUTHORIZATION over CORE.
    s.add(ForAll([c, m], signed(H, c, m) == And(c == POSS, m == CORE)))
    # A rotation authorized by H requires an AUTH-context signature by H over CORE:
    auth_ok = signed(H, AUTH, CORE)
    s.add(auth_ok)     # can a POSSESSION signature ever satisfy the AUTHORIZATION check?
    return s.check()


def main() -> int:
    print(f"pqkt rotation authorization — Z3 {get_version_string()} SMT proof")
    fails = 0

    if prove_no_rogue_rotation(require_auth=True) == unsat:
        print("  ok   T1: PROVEN — no rotation accepted without the current key's authorization (Z3 unsat)")
    else:
        print("  FAIL T1: rogue rotation NOT proven impossible"); fails += 1
    if str(prove_no_rogue_rotation(require_auth=False)) == "sat":
        print("  ok   T1 TEETH — a possession-only design lets an attacker self-rotate (Z3 sat)")
    else:
        print("  FAIL T1 teeth — possession-only design did not self-rotate (expected sat)"); fails += 1

    if prove_context_separation(distinct_ctx=True) == unsat:
        print("  ok   T2: PROVEN — a possession-context signature never satisfies the auth check (Z3 unsat)")
    else:
        print("  FAIL T2: context separation NOT proven"); fails += 1
    if str(prove_context_separation(distinct_ctx=False)) == "sat":
        print("  ok   T2 TEETH — collapsing AUTH==POSS lets a possession sig authorize a rotation (Z3 sat)")
    else:
        print("  FAIL T2 teeth — collapsed contexts did not confuse (expected sat)"); fails += 1

    print("")
    if fails:
        print(f"pqkt_rotation_auth_z3: FAIL ({fails})")
        return 1
    print("pqkt_rotation_auth_z3: PASS — no-rogue-rotation + context-separation machine-checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
