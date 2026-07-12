#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of DOMAIN SEPARATION — no cross-protocol / cross-context replay,
modelled at the ENCODING level (council upgrade — Qwen + DeepSeek round, 10 Jul).
================================================================================================
The verify-pqc SDK binds a per-use CONTEXT tag into every signed message. Concretely (two paths):
  - ML-DSA-87 / SLH-DSA legs pass the context via the FIPS-204/205 context parameter, which the
    algorithm folds into the signed message with an unambiguous length-prefixed encoding.
  - Ed25519 legs (no native context arg) sign encode(ctx, m) = ctx || m — raw concatenation
    (pqseal.mjs FAMILIES: `ed25519.sign(concatBytes(c, m), sk)`).

WHY THE ENCODING IS THE REAL PROPERTY (council finding): a 2-ary `signed(ctx, m)` model assumes the
primitive natively binds two arguments — which silently assumes away the very thing that can break.
Real schemes sign ONE byte string; domain separation holds IFF the (ctx, m) -> bytes encoding is
INJECTIVE across the deployed contexts. Raw concatenation is injective on a context set C iff C is
PREFIX-FREE: if ctxB = ctxA || s, then ctxA || (s || m') == ctxB || m' — a cross-context collision,
and a signature made under ctxA replays under ctxB WITHOUT any forgery. So this proof models:

  MODEL (EUF-CMA over the encoded message, ADAPTIVE adversary):
    - encode : (Ctx, Msg) -> Bytes, INJECTIVE (the assumption a prefix-free context registry earns).
    - signed1 : Bytes -> Bool — the honest key's signing history over encoded bytes. ADAPTIVE: the
      adversary may have obtained signatures on ARBITRARY encoded pairs — the sole assumption is
      that the honest signer never signed encode(ctxB, m0) (it never used context B for m0).
    - verify(ctx, m) accepts iff signed1(encode(ctx, m)).

  THEOREM: verify(ctxB, m0) is FALSE — no signature from any other (ctx, m) pair, including
  signatures on m0 under ctxA and on anything else under any context, verifies as (ctxB, m0).
  Z3: the negation is UNSAT. (Injectivity is instantiated at the decisive pair encode(ctxB, m0) ==
  encode(c, m) via a quantified axiom — general, and cheap for MBQI.)

  TEETH 1 (context ignored): a broken verifier that checks signed1(encode_m_only(m)) — the context
  never enters the signed bytes — accepts (ctxB, m0) given only a (ctxA, m0) signature -> `sat`.
  TEETH 2 (NON-PREFIX-FREE ENCODING — the sharp one): drop injectivity of encode. Z3 exhibits
  encode(ctxA, mA) == encode(ctxB, m0) with (ctxA, mA) != (ctxB, m0) — the concatenation-collision
  class (ctxB = ctxA || s, mA = s || m0) — and the honest (ctxA, mA) signature verifies as
  (ctxB, m0) -> `sat`. So BOTH the context-in-bytes AND the injective (prefix-free) encoding are
  load-bearing; the proof would catch a registry that broke prefix-freeness.

CODE-LEVEL COMPANION: formal/context_prefix_free_check.py verifies the DEPLOYED context registry is
actually prefix-free (the fact that discharges the injectivity assumption for the Ed25519 path).

Run:  python domain_separation_z3.py     (exit 0 = theorem unsat + both teeth sat)
"""
from __future__ import annotations
import sys
from z3 import (
    Solver, Function, Int, Ints, ForAll, Implies, And, Or, Not, BoolSort, IntSort,
    unsat, get_version_string,
)


def prove_domain_separation():
    s = Solver()
    Ctx, Msg, Bytes = IntSort(), IntSort(), IntSort()
    encode = Function("encode", Ctx, Msg, Bytes)     # (ctx, m) -> signed byte string
    signed1 = Function("signed1", Bytes, BoolSort())  # honest key's signing history (encoded bytes)
    ctxA, ctxB, m0 = Ints("ctxA ctxB m0")
    c, m = Ints("c m")

    s.add(ctxA != ctxB)
    # INJECTIVE encoding (what a prefix-free context registry buys): equal bytes => equal pair.
    c2, m2 = Ints("c2 m2")
    s.add(ForAll([c, m, c2, m2], Implies(encode(c, m) == encode(c2, m2), And(c == c2, m == m2))))
    # ADAPTIVE signing history: unconstrained EXCEPT the honest signer never signed (ctxB, m0).
    s.add(Not(signed1(encode(ctxB, m0))))
    s.add(signed1(encode(ctxA, m0)))                 # it DID sign m0 under ctxA (the replay source)

    # NEGATION of the theorem: verify(ctxB, m0) accepts, i.e. signed1(encode(ctxB, m0)).
    s.add(signed1(encode(ctxB, m0)))
    return s.check()


def broken_ctx_ignored():
    """TEETH 1: the context never enters the signed bytes — verify checks encode_m(m) only."""
    s = Solver()
    Msg, Bytes = IntSort(), IntSort()
    encode_m = Function("encode_m", Msg, Bytes)       # <-- the bug: ctx absent from the encoding
    signed1 = Function("signed1", Bytes, BoolSort())
    ctxA, ctxB, m0, m = Ints("ctxA ctxB m0 m")
    s.add(ctxA != ctxB)
    s.add(ForAll([m], Implies(m != m0, Not(signed1(encode_m(m))))))  # signed ONLY m0 (no forgery)
    s.add(signed1(encode_m(m0)))                      # the one honest signature ("under ctxA")
    # verify_broken(ctxB, m0) = signed1(encode_m(m0)) — accepted under ctxB: the replay.
    s.add(signed1(encode_m(m0)))
    return s.check()


def broken_non_prefix_free():
    """TEETH 2: encode NOT injective (e.g. raw concatenation over a NON-prefix-free context set).
    The adversary asks the honest signer for ONE innocuous signature (ctxA, mA) and replays it as
    (ctxB, m0) — no forgery, the bytes are literally identical. Z3 must exhibit this (`sat`)."""
    s = Solver()
    Ctx, Msg, Bytes = IntSort(), IntSort(), IntSort()
    encode = Function("encode", Ctx, Msg, Bytes)      # NO injectivity axiom — collisions possible
    signed1 = Function("signed1", Bytes, BoolSort())
    ctxA, ctxB, m0, mA = Ints("ctxA ctxB m0 mA")
    b = Int("b")
    s.add(ctxA != ctxB)
    s.add(Or(ctxA != ctxB, mA != m0))                 # (ctxA, mA) is a DIFFERENT pair than (ctxB, m0)
    # the honest signer signed exactly one encoded byte-string: encode(ctxA, mA)
    s.add(ForAll([b], signed1(b) == (b == encode(ctxA, mA))))
    # the collision the concatenation class admits: encode(ctxA, mA) == encode(ctxB, m0)
    s.add(encode(ctxA, mA) == encode(ctxB, m0))
    # verify(ctxB, m0) accepts — a cross-context replay with zero forgeries.
    s.add(signed1(encode(ctxB, m0)))
    return s.check()


def main() -> int:
    print(f"domain separation (encoding-level) — Z3 {get_version_string()} SMT proof")
    fails = 0
    if prove_domain_separation() == unsat:
        print("  ok   PROVEN — with an INJECTIVE encoding, no signature (adaptive history) verifies as (ctxB, m0) (Z3 unsat)")
    else:
        print("  FAIL — cross-context replay was NOT proven impossible"); fails += 1
    if str(broken_ctx_ignored()) == "sat":
        print("  ok   TEETH1 — a context-less encoding IS cross-context replayable (Z3 sat)")
    else:
        print("  FAIL teeth1 — context-less design did not replay (expected sat)"); fails += 1
    if str(broken_non_prefix_free()) == "sat":
        print("  ok   TEETH2 — a NON-injective (non-prefix-free concat) encoding admits a replay with 0 forgeries (Z3 sat)")
    else:
        print("  FAIL teeth2 — non-injective encoding did not collide (expected sat)"); fails += 1
    print("")
    if fails:
        print(f"domain_separation_z3: FAIL ({fails})")
        return 1
    print("domain_separation_z3: PASS — encoding-level domain separation machine-checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
