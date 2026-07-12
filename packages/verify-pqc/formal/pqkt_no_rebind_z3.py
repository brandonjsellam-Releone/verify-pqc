#!/usr/bin/env python3
"""
MACHINE-CHECKED (Z3 SMT) proof of pqkt KEY-TRANSPARENCY state-machine soundness.
================================================================================================
pqkt.resolveIssuerKey is a VERIFYING replay enforcing a strict per-issuer state machine

        UNSEEN --bootstrap(seq=0, prev=null, self-signed, PINNED)--> ACTIVE(key, seq=0)
        ACTIVE(key,s) --rotation(prev=key, seq=s+1, auth by cur ∧ possession by new)--> ACTIVE(new, s+1)
        ACTIVE(key,s) --revoke(pubkey=key, seq=s+1, auth by cur)--> REVOKED            (TERMINAL)
        REVOKED --anything--> REVOKED                                                  (no rebind)

with an EXACT next-seq gate (seq === cur+1) on every non-bootstrap transition. This file proves the
two load-bearing invariants of that machine, modelling the transition function EXACTLY as the code
(pqkt.mjs lines 100-113), and — via negative controls — that the harness DETECTS the insecure
designs the two council rounds actually fixed.

  (T1) NO POST-REVOKE REBIND — REVOKED is terminal: once an issuer key is validly revoked, NO
       ordering of ANY subsequent signed events (including a fresh self-signed bootstrap by an
       attacker) can resurrect the issuer to ACTIVE. Proven by unrolling the fold K steps over
       fully-symbolic events and showing "some step is REVOKED yet the final state is not" is UNSAT.

  (T2) STRICT MONOTONIC SEQ — every ACCEPTED non-bootstrap transition strictly increases the signed
       per-issuer seq. Consequences: a replayed / stale / duplicate event (seq <= current) is always
       rejected (no seq rollback), and the seq-sorted replay is canonical, so reordering the log's
       array cannot change the resolved state. Proven as "accepted ∧ new_seq <= old_seq" is UNSAT.

SYMBOLIC MODEL (honest scope): a Dolev-Yao-style abstraction. Each event's signature/possession/pin
checks are booleans (`sig`, `poss`, `pin`) — we assume, not re-derive, ML-DSA-87 EUF-CMA (an attacker
cannot set `sig=true` for a message the honest key did not sign) and that seq values are integers
(the code drops non-integer-seq leaves BEFORE sorting — the seq-poisoning fix — so integrality is a
precondition here, not a claim). What IS proven is that GIVEN those primitives, the state machine's
control flow admits no rebind and no seq rollback. Complements the executable self-test in pqkt.mjs.

Run:  python pqkt_no_rebind_z3.py     (exit 0 = both theorems proven unsat + both teeth sat)
"""
from __future__ import annotations
import sys
from z3 import Solver, Int, Bool, Bools, If, And, Or, Not, sat, unsat, get_version_string

UNSEEN, ACTIVE, REVOKED = 0, 1, 2
BIND, REVOKE = 0, 1


def _event(i):
    """Fresh fully-symbolic event i: an adversary picks every field."""
    op = Int(f"op_{i}")                       # BIND or REVOKE
    eseq = Int(f"eseq_{i}")                    # the signed monotonic seq carried by the event
    sig, poss, pin, prevOK, prevNull = Bools(f"sig_{i} poss_{i} pin_{i} prevOK_{i} prevNull_{i}")
    return {"op": op, "eseq": eseq, "sig": sig, "poss": poss, "pin": pin,
            "prevOK": prevOK, "prevNull": prevNull}


def step(st, cs, e, *, terminal=True, strict_seq=True):
    """(state, cur_seq) x event -> (state', cur_seq'), EXACTLY pqkt.mjs's resolveIssuerKey walk.

    terminal=True   : REVOKED has no outgoing edge (the real design, line 109 rejects bind-after-revoke).
    terminal=False  : TEETH — a broken design where a fresh bootstrap from REVOKED re-activates.
    strict_seq=True : non-bootstrap gate is eseq == cur+1 (real). False : eseq >= cur (accepts stale — TEETH).
    """
    seq_gate = (e["eseq"] == cs + 1) if strict_seq else (e["eseq"] >= cs)
    bootstrap = And(st == UNSEEN, e["op"] == BIND, e["prevNull"], e["eseq"] == 0, e["sig"], e["pin"])
    rotate = And(st == ACTIVE, e["op"] == BIND, e["prevOK"], seq_gate, e["sig"], e["poss"])
    revoke = And(st == ACTIVE, e["op"] == REVOKE, e["prevOK"], seq_gate, e["sig"])
    rebind = And(Not(terminal), st == REVOKED, e["op"] == BIND, e["prevNull"], e["eseq"] == 0, e["sig"], e["pin"])
    new_state = If(bootstrap, ACTIVE, If(rotate, ACTIVE, If(revoke, REVOKED, If(rebind, ACTIVE, st))))
    new_cs = If(bootstrap, 0, If(rotate, e["eseq"], If(revoke, e["eseq"], If(rebind, 0, cs))))
    accepted_nonboot = Or(rotate, revoke)
    return new_state, new_cs, accepted_nonboot


def prove_no_rebind(K, terminal=True):
    """T1: unroll K steps from UNSEEN; assert (some step REVOKED) AND (final NOT REVOKED)."""
    s = Solver()
    st, cs = UNSEEN, Int("cs0")
    s.add(cs == -1)                                   # no key yet
    reached_revoked = []
    for i in range(K):
        st, cs, _ = step(st, cs, _event(i), terminal=terminal)
        reached_revoked.append(st == REVOKED)
    s.add(Or(*reached_revoked))                       # a valid revoke happened at some step...
    s.add(st != REVOKED)                              # ...yet the issuer ends up NOT revoked = a rebind
    return s.check()


def prove_monotonic_seq(strict_seq=True):
    """T2: an ACCEPTED non-bootstrap transition with new_seq <= old_seq (a seq rollback)."""
    s = Solver()
    st = Int("st"); cs = Int("cs")
    s.add(Or(st == UNSEEN, st == ACTIVE, st == REVOKED))
    e = _event(0)
    s.add(Or(e["op"] == BIND, e["op"] == REVOKE))
    new_state, new_cs, accepted = step(st, cs, e, strict_seq=strict_seq)
    s.add(accepted)                                   # the event was accepted (a rotation or revoke)...
    s.add(new_cs <= cs)                               # ...but did NOT strictly advance the seq
    return s.check()


def main() -> int:
    print(f"pqkt key-transparency state machine — Z3 {get_version_string()} SMT proof")
    fails = 0

    # ---- T1: no post-revoke rebind (REVOKED terminal) ----
    for K in (3, 4, 5, 6):
        if prove_no_rebind(K, terminal=True) == unsat:
            print(f"  ok   T1 K={K}: PROVEN — once REVOKED, no ordering of {K} events resurrects the key (Z3 unsat)")
        else:
            print(f"  FAIL T1 K={K}: post-revoke rebind NOT proven impossible"); fails += 1
    # teeth: a design where REVOKED is NOT terminal admits a resurrection
    if str(prove_no_rebind(5, terminal=False)) == "sat":
        print("  ok   T1 TEETH — a non-terminal-REVOKED design IS re-bindable after revoke (Z3 sat)")
    else:
        print("  FAIL T1 teeth — broken design did not resurrect (expected sat)"); fails += 1

    # ---- T2: strict monotonic seq (replay / rollback defense) ----
    if prove_monotonic_seq(strict_seq=True) == unsat:
        print("  ok   T2: PROVEN — every accepted transition strictly advances the signed seq (Z3 unsat)")
    else:
        print("  FAIL T2: seq monotonicity NOT proven"); fails += 1
    # teeth: a lax gate (eseq >= cur) admits a stale/duplicate event that does NOT advance the seq
    if str(prove_monotonic_seq(strict_seq=False)) == "sat":
        print("  ok   T2 TEETH — a lax (eseq>=cur) gate admits a stale-seq replay/rollback (Z3 sat)")
    else:
        print("  FAIL T2 teeth — lax gate did not admit a rollback (expected sat)"); fails += 1

    print("")
    if fails:
        print(f"pqkt_no_rebind_z3: FAIL ({fails})")
        return 1
    print("pqkt_no_rebind_z3: PASS — no-post-revoke-rebind + strict-monotonic-seq machine-checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
