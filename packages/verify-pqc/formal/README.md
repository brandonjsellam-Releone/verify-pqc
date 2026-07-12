# verify-pqc · formal/ — machine-checked proofs

Most post-quantum products stop at "self-attested + tested." This directory goes one level further:
**machine-checked formal proofs** of the load-bearing security properties, using the
[Z3](https://github.com/Z3Prover/z3) SMT solver. A proof here is not an example that passed — it is
Z3 establishing that **no counterexample exists** in the stated symbolic model (`unsat` on the
negation), and, via a negative control, that the harness would **detect** an insecure design.

## What is proven today

### `pqseal_antidowngrade_z3.py` — N-of-N AND-composition anti-downgrade
pqseal binds every leg's signature to the digest of the **full** leg-set
(`SEAL_CTX = H(v, suite, all-leg-pubkeys, payload)`). This proof establishes, under two explicit
assumptions, that **no leg-set downgrade can produce a verifying seal**:

- **(A1) Collision resistance** of the context hash — distinct leg-sets ⇒ distinct digests.
- **(A2) EUF-CMA** of each leg, no honest-key compromise — an honest leg verifies for a digest iff
  its signer actually signed it; the signer signed only the full-set context.

**Result:** `unsat` (property holds) for N = 2, 3, 4. **Teeth:** the same harness on a *broken*
design (legs sign the payload only, not the leg-set) returns `sat` — Z3 exhibits the downgrade —
so the leg-set binding is proven to be the load-bearing mechanism.

## The claim this earns (claim-hygiene-clean)

> pqseal's N-of-N anti-downgrade binding is **machine-checked with the Z3 SMT solver**: under
> collision-resistance of the context hash and EUF-CMA of each leg, no leg-set downgrade yields a
> verifying seal without forging an honest leg's signature.

This is a **precise property in a stated model** — never "unbreakable", "quantum-safe", or
"certified". The model's assumptions (A1, A2) are stated so a reviewer can check exactly what is and
is not proven. It complements — does not replace — the executable tests, the fuzz/differential
harnesses, and an eventual external cryptographic audit.

## Scope & honesty

- This is a **symbolic-model** proof (Dolev-Yao / EUF-CMA style), not a computational proof and not
  a proof of the underlying primitives (ML-DSA-87 / SLH-DSA / Ed25519 themselves — those rest on
  NIST FIPS 204 / 205 and the Ed25519 literature). FIPS 206 (FN-DSA/Falcon) remains a **draft**.
- In the Merkle proofs, the single uninterpreted `H` stands for the code's node hash; the
  implementation's `0x00` leaf / `0x01` node prefixes (pqsign.mjs) are what make the "leaf and node
  inputs never collide" part of the CR assumption realistic for SHA-256 — load-bearing in the code,
  assumed in the model.
- Proven: downgrade by **dropping** legs (`pqseal_antidowngrade_z3.py`) AND by **swapping** a leg to
  an adversary-controlled key (`pqseal_legswap_z3.py` — a seal that reuses any honest leg verifies
  only if it is the exact honest seal). Still out of scope here: computational (bit-level) security,
  and a seal with NO honest leg (a wholly different signer — rejected operationally by `requireSuite`
  / pinning, not by the binding).

Also proven (same method — precise property, machine-checked, with a teeth control):

- `domain_separation_z3.py` — **no cross-protocol / cross-context replay, modelled at the ENCODING
  level** (council upgrade, 10 Jul): real schemes sign ONE byte string, so the property rests on the
  injectivity of the (ctx, m) → bytes encoding, not on a primitive that magically binds two
  arguments. With an injective encoding and an ADAPTIVE signing history (the adversary may hold
  arbitrary other signatures), no signature verifies under a different context — `unsat`. TWO teeth:
  a context-less encoding replays (`sat`), and a NON-injective encoding (the non-prefix-free
  concatenation class) admits a replay with ZERO forgeries (`sat`). The companion
  `context_prefix_free_check.py` verifies the DEPLOYED registry (97 context strings) is pairwise
  prefix-free — discharging the injectivity assumption for the raw-concatenation (Ed25519) path.
- `merkle_inclusion_binding_z3.py` — **RFC-6962 tamper-evidence**: under collision-resistance of the
  node hash, a valid inclusion proof recomputes to a root produced by exactly ONE leaf — no leaf
  substitution without a hash collision. `unsat` for depths 1-4; a non-CR hash admits a collision
  (`sat`).
- `pqkt_no_rebind_z3.py` — **key-transparency state-machine soundness**: models pqkt's
  `UNSEEN → ACTIVE(key,seq) → REVOKED` replay exactly. (T1) REVOKED is terminal — once validly
  revoked, no ordering of any subsequent signed events (incl. a fresh attacker bootstrap) resurrects
  the issuer (`unsat`, K=3-6). (T2) every accepted transition strictly advances the signed seq, so a
  stale/duplicate event is always rejected (`unsat`). Teeth: a non-terminal-REVOKED design is
  re-bindable, and a lax `seq >= cur` gate admits a rollback (both `sat`).
- `pqseal_legswap_z3.py` — **anti-downgrade, leg-SWAP case**: strengthens the drop-only proof. Under
  CR of the context and EUF-CMA, a seal that reuses ANY honest leg's public key verifies only if the
  entire (leg-vector, payload) is exactly the honest seal — you cannot mix an honest leg with a
  swapped adversary-key leg. `unsat` for N=2,3; a payload-only (leg-unbound) context admits the mix
  (`sat`).
- `merkle_consistency_z3.py` — **MTH prefix-binding lemma**: under CR of the node hash, a committed
  size-m root pins all m committed leaves. `unsat` for m=1-5,8; a non-CR hash admits a rewrite
  (`sat`). (Council precision: this is the algebraic lemma; the deployed VERIFIER is the next entry.)
- `rfc6962_consistency_algo_z3.py` — **the deployed verifyConsistency ALGORITHM is sound** (council
  top fix): the RFC-6962 §2.1.2 path-folding code in pqsign.mjs is transcribed LINE-FOR-LINE into a
  symbolic executor (index arithmetic concrete, hash values symbolic). Theorem: for every proof
  vector and claimed old root, acceptance ⇒ the old root IS the true size-m prefix root of the new
  tree; wrong proof lengths are structurally rejected. `unsat` for (m,n) = (1,2),(2,3),(2,4),(3,5),
  (5,8) — both pow2/non-pow2 branches; without CR, Z3 forges a consistency proof (`sat`). Chained
  with the lemma above, the append-only guarantee holds END-TO-END through the deployed code path.
- `pqkt_rotation_auth_z3.py` — **rotation authorization** (the crypto layer beneath the state
  machine): (T1) under EUF-CMA of the current key, no rogue operator — even one controlling the whole
  log — can rotate an issuer key without the current key's authorization; (T2) the AUTH/POSS context
  separation blocks signature confusion — a possession-context signature never satisfies the
  authorization check. Both `unsat`; a possession-only design and a collapsed-context design each
  attack (`sat`).
- `pqkt_witness_quorum_z3.py` — **witness-quorum no-equivocation**: with ≤ d dishonest witnesses,
  `2k − n > d` makes a same-size split view impossible; below the bound Z3 exhibits it (`sat`).
- `pqtrace_chain_z3.py` — **pqtrace chain binding** (Wave 2, AI execution traces): the pqseal'd HEAD
  (count, final_hash) pins the ENTIRE hash-chained step sequence; post-seal edit/insert/delete/
  reorder/truncate all detectable. `unsat` n=1-5; without the prev_hash link an earlier step rewrites
  (`sat`).
- `pqai_provenance_binding_z3.py` — **AI Provenance Record: no BOM substitution** (the pqaibom ∧
  pqtrace join): under CR of the runtime-binding hash, a verifying record's AIBOM is EXACTLY the
  inventory the trace committed to — you cannot pair an honest run's trace with a different (cleaner /
  higher-graded) AIBOM. `unsat` for 1-4 components; a non-CR binding admits a substitution (`sat`).
- `pqaibom_grade_cap_z3.py` — **AIBOM grade-cap anti-overclaim** (AI Bill of Materials): transcribes
  ALL SIX of gradeAibom's caps and proves final=='A' ⇒ declared level ≥ L1 (T1); a restrictive
  licence forbids 'A' (T2); every cap only lowers, never inflates (T3); a mislabeled model (T4) and a
  flagged high-risk component (T6) each cap at 'C'; and the **COMPLETENESS FLOOR** (T5) — a model with
  no training data / retrieval corpus can never exceed 'C', so **omission-gaming (declare less to
  grade higher) is structurally impossible**, machine-checked. All `unsat`; a broken cap table that
  could raise the grade admits an 'A' at level 0 (`sat`). This is the epistemic-honesty guarantee — the
  letter cannot outrun the evidence tier; verifyAibom re-checks it, and this proves the check sound for all
  inputs.

## Reproduce

```
pip install z3-solver
python run_all.py     # runs every *_z3.py; exit 0 = all proven (unsat) + all teeth (sat)
```

## Roadmap (one proof at a time)

1. ✅ pqseal anti-downgrade — `pqseal_antidowngrade_z3.py`.
2. ✅ Domain separation / no cross-protocol replay — `domain_separation_z3.py`.
3. ✅ RFC-6962 inclusion-proof binding (tamper-evidence) — `merkle_inclusion_binding_z3.py`.
4. ✅ pqkt key-transparency: no post-revoke rebind + strict-monotonic seq — `pqkt_no_rebind_z3.py`.
5. ✅ pqseal leg-**swap** (adversary-key) downgrade — `pqseal_legswap_z3.py`.
6. ✅ MTH prefix-binding lemma — `merkle_consistency_z3.py`.
7. ✅ pqkt rotation authorization: no rogue rotation (ADAPTIVE adversary) + AUTH/POSS context
   separation — `pqkt_rotation_auth_z3.py`.
8. ✅ Deployed verifyConsistency algorithm soundness — `rfc6962_consistency_algo_z3.py`
   (+ `context_prefix_free_check.py`, the code-level companion discharging the encoding assumption).
9. ✅ Witness-quorum no-equivocation — `pqkt_witness_quorum_z3.py`: the exact governance bound for
   k-of-n witnessed STHs. PROVEN: with ≤ d dishonest witnesses, `2k − n > d` makes a same-size
   split view impossible (quorum intersection contains an honest witness, whose one-root-per-size
   rule forbids double-signing). TEETH: below the bound Z3 exhibits the split view — including
   n=5,k=3,d=1, proving `d ≤ k−1` alone is NOT sufficient (the sharper rule now documented in
   pqkt.mjs itself). Gossip remains the detection layer below the bound.
10. ✅ pqtrace chain binding — `pqtrace_chain_z3.py` (Wave 2, AI execution traces): the pqseal'd
    HEAD (count, final_hash) pins the ENTIRE hash-chained step sequence — same head ⇒ every step
    payload is the honest one; edit/insert/delete/reorder/truncate all detectable after sealing.
    `unsat` n=1-5; teeth: without the prev_hash link, an earlier step rewrites under the same final
    hash (`sat`). Scope: tampering AFTER sealing — runner honesty at recording time is pqtrace's
    stated v1 trust boundary.

**Council-review round (10 Jul 2026):** the suite was adversarially reviewed by two independent
model lineages (DeepSeek + Qwen seats) instructed to refute faithfulness, strawman theorems,
vacuity, and overclaims. Their confirmed findings drove: the encoding-level rebuild of the
domain-separation proof (+ TWO teeth + the deployed-registry prefix-free check), the adaptive
strengthening of rotation-auth T1, the algorithm-soundness proof of verifyConsistency (their top
fix), and scope-precision notes in the anti-downgrade and consistency proofs. All nine proofs +
the registry check pass: `python run_all.py` → 10/10.

These cover the load-bearing **symbolic** properties of the trust spine: anti-downgrade
(drop + swap), encoding-level domain separation, transparency (inclusion + prefix lemma + the
deployed consistency verifier + the witness-quorum equivocation bound), and key-lifecycle
(terminality + strict seq + adaptive rotation authorization) — each with a teeth control proving
the harness detects the insecure design. Remaining work is a **different tool class** and is
tracked, not claimed here: computational (bit-level) security reductions.

Each converts one more "self-attested" invariant into "machine-proven."
