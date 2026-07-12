# Auditor Quickstart — TRELYAN PQ SDK

A cold-start path for an external crypto / side-channel auditor. Reference code, **unaudited**, not FIPS-140-3
validated, not constant-time. Node ≥18.

## Run everything (≈ minutes)
```bash
cd trelyan-interop/packages/verify-pqc
npm ci           # deterministic install from package-lock.json (@noble/post-quantum, @noble/hashes, @noble/ciphers, @noble/curves)
node test-all.mjs            # every module self-test + the four assurance harnesses (run node test-all.mjs → ALL MODULES PASS)
node kat-conformance.mjs     # deterministic NIST-style KATs (ML-KEM-1024 / ML-DSA-87 / SLH-DSA-SHAKE-256s)
node spine-vectors.mjs       # PINNED transparency-spine vectors (must reproduce the hex)
node vectors-crosscheck.mjs  # 42,574-case differential vs an independent RFC-6962 reference
node fuzz-robustness.mjs     # negative/fuzz sweep (60 verifiers × 72 adversarial input classes = 4,320 calls) — asserts 0 fail-open + verifier totality
node conformance-vectors.mjs # Wave-2 cores KAT (25): pinned deterministic ids / did:trelyan / commitments reproduce from fixed seeds + round-trip & negatives (hedged ML-DSA/SLH sigs not byte-pinned)
node platform-conformance-vectors.mjs # platform engines KAT (19): pqmonitor/pqgate/pqflow/pqdelegate/pqconsentflow deterministic ids + policy_id/cert_id/receipt_id/ledger-head/parent_ref + round-trip & attenuation/violation negatives
node product-flows.mjs       # end-to-end product lifecycles through the real cores (Shield/Agent/Market/Consent) — 16 assertions
node pqai-provenance-e2e.mjs # AI PROVENANCE RECORD composition: pqaibom (declared inventory) ∧ pqtrace (runtime log) bound by the BOM-reality-drift bridge — catches "BOM says model X, runtime loaded Y"; 8 assertions, distinct declarant/runner identities
node tamper-binding.mjs      # signature-coverage — flips every signed field across the signing surface, asserts each is bound (1,064 assertions; covers all 12 of this session's signed cores incl. the 5 platform engines + 7 Wave-2 cores)
node domain-separation.mjs   # 0 bare sign/verify (191 sites), 65 distinct contexts, cross-context rejection
node canon-determinism.mjs   # canon() byte-identical across 28 modules + deterministic/injective
```
All four assurance harnesses (`fuzz-robustness`, `tamper-binding`, `domain-separation`, `canon-determinism`) plus the
differential validator run inside `test-all.mjs` too. They already caught + fixed 5 real signed-vs-checked / protocol
gaps (logged in `SECURITY_REVIEW.md`) — the auditor's job is to **confirm** these proofs are faithful, then focus on
side-channel/constant-time (the class the harnesses cannot cover).

## Machine-checked formal proofs (`formal/`)  — beyond tested, *proven*
Fourteen load-bearing invariants are **machine-checked with the Z3 SMT solver** — Z3 establishes no counterexample
exists in the stated symbolic model (`unsat` on the negation), and each proof carries a **teeth** control (a broken
design that Z3 shows IS attackable, `sat`) so the harness is demonstrably able to tell secure from insecure. The
suite was adversarially reviewed by two independent model lineages (10 Jul 2026) instructed to refute faithfulness /
strawman theorems / vacuity / overclaims; their confirmed findings are fixed and noted per proof.
```bash
pip install z3-solver
python formal/run_all.py     # 15/15 (14 proofs + registry check); exit 0 — wire into CI
```
| Proof | Property (symbolic model) |
|---|---|
| `pqseal_antidowngrade_z3.py` | N-of-N AND-composition: no leg **drop** yields a verifying seal (N=2,3,4) |
| `pqseal_legswap_z3.py` | no leg **swap** to an adversary key — reusing any honest leg forces the exact honest seal |
| `domain_separation_z3.py` | **encoding-level** domain separation: with an injective (ctx,m)→bytes encoding, no cross-context replay under an adaptive signing history; teeth incl. the non-prefix-free-concatenation replay (0 forgeries) |
| `context_prefix_free_check.py` | code-level companion: the deployed 97-context registry is pairwise prefix-free — discharges the encoding-injectivity assumption for the Ed25519 (raw ctx‖m) path |
| `merkle_inclusion_binding_z3.py` | RFC-6962 inclusion: a (root, audit-path) is produced by exactly one leaf (depths 1-4) |
| `merkle_consistency_z3.py` | MTH prefix-binding lemma: a committed size-m root pins all m leaves (m=1-5,8) |
| `rfc6962_consistency_algo_z3.py` | the **deployed verifyConsistency algorithm** (pqsign.mjs, transcribed line-for-line) accepts only the true size-m prefix root — (m,n)=(1,2),(2,3),(2,4),(3,5),(5,8), both branches; chained with the lemma = end-to-end append-only |
| `pqkt_no_rebind_z3.py` | key-transparency: REVOKED is terminal (no post-revoke rebind) + strict-monotonic seq |
| `pqkt_rotation_auth_z3.py` | no rogue rotation under an **adaptive** adversary (arbitrary other signatures) + AUTH/POSS context separation |
| `pqkt_witness_quorum_z3.py` | witnessed-STH governance bound: `2k − n > d` prevents same-size split views; Z3 exhibits the attack below the bound (d ≤ k−1 alone is NOT sufficient) |
| `pqtrace_chain_z3.py` | pqtrace (AI execution traces): the sealed head (count, final_hash) pins the entire hash-chained step sequence — post-seal edit/insert/delete/reorder/truncate all detectable (n=1-5) |
| `pqaibom_grade_cap_z3.py` | pqaibom grade caps (all 6, T1-T6): no 'A' below declared-Bound / restrictive licence; caps only lower; mislabel/high-risk → 'C'; **completeness floor** — a model with no training data/corpus can never exceed 'C' (omission-gaming structurally impossible) |
| `pqai_provenance_binding_z3.py` | AI Provenance Record: under CR of the runtime-binding hash, a verifying record's AIBOM is exactly the inventory the trace committed to — no BOM substitution (n=1-4) |
| `pqeval_posture_cap_z3.py` | pqeval (AI evaluation attestation): a top posture requires an EARNED (registry-validated) registered suite — no 'A' for a self-declared suite tier or under-rigorous eval; non-clean contamination / rigour / safety failures each cap (T1-T5) |
| `pqgovern_admission_z3.py` | GOVERN admission soundness (pqgovern-policy + gate): admit ⇒ owner-authenticated in-scope signed policy (T1) ∧ all record legs owner-pinned + cross-bound (T2) ∧ version/hash pin honored (T3) ∧ in-window when required (T4) ∧ signed criteria met (T5) ∧ the unsigned caller flag cannot shadow the decision (T6); non-vacuous (still admits honest cases); teeth H1-H3 exhibit the unpinned-policy / window-fail-open / criteria-shadow breaks |

Scope is stated honestly in `formal/README.md`: these are **symbolic** (Dolev-Yao / EUF-CMA) proofs of the protocol
logic, GIVEN the primitives (ML-KEM/ML-DSA/SLH-DSA/Ed25519 rest on FIPS 203/204/205 + the Ed25519 literature; FIPS 206
is a draft). They do **not** replace the executable tests above, computational (bit-level) reductions, or this audit —
they narrow what the audit must re-derive by hand.

## Read order
1. `AUDIT_DOSSIER.md` — scope, primitive inventory, **canonicalization**, the domain-separation **context registry**
   (all signing contexts verified distinct), the Merkle scheme.
2. `SPINE_SPEC.md` — formal spec of the transparency spine (leaf/node, inclusion §2.1.1, consistency §2.1.2, STH,
   consumer obligations) + the pinned conformance vectors. **This is the recommended first audit target** (it is the
   shared root of trust for pqtsa / pqkt / pqvault / pqinduct).
3. `THREAT_MODEL.md` — assets / adversaries / boundaries / per-asset threat → mitigation → residual.
4. `SECURITY_REVIEW.md` — the full multi-model council-review log (every finding, applied vs rejected-with-reason).
5. `ADVERSARY_MODEL.md` (capability→property→evidence) · `REPRODUCIBILITY.md` + `sbom.cdx.json` (deterministic build + deps).
   · `CANONICALIZATION_SPEC.md` (the signing serializer) · `SIGNED_OBJECTS.md` (signed-object call-graph inventory) ·
   `KEY_HANDLING.md` (key ownership / RNG / zeroization residual / supply chain) ·
   `formal/README.md` (the 14 Z3 machine-checked proofs + registry check — exact claims and scope).
6. `SDK.md` (catalog + test counts), `PACKAGING.md` (publishable-verifier vs held-SDK split), `AUDIT_RFP.md` (the engagement scope/SoW).

## Suggested scope priority (per the council's diligence flag)
Audit the **spine first** (pqsign Merkle/STH/inclusion/consistency) — everything else inherits its guarantees. Then
the hybrid handshake (pqtransport), the KEM envelope (polarseek), and the signature-context domain separation. The
50+ modules are breadth; the spine + the 4 primitives are the depth that matters. The Wave-2 product cores (pqshield /
pqcap / pqadmit / pqconsent / pqvc / pqfirmware / pqpay) are independent signed objects — each TOTAL/fail-closed, with
its capability→property→evidence row in `ADVERSARY_MODEL.md` and a KAT in `conformance-vectors.mjs`.

## What to focus on
- Second-preimage / domain-separation on leaf (`0x00`) vs node (`0x01`) bytes; index/tree_size binding; consistency
  edge cases (powers of two, m==n, m==1).
- Canonical-JSON determinism across languages (key ordering, number/string encoding) — signature stability depends on it.
- **Timing/side-channels** (out of scope of the reference; a primary audit deliverable).
- Consumer-obligation gaps (§6 of SPINE_SPEC): freshness/completeness needs witnesses (witness-service.mjs is the node).

## Known non-goals (documented, not findings to "discover")
Not constant-time; JSON not ASN.1/X.509 DER (pqpki); single-log completeness needs gossip; pqtsa is not an accredited
eIDAS QTSP; custody keys (polarseek/pqvault) are long-lived by design. See each module header + `AUDIT_DOSSIER.md §7`.
