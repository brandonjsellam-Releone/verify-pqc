# Audit RFP / Statement of Work — TRELYAN PQ SDK (owner-to-auditor handoff)

A ready-to-send scope for commissioning an independent crypto + side-channel audit. The code is a reference
implementation; this engagement is the gate that turns it into something deployable and sellable. **Owner action:**
select a firm, agree scope/fee, sign. Claude prepared this; it does not commission, sign, or pay.

## 1. Engagement objective
Independent assurance that the TRELYAN PQ SDK's cryptographic core is correct, that its security claims hold, and
that the implementation is free of exploitable defects — sufficient to drop the "unaudited reference" caveat and
move named modules toward production.

## 2. Scope (priority order — audit the SPINE first)
1. **Transparency spine** (`pqsign`): Merkle leaf/node domains, inclusion (RFC-6962 §2.1.1) + consistency (§2.1.2)
   verification, STH signing, canonical-leaf determinism. *Everything else inherits this.* Spec: `SPINE_SPEC.md`;
   pinned vectors: `spine-vectors.mjs`; 42,574-case differential: `vectors-crosscheck.mjs`.
2. **Shared primitives & usage**: ML-KEM-1024 / ML-DSA-87 / SLH-DSA-SHAKE-256s / Falcon-1024 via `@noble`
   (the libraries themselves are separately audited — audit our USAGE: contexts, canonicalization, hybrid combiners).
3. **Hybrid handshake** (`pqtransport`) + **KEM envelope** (`polarseek`/`pqvault`) + **domain-separation registry**
   (`AUDIT_DOSSIER §4` — confirm no signing-context collisions).
4. **Product verifiers**: pqgateway(-session), pqkt, pqtsa, pqpki, pqef, pqcbom-report, pqcompliance — verify the
   security properties each claims in its header + `ADVERSARY_MODEL.md`.

## 3. Specific questions the audit must answer
- Is the RFC-6962 inclusion/consistency implementation faithful, and are proofs bound to (index, tree_size)?
- Are all signing contexts domain-separated with no cross-protocol reuse? *(We now mechanically DEMONSTRATE this in
  `domain-separation.mjs`: 0 bare PQ sign/verify across 104 production sites, 25 globally-distinct `trelyan-*` contexts,
  cross-context+bare verification rejected. Auditor to CONFIRM the harness is faithful + assess any residual, e.g. the
  Ed25519 hybrid leg whose context is bound into its pre-image rather than a native ctx param.)*
- Is every signed field actually BOUND (no signed-vs-checked mismatch)? *(We now demonstrate this in `tamper-binding.mjs`:
  707 assertions, every leaf flipped across 15 signing verifiers incl. the spine + the paid Evidence Pack. Auditor to
  CONFIRM coverage is complete vs the signed-object inventory + extend to the tracked follow-ups.)*
- Is the hybrid KEM/signature composition sound (X-Wing-style combiner; AND-composition certs; PQXDH one-time prekeys
  now signed)?
- **Side-channel / constant-time**: where does non-constant-time behaviour leak key material? (PRIMARY deliverable —
  the reference is explicitly NOT constant-time; this is the highest-value finding class an external firm adds, since
  our harnesses already cover functional correctness / fail-closed / binding / domain-separation.)
- Are the documented "honest limits" complete, or are there undisclosed gaps (esp. the witness/freshness residuals)?
- Do the canonical-JSON rules guarantee cross-language determinism + collision resistance for signed structures?
  *(`canon()` is a manual recursive sorted-key walk — never delegates to `JSON.stringify` on a rich object, so
  `toJSON`/`Symbol` hooks can't alter the signed view; auditor to confirm + probe number/Unicode/duplicate-key edges.)*

## 4. Materials provided (all in this package, offline-reproducible)
`AUDITOR_QUICKSTART.md` (run/read order) · `AUDIT_DOSSIER.md` (primitives, canonicalization, context registry) ·
`SPINE_SPEC.md` · `THREAT_MODEL.md` · `ADVERSARY_MODEL.md` · `SECURITY_REVIEW.md` (the full multi-model council log —
every prior finding applied vs rejected-with-reason) · `REPRODUCIBILITY.md` + `sbom.cdx.json` · the test suite
(`test-all.mjs`, `kat-conformance.mjs`, `spine-vectors.mjs`, `vectors-crosscheck.mjs`, `fuzz-robustness.mjs`,
**`tamper-binding.mjs`** = signature-coverage proof, **`domain-separation.mjs`** = no-bare-context / context-uniqueness
proof, **`canon-determinism.mjs`** = canonicalization consistency + injectivity proof). Specs: **`CANONICALIZATION_SPEC.md`**
(the signing serializer, exactly) · **`SIGNED_OBJECTS.md`** (the call-graph inventory: every signed object → core →
context → verifier → coverage) · **`KEY_HANDLING.md`** (key ownership, RNG assumptions, the JS-zeroization residual,
custody-key lifetime, supply-chain/SBOM). The council log records 5 real signed-vs-checked / protocol gaps these
harnesses already caught and we fixed.

## 5. Expected deliverables from the auditor
A findings report (severity-ranked, with repro), a constant-time/side-channel assessment, conformance confirmation
against the pinned vectors, and a written opinion on which modules are fit to drop the "unaudited" caveat.

## 6. Candidate auditors (PQ-capable; owner selects — not an endorsement)
NCC Group, Trail of Bits, Kudelski Security, SandboxAQ, PQShield, Cure53, Quarkslab, or an academic applied-crypto
group. Prefer a firm with both **PQC** and **side-channel** practice. **→ See `AUDIT_ENGAGEMENT_KIT.md`** for the
firm-selection matrix (fit / JS-TS / side-channel), a primary recommendation (Trail of Bits or NCC Group), a
ready-to-send cover email, typical engagement shape, and the owner readiness checklist.

## 7. Out of scope (separate tracks)
Deployment/operations (owner); the multi-witness gossip network (operational, not code); eIDAS QTSP accreditation;
HSM/PKCS#11 custody; the unbuilt network-product layers (messaging/search). These do not block the core audit.

> Reminder: this RFP describes UNAUDITED reference code. Do not represent any module as production-ready or
> standards-conformant until the audit closes and the caveat is explicitly lifted per module.
