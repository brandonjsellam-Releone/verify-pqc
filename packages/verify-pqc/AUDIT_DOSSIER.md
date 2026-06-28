# TRELYAN PQ SDK — Audit Dossier (cold-start for the third-party crypto audit)

SDK 0.16.0-draft. This is the single entry point for an external crypto / side-channel audit. It indexes the other
docs and adds the formal cross-module crypto details an auditor needs first. **Posture:** reference implementations,
**unaudited**, **not** FIPS-140-3 validated, **not** constant-time. Hybrid-PQ + fail-closed by design.

> **AUDIT TARGET.** Package: `@trelyan/pq-sdk` (`sdk.mjs`, `SDK_VERSION 0.16.0-draft`). The audited module set is
> exactly the modules exercised by `node test-all.mjs` (every module self-test + the assurance harnesses) — that
> run is the authoritative inventory and must print `=== PQ SDK: ALL MODULES PASS ===`. All counts in this dossier
> are **as of the current commit**: re-run `test-all.mjs`, `tamper-binding.mjs`, `fuzz-robustness.mjs`, and
> `domain-separation.mjs` to reconcile any number here against the live harness output.

## 0. Read order
1. This dossier (scope, primitives, canonicalization, context registry, Merkle scheme).
2. `THREAT_MODEL.md` — assets / adversaries / boundaries / per-asset threat→mitigation→residual.
3. `SECURITY_REVIEW.md` — the full multi-model council-review log (findings applied vs rejected-with-reason).
4. `SDK.md` — module catalog + test counts. `AUDIT_READINESS.md` — scope/inventory. `PACKAGING.md` — release split.

## 1. Scope
- **In scope (this dir):** the reference SDK — `sdk.mjs` + the 29 modules. Built ONLY on `@noble/post-quantum`,
  `@noble/hashes`, `@noble/ciphers`, `@noble/curves` (audited, pure-JS).
- **Two packages (see PACKAGING.md):** the lean, publishable `@trelyan/verify-pqc` browser verifier (narrow `files`
  allowlist — excludes all SDK modules) vs `@trelyan/pq-sdk` (the full SDK, HELD until this audit clears).

## 2. Primitive & parameter inventory (apex tier, enforced)
| Role | Primitive | FIPS |
|---|---|---|
| KEM | X25519 **+ ML-KEM-1024** (hybrid; PQ leg load-bearing) | FIPS 203 |
| Signature (load-bearing) | **ML-DSA-87** | FIPS 204 |
| Signature (hash-based diversity) | **SLH-DSA-SHA2-256f** (pqseal, pqattest, pqcbom-report, slhdsa leg) · **SLH-DSA-SHAKE-256s** (pqef, pqinduct, kat-conformance, fips-conformance) | FIPS 205 |
| Signature (classical hybrid leg) | Ed25519 | — |
| Signature (on-chain/provenance ONLY) | Falcon-1024 | draft FIPS 206 |
| AEAD | AES-256-GCM / ChaCha20-Poly1305 | — |
| Hash | SHA-512 / SHA3-256 / SHAKE-256 | — |
| KDF | HKDF-SHA-384 / SHA-512 | — |
Grep-verified: no sub-maximal parameter identifiers in code (the only 768/65 is the gateway's *interop fallback ladder*, a feature, default-off).

## 3. Canonicalization (signed-bytes determinism)
All structured signatures sign `utf8(canon(object))` where `canon` is recursive JSON with **lexicographically
sorted object keys** and minimal separators (RFC-8785/JCS-style): `canon(obj) = '{' + sortedKeys.map(k => JSON.stringify(k)+':'+canon(v))+ '}'`.
PQEF v0.1 uses the same JSON profile (production profile = deterministic CBOR, recorded in `statement.canonicalization`).
Auditor check: every verifier re-serializes the *received* object with `canon` and never trusts caller-supplied signed-bytes.

## 4. Domain-separation context REGISTRY (ML-DSA `context` param / HKDF `info`) — all DISTINCT
Signature contexts (verified unique — no collisions):
| Module | Context string(s) |
|---|---|
| pqsign | `trelyan-pqsign-attestation-v1`, `trelyan-pqsign-sth-v1` |
| pqtransport | `trelyan-transport-auth-v1/initiator`, `…/responder` |
| pqgateway | `trelyan-gateway-offer-v1`, `trelyan-gateway-session-v1` |
| pqgateway-session | `trelyan-gateway-client-countersig-v1` |
| pqtsa | `trelyan-pqtsa-token-v1` |
| pqkt | `trelyan-pqkt-auth-v1`, `trelyan-pqkt-possession-v1`, `trelyan-pqkt-witness-v1` |
| pqpki | `trelyan-pqpki-cert-v1`, `trelyan-pqpki-crl-v1` |
| pqcbom-report | `trelyan-pqcbom-evidence-pack-v1`, `trelyan-pqcbom-evidence-pack-slh-v1` (SLH-DSA leg) |
| pqcompliance | `trelyan-pqcompliance-report-v1` |
| pqseal | `trelyan-pqseal-v1` |
| pqmarket | `trelyan-pqmarket-listing-v1`, `trelyan-pqmarket-attestation-v1` |
| pqx3dh | `trelyan-pqx3dh-prekey-bundle-v1` |
| polarseek | `trelyan-kms-custody-v1` |
| pqguard | `trelyan-dual-control-approval-v1`, `trelyan-audit-log-head-v1` |
| pqinduct | `trelyan-lemniscate-manifest-v1`, `…-inner-ring-v1`, `…-credential-v1` |
| pqcouncil / pqclaimgate / pqanswer | `trelyan-council-attestation-v1` / `trelyan-claimgate-attestation-v1` / `trelyan-answer-provenance-v1` |
| pqindex | `trelyan-qds-omega-index-root-v1` |
HKDF info labels (separate namespace): `QuantumMesh-root/msg-v1`, `QuantumMesh-HE-root/msg/hdr-v1`, `QDS-Omega-KEM-v1`, `TRELYAN-KMS-v1-kek`, `TRELYAN-TRANSPORT-v1`.
**Auditor focus:** confirm uniqueness (done here) and that initiator/responder + auth/possession are never cross-verifiable.

## 5. Merkle / transparency scheme (pqsign — shared by pqsign, pqtsa, pqinduct, pqkt, pqvault)
- Leaf = `SHA-256(0x00 ‖ data)`, node = `SHA-256(0x01 ‖ left ‖ right)` (RFC-6962). Lone nodes promoted.
- **Inclusion** = `verifyInclusionRFC(leaf, index, treeSize, auditPath, root)` — RFC-6962 §2.1.1, directions DERIVED
  from (index, tree_size), proof length checked. Bundles also require `inclusion.tree_size === signed STH.tree_size`.
- **Consistency** = `verifyConsistency(m, n, root1, root2, proof)` — RFC-6962 §2.1.2, append-only/no-rewrite.
- STH = ML-DSA-87 over `{tree_size, root, ts}`. Gemini cross-checked the algorithms; `vectors-crosscheck.mjs`
  differential-tests an independent reference over 42,574 cases; each site has a non-power-of-2 all-members test.
**Auditor focus:** second-preimage on leaf/node domain bytes; index/tree_size binding; consistency edge cases.

## 6. Per-module security claims → evidencing tests
Each module header states its claims + honest limits; self-tests assert them (see `SDK.md` for counts). Highlights:
pqtransport (SIGMA, UKS/reflection/downgrade); pqgateway (downgrade/replay/lying-gateway); pqgateway-session
(transcript-bound attestation + client countersig); pqkt (CONIKS authority chaining, monotonic seq, post-revoke-rebind
block, equivocation/rollback); pqpki (hybrid strip-resistance, path_len, root-pinning); pqratchet-he (metadata privacy);
pqtsa (legacy re-stamp + multi-TSA threshold); pqef/pqcbom-report (typed allowlist, grade-recompute anti-forgery).
Negative coverage: `fuzz-robustness.mjs` — 0 fail-open observed across 3,240 adversarial calls (45 verifiers × 72 input classes); verdict verifiers returned no throw across the corpus. Plus `tamper-binding.mjs` (signature coverage, 15 verifiers), `domain-separation.mjs` (0 bare / 25 distinct contexts), `canon-determinism.mjs` (canonicalization consistency).

## 7. Known limits / OUT of audit scope to fix (documented, not defects to "find")
- NOT constant-time; timing/side-channel hardening is a primary audit deliverable.
- JSON not ASN.1/X.509 DER (pqpki); no name-constraints/full key-usage. CBOM is a lexical scanner (comment-aware).
- pqkt single-log completeness needs a gossip/witness network (witness-service is the node; operating ≥1 independent
  witness is owner-operational). pqtsa is not an accredited eIDAS QTSA. polarseek/pqvault custody keys are long-lived by design.

## 8. Test inventory
`node test-all.mjs` runs every module self-test + the four assurance harnesses (run `node test-all.mjs` → ALL MODULES PASS),
plus `node kat-conformance.mjs` (deterministic KATs), `node vectors-crosscheck.mjs` (42k+ differential), and the
fuzz sweep. All green at 0.16.0-draft.
