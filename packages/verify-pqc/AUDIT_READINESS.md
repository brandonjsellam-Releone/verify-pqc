# @trelyan/pq-sdk — third-party crypto audit readiness package (DRAFT)

Prepared so an external cryptographic auditor can start cold. The audit itself is an **owner/external** step — this
package scopes it. Status: reference implementation, **TRL ~5–6, NOT FIPS-140-3 validated, NOT constant-time, no
production keys touched.** `SDK_VERSION 0.16.0-draft`.

## 1. Scope for audit (priority order)

1. **Primitive usage correctness** — that `@noble/post-quantum` / `@noble/curves` / `@noble/ciphers` are invoked with
   correct parameters, domain separation, and no nonce/key reuse. See §3.
2. **Transparency / Merkle logic** — RFC-6962 inclusion (`verifyInclusionRFC`) and consistency (`verifyConsistency`)
   verification faithfulness; the four inclusion sites; the KT authorization state machine (`pqkt`).
3. **Protocol soundness** — the hybrid handshake (`pqtransport`), the PQ ratchets (`pqratchet`, `pqratchet-he`),
   the gateway attestation binding (`pqgateway` / `pqgateway-session`), the TSA (`pqtsa`).
4. **Evidence/claim gating** — `pqef` verdict logic + secret/schema guard; `pqclaimgate` / `pqverify`.

## 2. Primitive & parameter inventory (apex tier, enforced)

| Role | Primitive | FIPS |
|---|---|---|
| KEM (confidentiality) | X25519 **+ ML-KEM-1024** hybrid | 203 |
| Signature (load-bearing) | **ML-DSA-87** (hedged default; deterministic via fixed extraEntropy only in KAT) | 204 |
| Signature (diversity leg) | **SLH-DSA-SHAKE-256s** | 205 |
| On-chain / provenance ONLY | Falcon-1024 (FIPS 206 in development — never a compliance signature) | — |
| Hash | SHA-512 / SHA-384 / SHA3-256 (Merkle leaf/node 0x00/0x01 per RFC-6962) | 180/202 |
| AEAD | AES-256-GCM (counter nonces) · ChaCha20-Poly1305 | — |
| KDF | HKDF-SHA384 / SHA-512 | — |

Domain-separation contexts are distinct per protocol/role (e.g. transport initiator vs responder; gateway offer vs
attestation vs client-countersig; KT auth vs possession). Grep confirms zero sub-maximal parameter identifiers
outside the gateway's explicit interop-fallback ladder.

## 3. Known limits & assumptions the auditor should weigh (self-disclosed)

- Reference code, **not constant-time** → side-channel analysis out of scope of the current tests.
- `pqtransport`: deferred identity encryption (initiator privacy) + explicit key-confirm/state machine.
- `pqgateway-session`: attests the **client↔gateway leg only** (terminating proxy); transferable evidence needs the
  client countersignature; does not defend client+gateway collusion.
- `pqtsa`: NOT a qualified eIDAS QTSA (no accredited UTC source / ASN.1 TST / LTV-ERS); forward-secure signer = roadmap.
- `pqkt`: single-log core — **completeness / client-specific-view** (a log omitting events) needs a gossip/witness
  network; bootstrap keys are pin-or-TOFU (TOFU off by default); re-enrollment after revoke is out-of-band.
- `pqef`: secret value-scan regexes are heuristic; the schema is pinned to `pqef_version` 0.1.
- `polarseek`: KMS custody seals to a long-term key by design (not forward-secret); the KEK is single-purpose +
  transcript-bound.
- All "compliance/PQ-proven" verdicts require **verifier-supplied pinned keys** — never bundle-asserted claims.

## 4. What the auditor receives

- 29 self-testing modules; every module self-test + the four assurance harnesses pass (run `node test-all.mjs` → ALL MODULES PASS).
- Deterministic conformance vectors: `node kat-conformance.mjs` (drift detection) + `fips-conformance.mjs`.
- `SECURITY_REVIEW.md` — every internal council review, with findings APPLIED vs **rejected-with-reason** (e.g. the
  header-encryption "fixes" rejected as regressions; the POLARSEEK label item assessed as low-risk-no-change).
- `SDK.md` (module catalog), `RUN_SUMMARY.md` (build history), per-module headers stating honest limits.

## 5. Suggested audit method

Reproduce the test suite; then independently re-derive (a) the RFC-6962 inclusion/consistency verifiers against the
CT reference vectors, (b) the handshake transcript binding, (c) the KT authorization state machine's resistance to
replay/rollback/post-revoke-rebind/operator-minting. Adversarial focus on the four self-disclosed limits in §3.
