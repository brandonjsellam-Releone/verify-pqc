# Adversary Model — TRELYAN PQ SDK (audit input)

Tabular capability → claimed property → evidence/mitigation, per the council (Mistral). Reference, **unaudited**;
"evidence" = the test/design that supports the claim, NOT an assurance guarantee. Complements `THREAT_MODEL.md`.

## Global assumptions
- The verifier **pins** the relevant public key(s) out-of-band (issuer/log/CA/TSA/signer). Trust does not come from
  keys carried in the artifact.
- Adversary may be a **store-now-decrypt-later quantum** adversary (future), an **active network MITM**, and/or a
  **malicious log/gateway/CA operator** that can append/serve arbitrary data but does **not** hold pinned secret keys.
- **NOT defended:** an adversary holding a pinned secret key; collusion of all independent parties; timing/EM
  side-channels (reference is not constant-time); traffic analysis (timing/volume/IP).

## Capability → property → evidence

| Adversary capability | Claimed property (holds?) | Evidence / mitigation |
|---|---|---|
| Quantum computer (Shor) vs confidentiality | Hybrid KEM secrecy holds (ML-KEM-1024 leg) | X25519+ML-KEM-1024 envelopes (polarseek/pqvault/pqtransport); HNDL-safe |
| Quantum computer (Shor) vs signatures | Unforgeable (ML-DSA-87 load-bearing) | ML-DSA-87 everywhere; Ed25519/Falcon only as classical/on-chain legs |
| Grover (halved symmetric strength) | ≥128-bit quantum security | AES-256-GCM / ChaCha20-Poly1305; SHA-512/SHA3-256 |
| MITM strips the PQ leg in transit | Downgrade detected | Signed capability offers (pqgateway); hybrid cert binds both keys (pqpki); both sigs required |
| MITM swaps identity (UKS/reflection) | Mutual auth holds | pqtransport binds both identities into the transcript; distinct initiator/responder contexts |
| Malicious log rewrites history | Append-only detected | RFC-6962 consistency proofs (`verifyConsistency`); STH signature |
| Malicious log forges a position | Position-binding (if index checked) | Inclusion bound to (index, tree_size); consumer must check the expected index |
| Malicious log equivocates (split view) | Detectable ONLY with witnesses | Single log can't self-detect; needs gossip/`witness-service.mjs` (residual) |
| Malicious log serves a stale "current" state | Rollback resistance CONDITIONAL | Latest-leaf + FRESH STH required; freshness needs gossip/witnesses (residual) |
| Log operator mints a key it doesn't control (KT) | Prevented | CONIKS authority chaining: events signed by the issuer's current key; operator can't (pqkt) |
| Post-revoke rebind / replay (KT) | Prevented | Monotonic seq + UNSEEN→ACTIVE→REVOKED state machine (pqkt) |
| Stale-CRL replay (PKI) | Detected | CRL `this_update`/`next_update` + `crl_number` anti-rollback (pqpki) |
| Lying gateway claims PQ over a classical session | Defeated (transferable w/ countersig) | Attestation bound to the real transcript hash; client countersignature (pqgateway-session) |
| Forged "grade A" over insecure findings | Caught | `verifyEvidencePack` recomputes the grade from findings (pqcbom-report) |
| Secret smuggled into an evidence bundle | Rejected | Typed version-pinned schema allowlist + leaf-value secret scan (pqef) |
| Tampered ciphertext / proof / signature | Rejected (fail-closed) | AEAD auth tags; signature verify; fuzz sweep = 0 fail-open OBSERVED across 1,856 inputs (verifiers made total) |
| Malformed/adversarial input to a verifier | No crash (fail-closed) | `fuzz-robustness.mjs`: 1,856 calls (32 verifiers × 58 classes), no throw observed; `tamper-binding.mjs` field-coverage |

## Residual risks (require owner action / out of code scope)
Third-party crypto + **side-channel** audit (timing/EM — primary deliverable); a **multi-witness gossip network**
(equivocation/freshness/completeness for pqkt + pqvault); accredited time source / eIDAS QTSP status (pqtsa);
HSM/PKCS#11 key custody; name-constraints/EKU for untrusted PKI intermediates. See `THREAT_MODEL.md`, `SPINE_SPEC.md`.
