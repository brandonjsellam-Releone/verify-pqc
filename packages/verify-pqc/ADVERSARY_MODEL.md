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
| Tampered ciphertext / proof / signature | Rejected (fail-closed) | AEAD auth tags; signature verify; fuzz sweep = 0 fail-open OBSERVED across 4,320 inputs (verifiers made total) |
| Malformed/adversarial input to a verifier | No crash (fail-closed) | `fuzz-robustness.mjs`: 4,320 calls (60 verifiers × 72 input classes), no throw observed; `tamper-binding.mjs` 1,064-assertion field-binding coverage |
| A worker agent escalates beyond its delegated authority (widen tool/scope/uses, bypass a caveat, splice/replay the chain) | Caught | pqdelegate: attenuation enforced 3 ways — caveat ACCUMULATION (request checked vs root + every link), tool/scope/max_uses NARROW-only, and a signed delegation-authority chain (each link signed by the prior grantee + parent_ref binds order) + leaf holder-PoP; council-found scope/max_uses widening gaps closed |
| Over-capture / double-capture / replay a payment authorization across the capture lifecycle | Caught | pqflow: merchant-signed hash-chained capture log; verifyFlow RECOMPUTES the state and enforces Σcaptures ≤ authorized, no-capture-after-close, refund ≤ captured; per-flow unique nonces + durable cross-flow ledger; genesis auth re-verified under the pinned payer (NOT money movement — intent only) |
| Weaken the CI/CD deploy gate (lower the floor) or forge an "allow" decision | Caught | pqgate: admission rules are an authority-SIGNED policy (tampering breaks policy_id+sig); the allow/deny decision is hybrid-signed and RECOMPUTE-verifiable (verifyDecision re-derives allow+cert_id+app+version+cert_level from cert+policy) + a tamper-evident admission log; fail-dangerous (won't act under an unverified policy); consumer pins its current `policy_id` via `trustedPolicyId` to refuse a replayed OLD-policy decision (anti-rollback, mirrors pqadmit minVersion) |
| Hide a posture regression / replay a stale "all-good" digest / forge an "improving" trend | Caught | pqmonitor: tamper-evident hash-chained ledger (altering a past snapshot breaks the chain) + verifyPostureDigest RECOMPUTES current grade & trend (+ `since`) from the ledger + anti-rollback `minSeq`; fail-dangerous ingest (an unverified report is never recorded) + anti-replay at ingest (`generated_at` strictly-newer — a replayed OLD report can't append as "latest" to mask a regression) |
| Stolen agent capability token (no holder key) | Useless (holder-bound) | pqcap: holder proof-of-possession over a fresh challenge; agent_pub bound to the signed agent id |
| Over-broad tool call via an extra/unconstrained arg | Refused (least-privilege) | pqcap: arg caveats + deny_unlisted/args_allowed whitelist; strict-number arg_max; fail-closed max_uses (durable ledger) |
| Deploy a swapped, rolled-back, or revoked build | Blocked at admission | pqadmit: artifact-digest binding (deployed binary must hash to the cert) + monotonic minVersion floor + revocation deny-set |
| Flash a swapped or rolled-back firmware | Refused before flash | pqfirmware: manifest binds the binary's hash + version strictly-newer (anti-rollback); device verify-before-flash |
| Forged clean grade over a vulnerable estate | Caught (grade recomputed) | pqshield: the A–F grade is re-derived by the verifier from the signed assets; FAIL-DANGEROUS scoring (unknown→CRITICAL) |
| Process beyond / without the subject's consent | Refused (deny-by-default) | pqconsent: per-purpose×category scope, subject-signed; only the subject revokes (deny-list propagation = residual) |
| Controller accesses personal data AFTER the subject withdrew (or outside the granted scope) | Detected — cryptographically evidenced | pqconsentflow: a controller-SIGNED hash-chained lifecycle log (grant→access→withdraw); verifyConsentFlow RECOMPUTES the permitted state and flags any post-withdrawal / out-of-scope access in `violations[]` — the authentic-but-violating log IS the evidence; grant + withdrawal are the SUBJECT's pqconsent receipt/revocation bound into the chain; honest scope = verifiable EVIDENCE, NOT access enforcement |
| Replay a payment authorization (double-spend) | Refused (fail-closed) | pqpay: nonce normalized to string + verifyAuthorization fail-closed without a durable seen-nonce ledger; verifyAndConsume commit-on-success |
| Auditor known-answer reproducibility | Deterministic values reproduce | `conformance-vectors.mjs`: 25 KAT (ids / did:trelyan / derived commitments) reproduce from fixed seeds; hedged ML-DSA/SLH sigs covered by round-trip + negatives |

## Residual risks (require owner action / out of code scope)
Third-party crypto + **side-channel** audit (timing/EM — primary deliverable); a **multi-witness gossip network**
(equivocation/freshness/completeness for pqkt + pqvault); accredited time source / eIDAS QTSP status (pqtsa);
HSM/PKCS#11 key custody; name-constraints/EKU for untrusted PKI intermediates; **durable atomic nonce/use ledgers**
(pqpay/pqcap anti-replay — an in-memory ledger resets on restart) + **revocation deny-list propagation** (pqadmit/pqconsent —
a withheld revocation admits; mitigate with short expiry + an anchored online/transparency-log check). See `THREAT_MODEL.md`, `SPINE_SPEC.md`.
