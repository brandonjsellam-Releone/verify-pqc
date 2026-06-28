# Signed-Object Inventory (audit input — call-graph map)

The full map of every authenticated structure in the SDK: its signed core, its domain-separation context, its verifier,
and its test coverage. Requested by the council ("inventory by call-graph; reconcile 25 contexts vs 28 modules"). Each
context is checked globally distinct + bare-free by `domain-separation.mjs`; each verifier is exercised total/fail-closed
by `fuzz-robustness.mjs`; the ✓tamper rows are demonstrated field-bound by `tamper-binding.mjs` (runnable test evidence
over the stated cases — not formal proofs; the third-party audit is the gate).

## Signing surfaces (one ML-DSA-87 context each)
| Module | Signed object | Context (`trelyan-…`) | Verifier | Signed-coverage test |
|---|---|---|---|---|
| pqsign | artifact attestation | `…pqsign-attestation-v1` | `verifyArtifact` / `verifyBundle` | **✓ tamper (SPINE, 43)** + fuzz |
| pqsign | signed tree head (STH) | `…pqsign-sth-v1` | `verifySTH` | ✓ tamper (in bundle) + fuzz |
| pqsign | audit-log head | `…audit-log-head-v1` | (log-head verify) | fuzz · *tracked* |
| pqtsa | timestamp token (TST) | `…pqtsa-token-v1` | `verifyTimestamp` / `verifyRestamp` | **✓ tamper (9)** + fuzz |
| pqkt | key event (bind/revoke) | `…pqkt-auth-v1` | `resolveIssuerKey` / `verifyKeyEventInclusion` | **✓ tamper (49)** + fuzz |
| pqkt | key possession | `…pqkt-possession-v1` | (possession proof) | fuzz · *tracked* |
| pqkt | witness co-signature | `…pqkt-witness-v1` | `verifyWitnessedSTH` | fuzz |
| pqpki | hybrid cert (ML-DSA+Ed25519) | `…pqpki-cert-v1` | `verifyCert` / `verifyChain` | **✓ tamper (15)** + fuzz · Ed25519 leg ctx-bound in pre-image |
| pqpki | CRL (revocation list) | `…pqpki-crl-v1` | `checkRevocation` | **✓ tamper (9)** + fuzz |
| pqx3dh | prekey bundle | `…pqx3dh-prekey-bundle-v1` | `verifyPrekeyBundle` | **✓ tamper (8)** + fuzz · one-time prekeys signed |
| pqmarket | capability listing | `…pqmarket-listing-v1` | `verifyListing` | **✓ tamper (10)** + fuzz |
| pqmarket | reviewer attestation | `…pqmarket-attestation-v1` | `verifyAttestationInclusion` / `computeReputation` | **✓ tamper (47)** + fuzz |
| pqindex | signed shard | `…qds-omega-index-root-v1` | `verifyShard` | **✓ tamper (12)** + fuzz · `ts` now bound |
| pqgateway | capability offer | `…gateway-offer-v1` | `verifyOffer` | **✓ tamper (6)** + fuzz |
| pqgateway | session attestation | `…gateway-session-v1` | `verifySession` | **✓ tamper (12)** + fuzz |
| pqgateway | client countersignature | `…gateway-client-countersig-v1` | `acceptSession` path | fuzz · *tracked* |
| pqcompliance | compliance report | `…pqcompliance-report-v1` | `verifyComplianceReport` | **✓ tamper (111)** + fuzz · summary/disclaimer/posture now bound |
| pqcbom-report | PQC Evidence Pack (PAID) | `…pqcbom-evidence-pack-v1` | `verifyEvidencePack` | **✓ tamper (170, PAID)** |
| pqcbom-report | Evidence Pack SLH-DSA leg | `…pqcbom-evidence-pack-slh-v1` | `verifyEvidencePack` (hybrid) | **✓ tamper (171, hybrid)** |
| pqseal | N-leg AND-composition envelope | `…pqseal-v1` | `verifySeal` | **✓ tamper (12)** + fuzz |
| pqvault / polarseek | KMS custody record | `…kms-custody-v1` | `verifyCustodyRecord` / `pqvault.verifyEntry` | fuzz (vault entry) · *tracked for tamper* |
| pqinduct | order credential | `…lemniscate-credential-v1` | induction verify | self-test · *tracked* |
| pqinduct | inner-ring grant | `…lemniscate-inner-ring-v1` | induction verify | self-test · *tracked* |
| pqinduct | induction manifest | `…lemniscate-manifest-v1` | induction verify | self-test · *tracked* |
| pqguard | dual-control approval token | `…dual-control-approval-v1` | guard verify | self-test · *tracked* |

**25 distinct contexts** — matches `domain-separation.mjs`. ✓tamper = **15 verifiers** (incl. the spine, the paid
deliverable, revocation, marketplace attestation, and key-transparency events). All surfaces are in the fuzz/total
sweep + their own module self-tests.

## Verify-only surfaces (no own signing context)
| Module | Role | Verifier |
|---|---|---|
| pqef | verifies EXTERNAL issuer signatures (PQEF bundle) | `verifyPQEFBundle` (async; in fuzz sweep) |
| pqverify-api | hosted dispatcher → the above verifiers | `verify` (async; in fuzz sweep) |
| pqgateway-session | composes offer→negotiate→handshake→session attestation | (uses pqgateway verifiers) |

## Non-signing modules (no cross-protocol signature surface — reconciles 25 contexts vs ~28 modules)
`pqcbom`, `pqcbom-server` (scan/score only) · `pqverify`, `pqmoa`, `pqclaimgate`, `pqassistant`, `pqcouncil`, `pqanswer`
(compose/attest via other modules) · `polarseek` KEM envelope (X25519+ML-KEM — encryption, not signing) · the ratchets
`pqratchet`/`pqratchet-he` (AEAD/symmetric, no public-key signing). Verifiers here are covered by fuzz/total + self-tests.

## Tracked tamper-binding extensions (remaining; all already in fuzz/total + self-tests)
pqkt possession; pqvault custody entry (Map-backed vault — doesn't fit the generic leaf-walker; covered by its own
rollback/latest-leaf self-tests + fuzz totality); pqinduct (credential/inner-ring/manifest); pqguard approval; pqsign
log-head; pqgateway client-countersig. None gate the audit; listed so coverage is explicit, not implied. (CRL,
marketplace attestation, and key-transparency events were moved to ✓tamper above.)
