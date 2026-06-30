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

## Wave-2 + platform-engine signing surfaces (this session — 12 signed cores)
Each hybrid signer adds an Ed25519 (context bound into the pre-image) ∧ ML-DSA-87 (`…-v1`) ∧ optional SLH-DSA-256f (`…-slh-v1`) leg; the `-slh-v1` companion context is omitted from the table for brevity but is present + globally distinct (see `domain-separation.mjs`). All are field-bound by `tamper-binding.mjs` (1,064 assertions total) + total/fail-closed in `fuzz-robustness.mjs`.
| Module | Signed object | Context (`trelyan-…`) | Verifier | Signed-coverage test |
|---|---|---|---|---|
| pqshield | posture report (A–F grade RECOMPUTED) | `…shield-report-v1` | `verifyShieldReport` | **✓ tamper** + fuzz |
| pqcap | agent capability token (+holder PoP) | `…agent-capability-v1` (+`…agent-cap-pop-v1`) | `verifyCapability` / `verifyAndConsume` | **✓ tamper** + fuzz |
| pqadmit | app deploy cert (+revocation) | `…deploy-admission-v1` (+`…deploy-revocation-v1`) | `verifyAdmission` / `verifyRevocation` | **✓ tamper** + fuzz |
| pqconsent | consent receipt (+revocation) | `…consent-receipt-v1` (+`…consent-revocation-v1`) | `verifyConsent` / `verifyConsentRevocation` | **✓ tamper** + fuzz |
| pqpay | payment authorization (intent only) | `…quantumpay-auth-v1` | `verifyAuthorization` / `verifyAndConsume` | **✓ tamper** + fuzz |
| pqvc | verifiable credential (+presentation) | `…quantumdna-vc-v1` (+`…quantumdna-vp-v1`) | `verifyCredential` / `verifyPresentation` | **✓ tamper** + fuzz |
| pqfirmware | firmware manifest (anti-rollback) | `…quantumshield-fw-v1` | `verifyFirmware` | **✓ tamper** + fuzz |
| pqmonitor | posture digest + tamper-evident ledger | `…shield-monitor-digest-v1` | `verifyPostureDigest` / `verifyLedger` | **✓ tamper** + fuzz |
| pqgate | admission policy + recompute-verifiable decision | `…sovereign-admission-policy-v1` (+`…-decision-v1`) | `verifyPolicy` / `verifyDecision` / `verifyAdmissionLog` | **✓ tamper** + fuzz |
| pqflow | payment capture-lifecycle chain | `…quantumpay-flow-v1` | `verifyFlow` | **✓ tamper** + fuzz |
| pqdelegate | attenuating delegation chain (+leaf PoP) | `…agent-delegation-v1` (+`…agent-delegation-pop-v1`) | `verifyDelegationChain` | **✓ tamper** + fuzz |
| pqconsentflow | consent lifecycle log (grant→access→withdraw) | `…consent-flow-v1` | `verifyConsentFlow` | **✓ tamper** + fuzz |

Additional standing signing modules carry their own distinct contexts too (pqredact, pqauditlog, pqanchor, pqposture, pqattest, pqtls, the QRL anchor) — enumerated live by `domain-separation.mjs`.

**65 distinct contexts** — the authoritative live count is `domain-separation.mjs` (this table is the call-graph map of the principal surfaces). ✓tamper now spans **every one of this session's 12 signed cores** (the 5 platform engines + 7 Wave-2 cores) plus the spine, the paid deliverable, revocation, marketplace attestation, and key-transparency events — **1,064 tamper assertions** total. All surfaces are in the fuzz/total sweep (60 verifiers) + their own module self-tests.

## Verify-only surfaces (no own signing context)
| Module | Role | Verifier |
|---|---|---|
| pqef | verifies EXTERNAL issuer signatures (PQEF bundle) | `verifyPQEFBundle` (async; in fuzz sweep) |
| pqverify-api | hosted dispatcher → the above verifiers | `verify` (async; in fuzz sweep) |
| pqgateway-session | composes offer→negotiate→handshake→session attestation | (uses pqgateway verifiers) |

## Non-signing modules (no cross-protocol signature surface — these hold no signing context, so module count > the per-surface rows)
`pqcbom`, `pqcbom-server` (scan/score only) · `pqverify`, `pqmoa`, `pqclaimgate`, `pqassistant`, `pqcouncil`, `pqanswer`
(compose/attest via other modules) · `polarseek` KEM envelope (X25519+ML-KEM — encryption, not signing) · the ratchets
`pqratchet`/`pqratchet-he` (AEAD/symmetric, no public-key signing). Verifiers here are covered by fuzz/total + self-tests.

## Tracked tamper-binding extensions (remaining; all already in fuzz/total + self-tests)
pqkt possession; pqvault custody entry (Map-backed vault — doesn't fit the generic leaf-walker; covered by its own
rollback/latest-leaf self-tests + fuzz totality); pqinduct (credential/inner-ring/manifest); pqguard approval; pqsign
log-head; pqgateway client-countersig. None gate the audit; listed so coverage is explicit, not implied. (CRL,
marketplace attestation, and key-transparency events were moved to ✓tamper above.)
