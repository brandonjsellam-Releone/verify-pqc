# @trelyan/pq-sdk — module catalog (DRAFT, TRL ~5–6)

The unified post-quantum SDK surface (`sdk.mjs`, `SDK_VERSION 0.16.0-draft`). One import for the TRELYAN
Tier-1 PQ stack. Everything is built on the audited, pure-JS **`@noble/post-quantum`** (ML-KEM-1024 / FIPS 203,
ML-DSA-87 / FIPS 204, SLH-DSA / FIPS 205) + `@noble/hashes` / `@noble/ciphers` / `@noble/curves`.

**Apex tier (enforced):** ML-KEM-1024 · ML-DSA-87 · SLH-DSA (FIPS 205) · SHA-512 / SHA3-256 · AES-256-GCM /
ChaCha20-Poly1305. Falcon-1024 is the **on-chain / provenance leg only** (FIPS 206 in development — `verifyPQC`).

> **SLH-DSA parameter sets in use (FIPS 205).** The composition-signer modules — `pqseal`, `pqattest`,
> `pqcbom-report`, and the `slhdsa` leg — sign with **SLH-DSA-SHA2-256f** (`slh_dsa_sha2_256f`). The
> conformance / evidence modules — `pqef`, `pqinduct`, `kat-conformance`, `fips-conformance` — use
> **SLH-DSA-SHAKE-256s** (`slh_dsa_shake_256s`). Both are Category-5 NIST FIPS 205 parameter sets; verify
> against the per-module source string, not a single global label.

**Crypto-agility + attestation (apex):** `pqseal` is a reusable **N-of-N AND-composition** signer over an algorithm-
family registry (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519) — add/rotate a family without changing the format; anti-downgrade.
`pqattest` composes `pqseal` ∧ a threshold PQ timestamp (`pqtsa`) ∧ an RFC-6962 transparency-log inclusion proof ∧
(optional) witness co-signatures, with the seal computed LAST to **countersign** the timestamp + tree-head (downgrade-detecting under its trust model,
council-reviewed; the design + spec each had a downgrade caught and closed). Honest claim discipline: **not** an eIDAS
"qualified" timestamp, **not** "maximal" / "military-grade".

> **Honest posture.** Reference implementations, **not** FIPS-140-3 validated modules and **not** constant-time.
> Hybrid-PQ + fail-closed by design. Third-party crypto audit is required before any production use. Each module's
> own header states its honest limits; `SECURITY_REVIEW.md` logs every council review (and which findings were
> applied vs. rejected-with-reason).

## Modules

| Module | Purpose | Self-test |
|---|---|---|
| `verifyPQC` (index.js, UMD) | Falcon-1024 inspection + on-chain (AVM `falcon_verify`) verification | — |
| `pqef` | PQEF v0.1 evidence-bundle verifier — typed, version-pinned schema allowlist + value-secret scan | 15 |
| `polarseek` | PQ KMS / key-custody root — hybrid X25519+ML-KEM-1024 envelope | 11 |
| `pqsign` | PQ code-signing + RFC-6962 transparency notary (inclusion **and** consistency proofs, index/tree_size-bound; 32-bit fail-closed guard) | 18 |
| `pqkt` | **Key Transparency** — issuer-key bind/revoke log + monitor; CONIKS-style authority chaining (monotonic seq, UNSEEN→ACTIVE→REVOKED), equivocation/rollback/append-only detection + **witness co-signing (append-only, fork-refusing, anchorable) & gossip partition-detection** | 42 |
| `pqtransport` | Hybrid-PQ mutually-auth handshake (SIGMA/TLS-1.3-class) + AEAD channel; exposes transcript hash `th` | 9 |
| `pqgateway` | No-forklift PQC gateway core: signed capability offers, downgrade-safe negotiation, signed session attestation | 16 |
| `pqgateway-session` | **End-to-end wiring** — offer → negotiate → real handshake → transcript-bound attestation + client countersignature (transferable evidence) | 23 |
| `pqratchet` | PQ Triple Ratchet (X25519 + ML-KEM-1024): FS + classical & PQ post-compromise security | 10 |
| `pqratchet-he` | **Sealed-sender** Triple Ratchet — header encryption hides keys/counters/ratchet-signal (metadata privacy) | 12 |
| `pqx3dh` | **PQXDH async handshake** — Signal-style post-quantum X3DH: signed prekey bundle (X25519+ML-KEM-1024, ML-DSA-87) → offline-recipient session; derives the SK that seeds `pqratchet-he` (end-to-end tested) | 9 |
| `pqtsa` | **Quantum-safe timestamping authority** — ML-DSA-87 TSTs + legacy-signature re-stamping + multi-TSA threshold (eIDAS gap) | 11 |
| `pqindex` | QDS-Ω verifiable index — hybrid KEM, ML-DSA-87-signed Merkle-DAG, inclusion proofs, **+ absence/non-omission proofs (sorted-Merkle adjacency → "no results" can't be a lie / censorship-resistant)**, cascade dual-seal | 20 |
| `pqassistant` | Verifiable AI assistant — composes pqindex → pqmoa → pqclaimgate → pqverify → attest | 6 |
| `pqmarket` | **Agentic-marketplace core** — signed agent capability listings + append-only-logged attestations + verifying reputation (K distinct PINNED reviewers, anti-inflation, dispute-blocking); honest sybil framing | 9 |
| `pqcouncil` | PQ-attested multi-party council attestation/verification | 8 |
| `pqmoa` | PQ-attested Mixture-of-Agents — consensus_strength + dissent | 9 |
| `pqclaimgate` | Verified-claims-only gate (≥K independent verifiers + grounding + consensus) | 15 |
| `pqverify` | Real verifiers — deterministic math, citation support, self-consistency, refutation | 15 |
| `pqguard` | Agentic guardrails — dual-control token (nonce + expiry + single-use) | 24 |
| `pqinduct` | Order induction — merit-bound credential w/ Merkle inclusion, one-per-identity, access firewall | 18 |
| `pqcbom` | CBOM scanner — **two-layer** (inline patterns + dependency-manifest) crypto bill-of-materials, A–F grade, confidence triage, **SARIF 2.1.0** + CycloneDX export, inline-`pqcbom-ignore`/`.pqcbomignore` **suppression** (revenue product) | 37 |
| `pqcbom-server` | CBOM scorecard badge (shields.io), CI **policy gate (fail-closed on misconfig)**, HTTP handler, signed-Evidence-Pack tier, PREVIEW notice | 12 |
| `pqcbom-report` | **PQC Migration Evidence Pack** — the paid deliverable: **hybrid-signed (ML-DSA-87 ∧ SLH-DSA-256f)** report (scorecard + roadmap + crosswalk + CBOM); `verifyEvidencePack` recomputes the grade **+ risk tallies from the findings** and binds the rendered report (anti grade-forgery); `trustAnchored` validity-vs-trust | 19 |
| `pqseal` | **Crypto-agility signer** — N-of-N AND-composition over an algorithm-family registry (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519); add/rotate a family without changing the format; anti-downgrade (each leg binds the full ordered key-set + payload hash); `requireSuite`/`requireKinds`/`requirePinned` policy (DeepSeek-red-teamed) | 20 |
| `pqattest` | **downgrade-detecting attestation** — composes `pqseal` ∧ threshold PQ timestamp (`pqtsa`) ∧ RFC-6962 transparency inclusion ∧ optional witness co-signing; the seal countersigns the timestamp + tree-head + both thresholds (swap-TST / drop-cosigner / swap-STH / drop-witness all fail, under the declared trust model). 10-seat council reviewed the design + spec | 18 |
| `pqverify-api` | **Hosted public verify endpoint** — one surface to verify an Evidence Pack / PQEF / sign-bundle / TST / KT-proof **+ the 7 Wave-2 artifacts** (shield-report / capability / app-cert / consent-receipt / credential / firmware / payment-auth) without installing the SDK; honest trust model (validity vs pinned-trust; `pinned:false` for self-signed consent), fail-closed metadata-only opt-in, stateless/total | 34 |
| `pqpki` | **Hybrid PQ certificate authority** — issues certs binding subject Ed25519 + ML-DSA-87 keys (PQ can't be stripped), CA-signed hybrid; chain verify (CA-constraint + RFC-5280 path_len + root pinning) + signed CRL | 18 |
| `pqvault` | **Long-term confidentiality vault** — HNDL-safe hybrid X25519+ML-KEM-1024 envelopes + a signed append-only manifest (pqsign Merkle) + crypto-agility rotation; per-entry end-to-end verify | 9 |
| `pqcompliance` | **Signed cryptographic-control gap mapper** — CBOM scan → per-control gap/no-gap for CNSA 2.0 / NIS2 / CRA / DORA / SC-13 (code-context; CNSA needs real PQ-asymmetric); ML-DSA-87-signed, findings-hash-bound, recompute-verified; honest *not-a-certification* framing | 15 |
| `fips-conformance` | Hedged signing, exact sizes, ML-KEM implicit rejection, context separation, length rejection | 12 |
| `kat-conformance` | Deterministic NIST-style known-answer vectors (seed-pinned) for ML-KEM-1024 / ML-DSA-87 / SLH-DSA-SHAKE-256s | 10 |
| `pqvc` | **QuantumDNA** — PQ verifiable credentials: hybrid-signed (Ed25519∧ML-DSA-87∧opt SLH), `did:trelyan`, selective disclosure (pqredact), holder proof-of-possession, expiry/revocation, W3C-VC export | 24 |
| `pqpay` | **QuantumPay** — payment-AUTHORIZATION signing (payee/amount-minor-units/currency/nonce/expiry), amount/payee-bound, fail-closed replay (durable nonce ledger). NOT money movement — settlement is a licensed rail | 20 |
| `pqfirmware` | **QuantumShield IoT** — firmware-manifest signing; device verifies before flash: pinned vendor, binary hashes to the signed digest, version strictly-newer (monotonic anti-rollback), model-bound | 15 |
| `pqshield` | **TRELYANShield** — signed quantum-risk posture report; the A–F grade is RECOMPUTED by the verifier from the signed CBOM (can't sign a clean grade over bad crypto); FAIL-DANGEROUS scoring; dual-anchor-ready | 21 |
| `pqcap` | **Agent capability tokens** — least-privilege tool authorization (ThrondarAgent/QuantumFlow): scoped caveats + deny-unlisted-args, holder-PoP-bound, expiry, fail-closed max_uses; `verifyAndConsume` commit-on-success | 29 |
| `pqadmit` | **SovereignMarket admission** — signed app cert (CBOM/CVE/OPA/PQC + level) + verify-before-deploy: artifact-digest-bound, cert-level floor, monotonic anti-rollback, revocation deny-set | 23 |
| `pqconsent` | **Self-sovereign consent receipt** (VaultHealth GDPR-Art.9): subject-signed purposes×categories, deny-by-default scope, subject-only revocation, strict ASCII-token canon. Evidence, not legal validity | 19 |
| `pqmonitor` | **TRELYANShield SOC engine** — continuous posture monitoring: tamper-evident hash-chained ledger of pqshield snapshots (fail-dangerous ingest) + regression detection (RED-label deltas) + a hybrid-signed posture digest whose current grade & trend are RECOMPUTED from the ledger on verify; anti-rollback `minSeq` | 17 |
| `pqgate` | **SovereignMarket admission engine** — CI/CD supply-chain gate over `pqadmit`: an authority-SIGNED policy (rules can't be silently weakened) → a recompute-verifiable hybrid-signed ALLOW/DENY decision → a tamper-evident admission log; fail-dangerous (won't act under an unverified policy) | 21 |
| `pqflow` | **QuantumPay lifecycle engine** — merchant-signed, hash-chained capture lifecycle over a `pqpay` authorization (authorize→capture(s)→settle/void/refund); verifyFlow RECOMPUTES the state and enforces Σcaptures ≤ authorized + no-capture-after-close + refund ≤ captured; per-flow unique nonces + durable cross-flow ledger. Authorization/capture INTENT only — NOT money movement | 18 |
| `pqdelegate` | **ThrondarAgent delegation engine** — attenuating capability-delegation chains over `pqcap` (multi-agent): a holder sub-delegates a NARROWER capability; verifyDelegationChain enforces attenuation 3 ways (caveat ACCUMULATION, tool/scope/max_uses narrow-only, signed delegator-chain + parent_ref binding) + leaf holder-PoP back to the root principal. A worker can never escalate beyond what it was granted | 26 |
| `pqconsentflow` | **VaultHealth consent-lifecycle engine** — a controller-SIGNED, hash-chained grant→access→withdraw log over `pqconsent`; verifyConsentFlow recomputes the permitted state, binds the access time into the scope check, and flags access-after-withdrawal (vs the SUBJECT-signed `revoked_at`, not chain position) / withheld-withdrawal / out-of-scope as cryptographically-evidenced `violations` — returning `verified` (chain authentic) distinctly from `compliant` (no violation). Verifiable EVIDENCE, not access enforcement | 19 |
| `pqaibom` | **AI Bill of Materials (MAP)** — verifiable ML-BOM (CycloneDX 1.6) + a *Declaration-Assurance* grade; assurance-level cap (an 'A' implies hash-bound components) + completeness floor (no vacuous 'A'); Z3-proven grade caps | 53 |
| `pqeval` | **AI Evaluation Attestation (MEASURE)** — a signed eval receipt + posture grade; suite-type cap (a top posture needs an earned, registry-validated suite) + value/contamination/safety checks; Z3-proven | 26 |
| `pqtrace` | **AI Execution Trace (MANAGE)** — runner-attested, hash-chained PQ execution/provenance log; salted-HMAC content commitments; RFC-6962 anchorable; Z3 chain-binding | 38 |
| `pqgovernance-record` | **AI Governance Record (capstone)** — cross-binds MAP ∧ MEASURE ∧ MANAGE to ONE model (three distinct signers); subject authenticated from the signed AIBOM; pairwise-disjoint signer sets | 22 |
| `pqgovernance-gate` | **CI admission gate** over the record — fail-closed; letter-floor / distinct-signer / fully-pinned-drift policy; `allowUnpinnedSeal` forced off | 25 |
| `pqgovern-policy` | **Governance Policy (GOVERN)** — a signed, versioned admission policy the gate enforces (criteria become verifiable evidence); replay/window pins; caller can't shadow the signed criteria; Z3 admission-soundness proof | 37 |
| `pqgovern-evidence` | **AI Governance Evidence Pack** — one self-contained, independently-verifiable artifact; re-derives the whole admission under the verifier's own pins (no embedded verdict); domain-separated packager seal | 15 |
| `pqgovern-anchor` | **Transparency-anchored admissions** — bind an admission into an append-only RFC-6962 log; prove inclusion under a pinned STH + detect history-rewrite (consistency proofs); the log entry is the canonical projection of the pack (poisoned-index-safe); inclusion ≠ completeness | 18 |
| `pqgovern-monitor` | **Fork-refusing transparency monitor** — a stateful watcher that holds the log append-only across the STHs it observes (checkpoint bootstrap, freshness, bounded history); on equivocation/rewrite it alerts + keeps the last-good head | 20 |
| `pqgovern-witness` | **Multi-party witness/gossip quorum** — independent witnesses co-sign the heads they accept; `gossipReconcile` cross-checks their signed tree heads to detect a **split-view/equivocation** a single monitor is blind to (exact-size fork + proof-checked prefix violation); `consistent` = proven append-only, never "no fork yet"; safety-not-liveness | 18 |
| `pqgovern-cli` | **CI admission command** — `node pqgovern-cli.mjs <pack.json> <config.json>` → exit 0 (ADMIT) / 1 (BLOCK) | 8 |

### AI Governance layer (NIST AI RMF) — see [AI_GOVERNANCE.md](./AI_GOVERNANCE.md)

The eleven modules above (`pqaibom`/`pqeval`/`pqtrace` + `pqgovern*`) compose **MAP ∧ MEASURE ∧ MANAGE ∧
GOVERN** into one cross-bound, fail-closed AI-governance admission — with a self-verifiable Evidence Pack,
transparency anchoring, a CI command, an end-to-end composition test (`pqgovern-e2e`, 15), and a
machine-checked Z3 admission-soundness proof (`formal/pqgovern_admission_z3.py`). Self-attested pre-audit;
attestation proves *who signed what*, not that a claim is true; **not a certification**.

Plus CLI + GitHub Action (`pqcbom-cli.mjs`, `pqcbom-action/` — SARIF→code-scanning, report-only default), the **Evidence
Pack Express generator** (`pqevidence-cli.mjs` — point at any repo → scan → hybrid-signed pack + buyer-facing report +
CBOM, self-verified; the paid deliverable productized), a standalone Evidence-Pack verifier (`verify-pack.mjs`), a
**60-second runnable demo** (`examples/demo/run-demo.mjs` — scans a sample repo → SARIF + CBOM + a hybrid-signed,
fully-attested Evidence Pack, self-checked) and owner-gated hosted config (`deploy/`).
Plus the **Wave-2 product CLIs** (`pqfirmware-cli.mjs`, `pqvc-cli.mjs` — keygen / sign / verify, each with `--selftest`;
`pqverify-cli.mjs` — verify ANY artifact type from the command line via the hosted-API surface, key-pinned),
the in-browser **PQ Trust Sandbox** (website `/sandbox` — runs pqshield's scoring client-side), and Wave-2 assurance
harnesses (`conformance-vectors.mjs` 25 KAT, `product-flows.mjs` 16 end-to-end, `sandbox-parity.mjs` drift-guard).

**Every module self-test + harness green in this build** (`node test-all.mjs` runs all of them + the unified `sdk.mjs`
surface smoke test). Beyond the per-module self-tests: **`tamper-binding.mjs` — 1,064 mutation assertions** (every signed
field of each signed core proven bound; cosmetic fields documented-unsigned, never silent — now incl. `pqseal`),
**`assurance-properties.mjs`** (property-based: totality/determinism/tally-consistency/grade-purity/fail-closed over
~2,500 adversarial inputs), **`accuracy-benchmark.mjs`** (scanner precision/recall on a labeled corpus + published blind
spots), the 42k+ differential RFC-6962 cross-check, and the fuzz sweep across the verifiers (**0 fail-open observed**; verdict verifiers returned no throw across the corpus — covering the PKI / vault / compliance / PQXDH / marketplace / search-absence / hosted-API verifiers, and exotic-input classes: `toJSON`/`valueOf`/`Symbol.toPrimitive` hooks, throwing getters, Proxies, BigInt, boxed-String, typed arrays, sparse arrays). These are runnable **assurance harnesses** (bounded test evidence over the stated corpora) — **not** formal proofs of bug-absence, and **not** a substitute for the pending third-party audit. Run the whole suite:

```bash
node test-all.mjs        # every module self-test + the unified SDK surface smoke test
node kat-conformance.mjs # deterministic KAT vectors (drift detection)
```

## Audit & operations artifacts

- `vectors-crosscheck.mjs` — independent differential validation of the RFC-6962 code (two implementations agree over 42k+ cases).
- `witness-service.mjs` — runnable KT witness node (durable state) + gossip pool + HTTP handler (deploy-ready, owner-gated).
- `fuzz-robustness.mjs` — negative/fuzz sweep: 0 fail-open across 4,320 adversarial calls (60 verifiers × 72 malformed/exotic input classes, incl. `toJSON`/`valueOf`/`Symbol.toPrimitive` serialization hooks, throwing getters, Proxies, BigInt, boxed-String, typed arrays, sparse arrays); asserts verdict verifiers are total (fail-closed, never throw) — caught throws (216) occur only in the by-design decrypt/handshake steps. The manual recursive `canon()` never passes a rich object to `JSON.stringify`, so `toJSON`/`Symbol` hooks cannot alter the signed view (empirically: 0 fail-open on those inputs).
- `tamper-binding.mjs` — signature-coverage proof (1,064 assertions across every signed core; authoritative inventory in `SIGNED_OBJECTS.md` / `AUDIT_DOSSIER.md`): builds a VALID signed object for each (listing / cert / shard / session-attestation / TST / prekey-bundle / **transparency-SPINE bundle** / **gateway offer** / **PAID Evidence Pack** / **compliance report** / **CRL** / **marketplace attestation** / **key-transparency event**), flips EVERY leaf, and asserts verification breaks (the field is bound) — so no field the verifier reads is silently outside the signature; intentionally-unsigned fields (e.g. re-derivable `markdown`, cosmetic `signature.alg`) are RECORDED, not silent. Caught + fixed THREE real gaps: pqindex shard `ts` unsigned, pqx3dh one-time PQ prekeys unsigned (Signal-PQXDH HNDL gap), and pqcompliance `summary`/`disclaimer`/`posture` unsigned (caveat-stripping on a signed deliverable). Council-confirmed.
- `domain-separation.mjs` — cross-protocol-reuse check: static-scans every module source (191 production PQ sign/verify sites — all context-bound, 0 bare found), asserts the 65 signing contexts are globally distinct (0 cross-module reuse), and functionally demonstrates the ML-DSA primitive rejects a signature presented under the wrong context or bare. The pqpki Ed25519 hybrid leg is domain-separated by binding the context into its pre-image. (NB: the pqsign STH uses a fixed-key-order `JSON.stringify` core, not `canon()` — see `CANONICALIZATION_SPEC.md §5`.)
- `canon-determinism.mjs` — canonicalization check (16 assertions): the `canon()` serializer is byte-identical across the 12 `canon()`-using modules (no divergent copy → no cross-module signing-determinism bug), and is deterministic, input-key-order-independent, and **collision-free over the tested value shapes** (types/structure don't collide — test evidence, not a formal injectivity proof; value-domain caveats in `CANONICALIZATION_SPEC.md`). Full signed-object inventory: `SIGNED_OBJECTS.md`.
- `THREAT_MODEL.md` · `AUDIT_READINESS.md` · `SECURITY_REVIEW.md` — threat model, audit scope/inventory, and the full council-review log (findings applied vs rejected-with-reason).

See `SDK_USAGE` examples in each module header and the published browser-verifier doc in `README.md`.
