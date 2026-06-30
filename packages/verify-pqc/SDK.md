# @trelyan/pq-sdk — module catalog (DRAFT, TRL ~5–6)

The unified post-quantum SDK surface (`sdk.mjs`, `SDK_VERSION 0.16.0-draft`). One import for the TRELYAN
Tier-1 PQ stack. Everything is built on the audited, pure-JS **`@noble/post-quantum`** (ML-KEM-1024 / FIPS 203,
ML-DSA-87 / FIPS 204, SLH-DSA / FIPS 205) + `@noble/hashes` / `@noble/ciphers` / `@noble/curves`.

**Apex tier (enforced):** ML-KEM-1024 · ML-DSA-87 · SLH-DSA (FIPS 205) · SHA-512 / SHA3-256 · AES-256-GCM /
ChaCha20-Poly1305. Falcon-1024 is the **on-chain / provenance leg only** (draft FIPS 206 — `verifyPQC`).

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

Plus CLI + GitHub Action (`pqcbom-cli.mjs`, `pqcbom-action/` — SARIF→code-scanning, report-only default), a standalone
Evidence-Pack verifier (`verify-pack.mjs`), a **60-second runnable demo** (`examples/demo/run-demo.mjs` — scans a sample
repo → SARIF + CBOM + a hybrid-signed, fully-attested Evidence Pack, self-checked) and owner-gated hosted config (`deploy/`).
Plus the **Wave-2 product CLIs** (`pqfirmware-cli.mjs`, `pqvc-cli.mjs` — keygen / sign / verify, each with `--selftest`;
`pqverify-cli.mjs` — verify ANY artifact type from the command line via the hosted-API surface, key-pinned),
the in-browser **PQ Trust Sandbox** (website `/sandbox` — runs pqshield's scoring client-side), and Wave-2 assurance
harnesses (`conformance-vectors.mjs` 25 KAT, `product-flows.mjs` 16 end-to-end, `sandbox-parity.mjs` drift-guard).

**Every module self-test + harness green in this build** (`node test-all.mjs` runs all of them + the unified `sdk.mjs`
surface smoke test). Beyond the per-module self-tests: **`tamper-binding.mjs` — 781 mutation assertions** (every signed
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
- `fuzz-robustness.mjs` — negative/fuzz sweep: 0 fail-open across 3,240 adversarial calls (45 verifiers × 72 malformed/exotic input classes, incl. `toJSON`/`valueOf`/`Symbol.toPrimitive` serialization hooks, throwing getters, Proxies, BigInt, boxed-String, typed arrays, sparse arrays); asserts verdict verifiers are total (fail-closed, never throw) — caught throws occur only in the 3 by-design decrypt/handshake steps. The manual recursive `canon()` never passes a rich object to `JSON.stringify`, so `toJSON`/`Symbol` hooks cannot alter the signed view (empirically: 0 fail-open on those inputs).
- `tamper-binding.mjs` — signature-coverage proof (781 assertions across 15 signing verifiers): builds a VALID signed object for each (listing / cert / shard / session-attestation / TST / prekey-bundle / **transparency-SPINE bundle** / **gateway offer** / **PAID Evidence Pack** / **compliance report** / **CRL** / **marketplace attestation** / **key-transparency event**), flips EVERY leaf, and asserts verification breaks (the field is bound) — so no field the verifier reads is silently outside the signature; intentionally-unsigned fields (e.g. re-derivable `markdown`, cosmetic `signature.alg`) are RECORDED, not silent. Caught + fixed THREE real gaps: pqindex shard `ts` unsigned, pqx3dh one-time PQ prekeys unsigned (Signal-PQXDH HNDL gap), and pqcompliance `summary`/`disclaimer`/`posture` unsigned (caveat-stripping on a signed deliverable). Council-confirmed.
- `domain-separation.mjs` — cross-protocol-reuse check: static-scans every module source (104 production PQ sign/verify sites — all context-bound, 0 bare found), asserts the 25 signing contexts are globally distinct (0 cross-module reuse), and functionally demonstrates the ML-DSA primitive rejects a signature presented under the wrong context or bare. The pqpki Ed25519 hybrid leg is domain-separated by binding the context into its pre-image. (NB: the pqsign STH uses a fixed-key-order `JSON.stringify` core, not `canon()` — see `CANONICALIZATION_SPEC.md §5`.)
- `canon-determinism.mjs` — canonicalization check (16 assertions): the `canon()` serializer is byte-identical across the 12 `canon()`-using modules (no divergent copy → no cross-module signing-determinism bug), and is deterministic, input-key-order-independent, and **collision-free over the tested value shapes** (types/structure don't collide — test evidence, not a formal injectivity proof; value-domain caveats in `CANONICALIZATION_SPEC.md`). Full signed-object inventory: `SIGNED_OBJECTS.md`.
- `THREAT_MODEL.md` · `AUDIT_READINESS.md` · `SECURITY_REVIEW.md` — threat model, audit scope/inventory, and the full council-review log (findings applied vs rejected-with-reason).

See `SDK_USAGE` examples in each module header and the published browser-verifier doc in `README.md`.
