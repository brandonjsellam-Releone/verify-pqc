# TRELYAN OMEGA (QTOS) — honest architecture + capability spec (DRAFT)

*OMEGA is a 7-layer post-quantum **trust + provenance** architecture. It is **not a new monolith**: ~80% of its
substance is the already-shipped `@trelyan/verify-pqc` modules, composed under one honest status map. This spec exists so
any pitch/datasheet is generated **from the machine-readable manifest** (`omega.mjs` → `OMEGA_LAYERS`) and never claims a
layer beyond what the code does. Reference implementation: `omega.mjs` (manifest), `omega-gov.mjs` (Layer 1),
`omega-bridge.mjs` (Layer 4/5). Status: DRAFT, unaudited composition over the independently-audited `@noble` crypto.*

> **For the reviewer (Dorit Dor test):** the defensible core is AND-composition signing, tamper-evident logs + anchoring,
> an IP vault, M-of-N governance, hybrid-key derivation + entropy estimation, and hybrid-PQ messaging — all offline,
> fail-closed, verifiable. There is **no quantum hardware, no token, no marketplace, no autonomous key rotation, and no
> legal guarantee** in the shipped core; those are MOCK / STUB / GATED and labelled as such below.

## 1. Capability matrix (single source of truth)

| Layer | What it is | Status | Backing modules |
|---|---|---|---|
| **L1 Foundation** | M-of-N PQ-signed threshold governance (2/3/4-of-5 + 2-of-3 emergency) + a constitutional contract that **runs on a real AVM** (thresholds enforced on-chain: 3-of-5 executes, 2-of-5 rejected, outsider vote rejected) | **REFERENCE** | `omega-gov.mjs`, `program/omega/omega_constitution.py` (+ `LOCALNET_REPRODUCE.md`), pqauditlog, pqseal |
| **L2 Chain** | `omega-chain`: batch OMEGA events → PQ-signed log → **exact Algorand anchor bytes** + offline binding proof (`verifyBatch`) | **REFERENCE** | `omega-chain.mjs`, pqanchor, pqauditlog, pqtsa, pqkt |
| **L3 Vault** | Quantum IP Vault: inscribe IP → 3-family AND-sign → Vault Cell + PQ timestamp + custody chain + pinned pointer | **BUILT** | `qiv.mjs`, `qiv-pin.mjs`, pqseal, pqtsa, pqanchor |
| **L4 Bridge** | SP 800-90B MCV min-entropy estimator + accept gate; hybrid-key HKDF combiner; PQ-signed key-derivation attestation | **REFERENCE** | `omega-bridge.mjs`, pqgateway, pqtransport, pqseal |
| **L5 Fountain** | Entropy source abstraction; MVP source = OS CSPRNG labelled MOCK (swap in certified QRNG later) | **MOCK** | `omega-bridge.mjs` (getEntropyMock) |
| **L6 Nexus** | `omega-nexus`: 1:1 async PQ session between **pinned** OMEGA identities (PQXDH → triple ratchet) + verified messages | **REFERENCE** | `omega-nexus.mjs`, pqx3dh, pqratchet, pqratchet-he, pqtransport, pqvault, pqindex |
| **L7 Sentience** | `omega-sentinel`: PQ-signed posture ledger → reactive regression detection → human-in-the-loop gate; **no autonomous action** | **GATED** | `omega-sentinel.mjs`, pqmonitor, pqshield, pqkt |

Status vocabulary: **BUILT** (tested reference core), **REFERENCE** (unaudited JS reference; on-chain/hardware productionization gated), **MOCK** (labelled placeholder, no real capability claimed), **STUB** (interface only), **GATED** (deliberately not built pending owner/legal/hardware/securities action).

## 2. Claim-hygiene rewrite (blueprint → honest)

The blueprint carries claims a cryptographer would reject on sight. What we actually say:

| Blueprint phrase | Honest statement |
|---|---|
| "post-catastrophe / the only infrastructure that survives the break" | Hybrid PQ + classical composition (ML-KEM/ML-DSA/SLH-DSA, FIPS 203/204/205); resists known quantum attacks under those assumptions. Not a survival guarantee. |
| "quantum-computer-proof / unbreakable finality" | Anchoring proves the off-chain↔on-chain **binding**; it does not prove chain immutability, honesty, or availability. |
| "Impossible to decrypt retroactively" (Quantum Voice) | Forward secrecy under harvest-now-decrypt-later **if** endpoints aren't compromised and the hybrid KEM holds. The ratchet is DH+KEM, **not** a one-time pad. |
| "true quantum randomness" (QRNG) | MVP uses OS CSPRNG, labelled **MOCK_CSPRNG**. True QRNG needs certified hardware (gated). |
| "QKD-integrated / verified with QKD hardware" | **QKD-ready interface only** — `qkdSessionMock` is a labelled mock; no hardware. |
| "Legally admissible governance / evidence" | Cryptographically verifiable records that can **support** a legal process; admissibility is a court + counsel determination. |
| "Falcon-1024 FIPS 206 compliant" | Falcon-1024 / FN-DSA / **FIPS 206 is DRAFT** — caveat every mention; it is the optional on-chain leg only. |
| "Autonomous AI auto-rotates keys" | Human-in-the-loop only; `autonomousKeyRotation()` is machine-gated OFF. Signals are reactive + falsifiable, not "73.4% RSA break" predictions. |
| "World's first" | Dropped — no primacy claim; the distinct claim is the specific PQ composition. |
| "FIPS-certified / audited / NIST-approved" | Pre-audit, self-attested; `@noble/post-quantum` is not independently audited. |

## 3. Securities / token / regulatory gate register (machine-enforced where code exists)

Everything below is **deliberately NOT built** and, where a code path exists, is enforced by a throwing gate. The
project's standing rule (no token, no securities offering, pure utility) is honored.

| Gated feature | Layer | Enforcement |
|---|---|---|
| IP marketplace / fractional-tokenized ownership | L3 | `qiv.marketplace()` throws `QIV_MARKETPLACE_SECURITIES_GATED` |
| Token-holder / quadratic voting; treasury-token | L1 | `omegaGov.tokenHolderVote()` throws `OMEGA_TOKEN_GOVERNANCE_GATED` |
| True m-of-n secret-sharing / BLS-MPC escrow | L4 | `omegaBridge.thresholdSecretShare()` throws `OMEGA_MPC_THRESHOLD_GATED` |
| Autonomous (no-human) key rotation on AI signal | L7 | `omega.autonomousKeyRotation()` throws `OMEGA_AUTONOMOUS_ACTION_GATED` |
| "Omega token", "entropy-mining rewards", 2% equity, carried interest, LP waterfall, $500K/yr revenue-share | L1/L5/integration | Not implemented; excluded from design (securities). Any such feature requires counsel + a compliant structure first. |
| On-chain broadcast / PyTeal deploy (all layers) | L1–L5 | Owner-gated (funded account); cores produce exact bytes only, never broadcast. |
| QKD/QRNG/HSM/satellite hardware | L4/L5 | Owner-gated certified integration; mocks are labelled. |

`omega.omegaSelfCheck()` verifies all four in-code gates actually throw (part of the self-test).

## 4. What is genuinely new here (beyond the existing SDK)

- **`omega-gov.mjs`** — a verifiable M-of-N threshold governance state machine: per-member ballots are pqseal
  AND-compositions bound to the exact proposal hash; `tally()` verifies every ballot against the pinned roster, dedupes,
  detects double-votes, enforces class thresholds + time-locks + a 2-of-3 emergency pause. 16 self-tests.
- **`omega-bridge.mjs`** — a real **SP 800-90B §6.3.1 MCV min-entropy estimator** (a lower-bound estimate, honestly
  labelled — not the full 90B battery), a **hybrid-key HKDF combiner** (QKD-slot ∥ ML-KEM ∥ classical, OR-secure,
  domain-separated, fail-closed on a missing required slot), and a **PQ-signed key-derivation attestation** (signs a key
  *commitment*, never the key). 17 self-tests.
- **`omega.mjs`** — the machine-readable manifest + capability matrix + gate/hazard registers + the L7 human-in-the-loop
  review and autonomous-action gate, plus a **capability attestation**: `attestCapabilities(signers)` PQ-signs the honest
  claim set (pqseal 3-family AND-composition) so a reviewer verifies the capability statement is exactly what TRELYAN
  signed and hasn't drifted — the product signs its own claims. 14 self-tests.
- **`qiv-pin.mjs`** — the QIV off-chain storage adapter (Layer 3 completion): records a plain SHA-256 of the exact bytes
  into the signed record so a fetched IPFS object is offline-verifiable against the inscription; MOCK/dry-run by default,
  live Pinata upload owner-gated (publishes the artifact). 10 self-tests.
- **`omega-evidence.mjs`** — the end-to-end **Evidence Pack**: one PQ-signed bundle exercising the whole stack (signed
  capability statement + a live 3-of-5 governance decision that tallies executable + a QIV inscription with a pinned
  pointer + a hybrid-key attestation), bound by a top-level pqseal so it can't be cherry-picked. `verifyEvidencePack`
  checks every component + the binding offline, fail-closed — the tangible "verify the whole thing yourself" artifact for
  a VC. 6 self-tests (incl. wrong-issuer, tampered-ballot, and capability-drift rejection).

## 5. Roadmap (honest sequencing)

MVP-defensible now: L3 (BUILT), L1/L2/L4/L6 (REFERENCE). Gated on owner/hardware/legal: on-chain deploy + broadcast,
certified QKD/QRNG, marketplace (securities), token features, autonomous response. The credible near-term wedge is the
same as the rest of the suite — a **tamper-evident, independently-verifiable PQ trust + provenance layer** sold on
"measure, don't claim," with governance (L1) and the IP vault (L3) as the lead artifacts for the Qbeat conversation.

## 6. Self-tests

`node omega-gov.mjs` (16) · `node omega-bridge.mjs` (21) · `node omega.mjs` (14) · `node qiv-pin.mjs` (10) ·
`node omega-evidence.mjs` (6) · `node omega-chain.mjs` (7) · `node omega-sentinel.mjs` (8) · `node omega-nexus.mjs` (8) ·
`node omega-server.mjs` (8). All included in the SDK green-gate (`node test-all.mjs`, **71 modules**). SDK surface adds
`sdk.omegaChain`, `sdk.omegaSentinel`, `sdk.omegaNexus`, `sdk.omegaServer` (SDK_VERSION **0.22.0-draft**). Every one of
the 7 layers has a concrete, tested OMEGA-named artifact. The L1 on-chain contract lives at
`program/omega/omega_constitution.py` (compiles to TEAL v10).

**Demo surface (`omega-server.mjs`).** A framework-free `node:http` API + embedded self-contained dashboard: `GET /`
(dashboard), `GET /api/manifest`, `GET /api/capability` (signed statement), `GET /api/demo-evidence` (build + verify a
fresh Evidence Pack server-side), `POST /api/verify-evidence`. Run `node omega-server.mjs --serve 8787`. It is the
"verify it live" surface for a due-diligence session — and building it caught **two real root-cause bugs the unit tests
missed** (both fixed): the governance roster wasn't JSON-portable (Uint8Array pubkeys → now hex, so a governance decision
serializes + verifies elsewhere), and `verifyEvidencePack` conflated *validity* with *trust* (now fail-closed when no
issuer is pinned).

## 7. Adversarial review (3-lens, applied 2026-07-03)

A 3-lens review (crypto soundness / claim hygiene / securities-gate completeness) over the OMEGA cores + this spec:
**crypto = ROBUST** (governance `tally()` has no bypass — ballots verified against the pinned roster, bound to the exact
proposal hash, deduped, double-vote-safe, time-lock fail-closed; MCV formula correct; combiner injective; attestation
signs only a key commitment); **claim hygiene = clean PASS** (every Falcon mention DRAFT-caveated, all mocks labelled,
no affirmative overclaim); **securities = all 4 in-code gates enforced**, no regulated feature callable. Applied the two
genuine hardening items: a `requireReliable` option on `acceptEntropy` (reject a statistically-weak small-sample estimate
for security-critical use) and `requirePresent` reserved-slot validation on `hybridCombine` (a non-slot name is rejected
rather than silently non-contributing). Both covered by new negative tests.
