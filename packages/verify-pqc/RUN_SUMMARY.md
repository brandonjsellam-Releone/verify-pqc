# Autonomous build run — summary (25 Jun 2026)

User-authorized envelope: *"entire team + connectors, ~3h"* + standing law *"only upgrade to higher / max apex."*
Cadence each cycle: **build → test → council-review (11 external seats) → verify findings against the spec → apply
real fixes / reject misfits → record to memory + `SECURITY_REVIEW.md` → run `test-all.mjs` → next.**
**Hard constraint honored throughout: nothing deployed, published, sent, or spent — all owner-gated.**

## Delivered (10 tasks)

1. **pqgateway** — no-forklift PQC gateway core (the council's #1 unbuilt gap): signed capability offers (downgrade
   detection), policy-driven suite negotiation, signed session attestation. *DeepSeek caught replayable offers +
   lie-able attestation → added per-session challenge + transcript binding + lying-gateway defense.*
2. **SDK hardening** — applied the corpus deep-read corrections to crypto paths (canonical signing, context
   separation, implicit rejection, cascade dual-seal replacing an unsound XOR).
3. **KNOWLEDGE_BASE** — full 12/12 corpus deep-read synthesis integrated (corrections + validations).
4. **Revenue product** — `pqcbom` productized: CLI + GitHub Action + Cloudflare worker; deploy package staged
   (owner-gated, not deployed).
5. **Max-apex params** — audited the whole SDK; upgraded every sub-maximal parameter (ML-KEM-768→1024, ML-DSA-65→87,
   SLH-DSA→SHAKE-256s). Grep confirms zero sub-max identifiers (only the gateway's interop fallback ladder remains, by design).
6. **kat-conformance** — deterministic NIST-style known-answer vectors (seed-pinned) → CI drift detection.
7. **pqratchet-he** — sealed-sender / header encryption (metadata privacy). *DeepSeek's reorder + counter-nonce
   "fixes" REJECTED with reason — they would regress HE correctness/privacy; kept the spec-correct design.*
8. **pqtsa** — quantum-safe timestamping authority + legacy-signature re-stamping (eIDAS gap). *Mistral → added
   multi-TSA threshold co-signing; documented the not-a-qualified-QTSA + forward-secure-key + GDPR limits.*
9. **pqgateway-session** — end-to-end wiring (offer→negotiate→REAL hybrid handshake→transcript-bound attestation).
   *Grok → reframed the "genuine PROOF / end-to-end" overclaim (it's the client↔gateway leg, participant-verifiable),
   ADDED a client countersignature for transferable evidence, and folded the offer fingerprint in (anti-splice).*
10. **Consolidation** — this summary + `SDK.md` module catalog + `SDK_VERSION → 0.2.0-draft`.

## State

- **~237 self-tests across 22 tested modules — all green.** Apex tier throughout (ML-KEM-1024 / ML-DSA-87 /
  SLH-DSA-SHAKE-256s / SHA-512 / SHA3-256).
- The defining discipline: the external council found **real** bugs (gateway replay, TSA single-point trust,
  the end-to-end overclaim) **and** suggested fixes that did **not** fit (the HE reorder/counter). Every finding was
  checked against the spec — applied when right, rejected-with-reason when wrong. Not cargo-culted.

## Owner-gated next steps (NOT auto-done)

- Third-party crypto audit before any production use.
- Forward-secure / key-evolving TSA signer (XMSS/LMS) or key-epoch rotation; separate attestation key per role.
- eIDAS qualification path for pqtsa (ASN.1 RFC-3161 TST, LTV/ERS, accredited UTC source) if pursuing QTSA status.
- Deploy decisions for `pqcbom` (Cloudflare worker / GitHub Action) and any hosted endpoints — all staged, none live.
- Official NIST ACVP cross-validation vectors to complement the deterministic KATs.

## Deferred-hardening pass (after the 10-task run) → SDK 0.3.0-draft, 23 modules, ~273 tests

Closed the tracked pure-code backlog from `SECURITY_REVIEW.md`, each council-reviewed and verified against spec:

1. **RFC-6962 index/tree_size binding at ALL FOUR inclusion sites** — `pqsign.verifyBundle`, `pqtsa.verifyAnchor`,
   `pqindex.verifyTermInclusion` (local sha512 RFC verifier), and `pqinduct` (added `sth_tree_size` to the SIGNED
   credential core so its unsigned carried proof is bound). Each has a non-power-of-2 all-members test.
2. **pqsign consistency proofs** — RFC-6962 §2.1.2 (`verifyConsistency`), append-only / no-rewrite, Gemini-confirmed.
3. **PQEF schema finalize** — typed, version-pinned allowlist; RFC-6901 JSON-Pointer paths; reject-unknown-version;
   value-secret + type-confusion guards (Moonshot's remaining items).
4. **pqkt — NEW Key Transparency module** — issuer-key log + monitor, hardened across TWO council rounds: Grok
   (added CONIKS authority chaining — operator can't mint keys) then OpenAI (monotonic seq vs replay; bootstrap
   pinning, TOFU off by default; UNSEEN→ACTIVE→REVOKED blocking post-revoke rebind; distinct signing contexts).
5. **AUDIT_READINESS.md** — scope/primitive-inventory/known-limits package so the (owner/external) third-party
   crypto audit can start cold.

Discipline held: the council found genuine breaks (pqkt operator-minting + post-revoke-rebind) and they were fixed
*before* the module was accepted, with explicit attack tests. Still owner-gated: the external audit, and a
multi-witness gossip network for pqkt completeness. Nothing deployed.

## "Do it all" — maximum buildable toward the remaining owner/external items → SDK 0.4.0-draft

The remaining items were a third-party audit (must be external) and deploying independent witnesses (needs your hosts).
Built everything buildable toward both:

1. **`vectors-crosscheck.mjs`** — the audit's verifiable core in-repo: an independent from-scratch RFC-6962 reference
   differential-tested against the optimized verifiers over **42,574 cases** (every size/index/prefix to 130). It
   immediately surfaced a test-design subtlety (an inconsistent size+root pair the STH never forms), confirming the
   verifiers correctly check against the *signed* pair.
2. **`witness-service.mjs`** — a deploy-ready witness node with **durable state** (a restarted node still refuses
   forks), a gossip pool, and an HTTP handler; owner-gated DEPLOY steps included.
3. **`THREAT_MODEL.md`** — audit-grade assets/adversaries/boundaries + per-asset threat→mitigation→residual.

Irreducible remainder (NOT autonomously doable, by definition): you commission the external crypto/side-channel
audit; you operate ≥1 independent witness + gossip channel. Everything else is built, tested (~298 across 25 files),
and staged. Nothing deployed.

## Roadmap-completion run → SDK 0.10.0-draft (~26 modules, ~360 tests, all green)

"Build everything + all products + money + always full Team-Apex." Delivered, each full-council-reviewed (fixes
applied BEFORE acceptance):
1. **New products:** `pqpki` (hybrid PQ CA — Ed25519+ML-DSA-87 certs, chain/path_len/CRL-freshness/kid-binding),
   `pqvault` (long-term confidentiality vault — HNDL envelopes + signed manifest + crypto-agility; rollback-fixed),
   `pqcompliance` (signed control-gap mapper, CNSA/NIS2/CRA/DORA/SC-13 — code-context, findings-hash-bound,
   "not-a-certification"), `pqx3dh` (Signal **PQXDH** async handshake → seeds `pqratchet-he`; transcript-bound +
   one-time KEM). **Messaging core now complete end-to-end** (PQXDH → ratchet → sealed-sender).
2. **Money / federal:** `pqcbom-report` Evidence Pack + `pqverify-api` public verifier wired into the funnel worker
   (PREVIEW-labeled, hold-until-audit); `program/fed-grants.mjs` found **6 real PQC vehicles** (NIST/NRL/DOE/USMA/
   USAFA); `program/sam-scan.mjs` (SAM key validated, rate-frugal).
3. **Audit package now TURNKEY:** `SPINE_SPEC` + pinned PROOF-BYTE vectors + edge sizes + negatives, `AUDIT_DOSSIER`,
   `ADVERSARY_MODEL`, `REPRODUCIBILITY` + CycloneDX `sbom.cdx.json`, `AUDITOR_QUICKSTART`, **`AUDIT_RFP.md`**.
   Convergent council fix this run: **canonical leaves** (`entryLeafHash`) across the whole spine — cross-impl determinism.

Council discipline held throughout: real breaks found AND fixed pre-acceptance (pqvault rollback, pqpki CRL/kid,
pqcompliance overclaim+integrity, pqx3dh transcript-binding+one-time-KEM); seat suggestions that didn't fit were
rejected-with-reason (logged in SECURITY_REVIEW).

**Irreducible remainder (unchanged, genuinely not single-module code):** (a) OWNER/EXTERNAL — commission the audit
(turnkey), the preview deploy (your accounts/spend), sales; (b) LARGE multi-month NETWORK programs — messaging
transport/super-app, decentralized search network, agentic marketplace (their crypto CORES are built). Recommendation
on record: commission the audit — it's the gate from "unaudited reference" to deployable + sellable. Nothing deployed.
