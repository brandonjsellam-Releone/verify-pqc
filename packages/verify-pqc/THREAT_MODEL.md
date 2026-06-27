# @trelyan/pq-sdk — threat model (DRAFT, audit input)

Companion to `AUDIT_READINESS.md` and `SECURITY_REVIEW.md`. Scope: the reference SDK's cryptographic/protocol logic.
Out of scope: side-channels (not constant-time), deployment/operations, the underlying `@noble` primitives (widely
validated; cross-check vs NIST ACVP is the auditor step). `SDK_VERSION 0.3.0-draft`.

## Assets
- **A1** Authenticity/integrity of signed artifacts, attestations, timestamps, and evidence bundles.
- **A2** Confidentiality of sealed secrets (POLARSEEK) and message plaintext (ratchets).
- **A3** Correct binding of *which* PQ suite/keys were actually used (gateway attestation, PQEF verdict).
- **A4** Accountable, non-equivocating key lifecycle (pqkt key transparency).
- **A5** Append-only integrity of transparency logs (pqsign/pqtsa/pqkt/pqinduct/pqindex).

## Adversaries & capabilities
- **N — Network MITM:** can read/modify/drop/replay messages; cannot break ML-KEM-1024/ML-DSA-87/SHA-2/3.
- **L — Malicious log/gateway/TSA operator:** controls a server, can append/withhold/reorder, equivocate, lie about
  posture; does NOT hold pinned issuer/peer secret keys.
- **I — Compromised issuer key:** holds a (possibly stale/revoked) issuer secret.
- **Q — Quantum adversary (HNDL):** harvests ciphertext now to break classical crypto later.
- **Out of scope:** physical/side-channel; a global passive adversary's traffic analysis; collusion of *all* trusted parties.

## Trust boundaries
- Verifier-supplied **pinned keys** are the root of trust (never bundle/peer-asserted claims).
- Transparency-log **STH (tree_size + root)** is bound under the log signature; inclusion/consistency proofs are
  verified against the *signed* pair (size and root never mixed across STHs).
- Identity ⇄ negotiation ⇄ attestation tied to ONE pinned identity per party (gateway), domain-separated by context.

## Per-asset analysis (threat → mitigation → residual)

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| A1 | N forges/replays a signature | ML-DSA-87 over canonical bytes + distinct domain-separation contexts; hedged signing | — |
| A1/A5 | L serves a proof for an unlogged or wrong-position leaf | leaf RECOMPUTED from content; RFC-6962 §2.1.1 inclusion DERIVES directions from (index, tree_size) + length-checked; tree_size bound to the signed STH; differential-tested (42k cases) | log can still *withhold* a leaf from a client view → needs gossip (A4) |
| A5 | L rewrites history / rolls back | RFC-6962 §2.1.2 consistency proofs; monitor rejects smaller/inconsistent STH | client must actually run the monitor against gossiped STHs |
| A3 | Lying gateway claims pq:true over a classical handshake | attestation binds the REAL transcript hash; client checks vs its OWN th; client countersignature = transferable evidence; offer fingerprint folded in (anti-splice) | client↔gateway leg only (terminating proxy); collusion out of scope |
| A4 | L mints a key for an issuer it doesn't control | CONIKS authority chaining: bind/revoke signed by the issuer's current key; unauthorized events ignored | bootstrap = pin-or-TOFU (TOFU off by default) |
| A4 | L replays/rolls back an issuer key | per-issuer monotonic seq (exact next-seq); REVOKED terminal (no post-revoke rebind); distinct auth/possession contexts | — |
| A4 | L equivocates / splits view across clients | witness co-sign (refuse conflicting same-size root); witness append-only check vs own last head (no fork-following); k-of-n; gossipDetectEquivocation flags partitions | needs ≥1 independent witness + durable state + a real gossip channel (deployment) |
| A2 | Q harvest-now-decrypt-later | hybrid X25519+ML-KEM-1024 (KEM); long-term confidentiality rests on ML-KEM | not forward-secret where custody is by-design long-term (POLARSEEK) |
| A2 | N reads message metadata | ratchet header encryption (pqratchet-he) hides keys/counters | traffic timing/volume/IP not hidden (onion layer's job) |
| I | Compromised/old issuer key used | revoke + monotonic seq; RP watches via detectUnexpectedRotation | window before revoke is logged + witnessed |
| A1 | Evidence bundle smuggles secrets / type-confusion | typed, version-pinned schema allowlist; value-secret scan; reject-unknown-version | secret value-scan is heuristic |

## Self-disclosed residuals requiring the AUDIT / DEPLOYMENT (not code)
1. **Third-party cryptographic + side-channel audit** (constant-time, primitive cross-validation vs NIST ACVP).
2. **Operate ≥1 INDEPENDENT, durable witness** + a gossip channel (closes A4 completeness/split-view in practice).
3. **FIPS-140-3 validated module** for any compliance claim; **qualified eIDAS QTSA** for legal timestamps.
4. **Privacy/GDPR:** pseudonymous/salted issuer_ids + DPIA before operating a public KT log.

Every code-level finding from the council rounds is recorded in `SECURITY_REVIEW.md` (applied or rejected-with-reason).
