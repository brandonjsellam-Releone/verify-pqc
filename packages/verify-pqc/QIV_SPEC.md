# Quantum IP Vault (QIV) — reference spec (DRAFT)

*An immutable, post-quantum-signed intellectual-property **inscription + provenance** core. Blueprint 6 of the
TRELYAN × Qbeat set, built on the existing `@trelyan/verify-pqc` primitives. Reference implementation: `qiv.mjs`
(+ `qiv-cli.mjs`). Status: DRAFT, unaudited composition layer over the independently-audited `@noble` crypto.*

---

## 1. What the QIV is (precise, falsifiable)

The QIV lets an inventor/holder take an IP artifact — a patent draft, a trade-secret ciphertext, a lab notebook, a
dataset, or a defensive publication — and produce a **tamper-evident, independently-verifiable, post-quantum-signed
record** that:

1. **binds a digest** of the exact artifact bytes (SHA-512, domain-separated),
2. is **AND-signed** across three algorithm families — **ML-DSA-87 (FIPS 204) ∧ SLH-DSA-256f (FIPS 205) ∧ Ed25519** —
   so a forgery must break a lattice **and** a hash-based **and** a classical scheme (anti-downgrade; see `pqseal`),
3. is **timestamped** by a post-quantum TSA token (ML-DSA-87 over the artifact digest — existence-at-time; `pqtsa`),
4. is bound to a **TRELYAN Vault Cell** (1 of the 1,024-cell supply) with a lifecycle state
   (`sealed → inscribed → released`), and
5. carries the **exact bytes** to anchor on Algorand (TRELYAN's live PQ chain, TestNet app `763809096`) — produced but
   **not broadcast** (broadcasting is owner-gated; the same honesty as `pqanchor`).

Plus an append-only, hash-chained, per-transition-**signed chain of custody** (who touched the IP, when, with what
authority, moving the cell state forward only) — Blueprint-6 Module 2.

Everything verifies **offline, fail-closed**, against pinned keys (`verifyInscription`, `verifyCustody`).

## 2. What the QIV is **not** (claim hygiene — do not overclaim)

| Tempting claim | Honest statement |
|---|---|
| "Legally admissible, tamper-proof records" | Produces evidence that can **support** an IP dispute (existence-at-time + integrity + provenance). **Admissibility and legal weight are for a court + counsel** in the relevant jurisdiction — the QIV does not and cannot confer them. |
| "World's first blockchain IP registry" | Blockchain IP-timestamping products already exist (e.g. WIPO PROOF's successors, Bernstein, various OpenTimestamps tools). The QIV's distinct claim is the **specific PQ composition** above — not primacy. |
| "Register / file your patent on-chain" | Inscribing a hash **does not create, register, examine, or prosecute** any IP right. It is a private evidentiary record. Actual filing goes through USPTO/EPO/WIPO. |
| "Quantum-proof / unbreakable" | The claim is the exact composition (3-family AND, offline-verifiable against pinned keys). No "unbreakable / quantum-safe." |
| "Falcon-1024 secured" | Falcon-1024 (FN-DSA) is the **optional on-chain provenance leg only** (AVM `falcon_verify`), and **FIPS 206 is a DRAFT**. The off-chain record's integrity does **not** depend on Falcon — the primary signature is the NIST-standardized ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519. |

## 3. Securities red-line (Blueprint-6 Module 3 — deliberately NOT built)

The blueprint's Module 3 describes a **marketplace** with *"fractional ownership (tokenized patent shares,
SEC-compliant)"* and buying/selling/licensing of IP value. **Offering or selling fractional/tokenized ownership
interests is a securities matter** (US Securities Act; EU Prospectus Regulation / MiCA; CH FINMA), and building it
without securities counsel and a compliant offering structure is a legal red-line.

- `qiv.mjs` **machine-enforces** this gate: `marketplace()` **always throws** `QIV_MARKETPLACE_SECURITIES_GATED`.
- **Provenance-only** custody entries (`assign`, `license`) are permitted because they **record who holds/licenses IP
  and confer no investment interest and move no value**. Any feature that transfers value or an ownership interest is
  out of scope until counsel signs off.

## 4. Architecture (module map)

```
artifact bytes ──digestArtifact()──▶ SHA-512 (tag: trelyan-qiv-artifact-v1)
                                         │
 metadata + cell + offchain ptr ─────────┼──▶ record core ──recordHash()──▶ record_hash (tag: trelyan-qiv-record-v1)
                                         │                                      │
                              pqseal.seal (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519)  │
                                         │                                      │
                              pqtsa.timestamp (ML-DSA-87 over digest)           │
                                         │                                      ▼
                              anchorNote()  "TRLQIV1"|app(8)|cell(2)|digest(64)|record_hash(32)  ──▶ (owner-gated broadcast)

 custody:  openCustody(cell) ─ appendCustody{create,inscribe,release,assign,license,annotate}* ─ verifyCustody (fail-closed)
           Ed25519 ∧ ML-DSA-87 ∧ (opt) SLH-DSA-256f, prev_hash chain, nonce anti-replay, monotonic ts + cell state
```

Reused audited-composition primitives (already in this SDK, already swept): `pqseal.mjs`, `pqtsa.mjs`, `pqanchor.mjs`,
and the `pqauditlog.mjs` custody pattern. The QIV adds the IP-specific state machine + record format + securities gate.

## 5. API

```js
import { inscribe, verifyInscription, openCustody, appendCustody, verifyCustody, digestArtifact, marketplace } from './qiv.mjs';

const ins = inscribe({ cellId, ipType, metadata, artifactBytes, offchain }, signers, tsaKey, { ts });
const v   = verifyInscription(ins, artifactBytes, { trusted, requireKinds:['lattice','hash-based','classical'], tsaPub, appId });
// v.verified is TRUE only when: artifact digest matches, record hash matches, the 3-family seal verifies under pinned
// keys, the timestamp binds the digest, the anchor note is the exact deterministic bytes, and cell/type/state are valid.
```

CLI:
```
node qiv-cli.mjs keygen   --out keys.json
node qiv-cli.mjs inscribe --artifact draft.pdf --cell 7 --type patent --title "…" --keys keys.json --out record.json
node qiv-cli.mjs verify   --record record.json --artifact draft.pdf --keys keys.json
node qiv-cli.mjs custody  --demo
```

## 6. Trust vs. validity

A verdict is **validity** (the record is internally self-consistent) until you **pin** the expected keys, at which
point it is **trust** (this specific signer produced it). `verifyInscription` without `opts.trusted` returns validity
only; the CLI's `verify` pins from `--keys` by default and warns when unpinned. This mirrors the whole SDK's
validity-vs-trust discipline (see `pqseal` footgun note).

## 7. Owner-gated / not done here

- **Broadcasting** the anchor to Algorand (needs a funded account + the on-chain Falcon-1024 signer). The core emits the
  exact note bytes + commitment and verifies them after the fact; it never broadcasts.
- **Off-chain storage pinning** (IPFS/Arweave/Pinata) — `qiv-pin.mjs` is the adapter. It records a plain SHA-256 of the
  exact bytes into the (signed) record's pointer, so a third party can fetch `ipfs://<cid>`, hash the bytes, and verify
  they match the inscription (`verifyPinnedContent`) — the binding is offline-verifiable and does **not** require us to
  recompute the IPFS CID. `pin()` is MOCK/dry-run by default; a **live upload publishes the artifact and is owner-gated**
  (`{live:true, jwt, confirmOwnerApproved:true}` — the caller supplies the Pinata JWT; the module never reads secrets).
- **Multi-signature high-value transfer**, trade-secret key escrow, WIPO/registry integration, ML valuation — roadmap.
- **Marketplace / tokenized ownership** — securities-gated (§3).

## 8. Revenue framing (projections; platforms gated)

The blueprint's figures are **projections**, not committed pricing, and any paid offering is gated on the security
audit and (for the marketplace) securities counsel:

- Inscription fee (per artifact) and per-Vault-Cell annual maintenance — evidentiary-record SaaS.
- Enterprise API for large portfolio holders.
- **Not** included in any near-term offer: marketplace transaction fees / fractional-ownership (securities-gated).

**8a. Platform fees vs. investment interests.** Evidentiary-record SaaS fees (per-inscription, per-cell annual
maintenance, API tiers) are **operational access/service fees** — they confer no ownership interest, no voting
right, and no share of value, so they are *not* the thing the securities gate (§3) governs (analogous to cloud-storage
pricing). The Module 3 gate applies **only** to features that offer, sell, or facilitate transfer of IP *ownership
interests*, fractional shares, royalties, or secondary-market trading. A commercial build may charge basic SaaS fees
without tripping the gate; anything that grants a stake in an asset's value must go to securities counsel first. (This
is guidance, not legal advice — a specific fee structure should still be reviewed by counsel.)

The credible near-term wedge is the **defensible evidentiary record** (prior-art / trade-secret / research-data
timestamping with PQ signatures + provenance) — an extension of the Evidence Pack, sold on the same "measure, don't
claim" basis as the rest of the suite.

## 9. Self-tests

`node qiv.mjs` → 21 checks (inscribe/verify, wrong-artifact, doctored-metadata, swapped-anchor, dropped-leg downgrade,
cell bounds, **wrong-digest timestamp rejection (pinned + unpinned)**, **injected/missing record-field rejection**,
**offchain content-pointer allowlist**, custody chain + regression + tamper + unpinned, securities gate).
`node qiv-cli.mjs --selftest`. Included in the SDK green-gate (`node test-all.mjs`).

## 10. Adversarial review (3-lens, applied 2026-07-03)

A 3-lens review (crypto soundness / claim hygiene / securities red-line) was run over `qiv.mjs`, `qiv-cli.mjs`, and this
spec. **Claim hygiene: clean.** Applied fixes: exact-key **record schema validation** (blocks unsigned-field injection);
**off-chain pointer allowlist** (content-scheme only, not a payment/marketplace endpoint); explicit big-endian in the
anchor note; clarifying comments on the Ed25519 context-prepend pattern; the SaaS-fee vs. investment-interest note (§8a);
and negative tests for wrong-digest timestamps + record injection. Findings assessed as misreads (already-enforced TST
artifact binding; already-correct finite-ts ordering; DataView already big-endian) or house-convention (top-level verdict
fields, matching every sibling verifier) were not changed — the reasoning is recorded in the run notes.
