# LIMITATIONS — what `@trelyan/verify-pqc` does NOT guarantee

*Read this before relying on anything here. Credibility is the product: we'd rather you know the edges. This complements `ASSURANCE.md` (what IS demonstrated) and `THREAT_MODEL.md`. Posture: **experimental, feature-complete reference implementation — UNAUDITED. Not for production cryptographic reliance until a third-party audit closes.***

## Cryptographic core
- **Unaudited.** No third-party cryptographic or side-channel (SCA) audit has been performed. A funded audit (OSTIF/NLnet) is being pursued; until it closes, treat this as research-grade.
- **Not FIPS-validated.** It *uses* the NIST-standardized algorithms (FIPS 203 ML-KEM, 204 ML-DSA, 205 SLH-DSA) via `@noble/post-quantum`, but has **no CMVP validation**. "Uses FIPS algorithms" ≠ "FIPS-validated module."
- **Not constant-time / no side-channel guarantee.** Our harnesses show *functional* and *binding* properties, not timing/cache/power resistance. Do not assume protection against a local side-channel adversary.
- **Ed25519 is the classical interop leg — NOT post-quantum.** In hybrids it adds classical robustness only; it is broken by a quantum adversary on its own.
- **Falcon-1024 is provenance/on-chain only** (draft FIPS 206, not finalized); not a load-bearing PQ signature here.

## Attestation (`pqattest`) — "downgrade-detecting", not absolute
- It is **downgrade-DETECTING under the declared trust model** (see `ATTESTATION_SPEC.md §4`), not "downgrade-proof." It holds only when: keys are **correctly pinned**, a **threshold of TSAs/witnesses is honest**, and the underlying primitives are sound. Violate those and the guarantee does not hold.
- **Not an eIDAS "qualified" timestamp** — we are not an accredited QTSP. **Not** a legal, evidentiary, or court-admissibility determination.
- **Freshness/replay:** a static attestation proves existence-at-time + logging; it does not prevent replay of the artifact itself. Add a verifier nonce for online use.
- **Transparency log:** witness co-signing reduces but does not eliminate equivocation risk; a fully colluding log + all witnesses defeats it.

## Evidence Pack — tamper-evident ≠ correct/complete/compliant
- The signature proves **integrity + origin against a pinned key** (validity-vs-trust: with no pin, a pass proves only self-consistency, not authenticity).
- The A–F grade is a **heuristic posture score**, not a certification, audit opinion, or guarantee.
- The regulatory-relevance note maps findings to CRA/NIS2/DORA/CNSA 2.0 **topics** — it is **informational**, not conformance, an audit opinion, or legal advice.

## CBOM scanner — lexical + dependency-manifest, leads-to-verify
- Two layers: inline patterns over code/config **and** declared crypto libraries from manifests. Findings are **leads to verify**, NOT a guaranteed-complete inventory.
- **Published blind spots** (a lexical scan cannot see these — see `BENCHMARK.md`): crypto identified only by OID, embedded in a longer identifier, behind a custom wrapper name, resolved at runtime via a variable, or present as an encoded key/material blob. Also: no full AST/data-flow, no live-TLS handshake probing, no runtime, no binary/firmware discovery, limited language coverage.
- **Suppression** (`pqcbom-ignore` / `.pqcbomignore`) is auditable (counted, not silent) but can be **abused by a maintainer** to hide real findings.

## Assurance harnesses — evidence, not proofs
- tamper-binding (707 assertions), fuzz, property-based, accuracy-benchmark, and the 42k-case RFC-6962 differential are **bounded test evidence over the stated corpora** — they demonstrate engineering discipline and catch regressions; they are **not** formal proofs of bug-absence and not a substitute for the pending audit.
- The "breaking pqattest ⇒ breaking an underlying primitive" reduction is argued **informally**, not machine-checked.

## Operational
- Solo-maintained; no SLA, no support guarantee, no security-response SLA beyond `SECURITY.md`.
- Distributed as **source for review** (the npm package is marked private until the audit closes — see `PACKAGING.md`).

*If you find something this document fails to disclose, that's a bug in our honesty — please open an issue.*
