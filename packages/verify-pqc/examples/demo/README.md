# TRELYAN Quantum-Safe Scan — 60-second runnable demo

Don't trust the claims — **run them.** This scans a synthetic target repo with the real TRELYAN SDK and produces inspectable artifacts. No hosting, no account, no network calls.

```bash
cd trelyan-interop/packages/verify-pqc
npm install            # one dependency: @noble/post-quantum
node examples/demo/run-demo.mjs
```

Expected output: **grade F · 6 files · 25 findings · 2 suppressed**, then 8 self-checks (all ✓), then artifacts in `examples/demo/demo-out/`.

## What gets produced (in `demo-out/`)
| File | What it proves |
|---|---|
| `findings.sarif` | SARIF 2.1.0 with **repo-relative paths** — upload to GitHub and findings appear in **Security ▸ Code scanning** + inline PR annotations. |
| `cbom.cdx.json` | A **CycloneDX 1.6** Cryptographic Bill of Materials (structurally conformance-checked). |
| `evidence-pack.signed.json` | The **hybrid-signed** (ML-DSA-87 ∧ SLH-DSA, FIPS 204+205) Migration Evidence Pack. The grade is **recomputed from the findings** at verification and the rendered report is bound — a forged grade or doctored report is caught. |
| `evidence-pack.md` | The human-readable report (scorecard + roadmap + regulatory-relevance note + honest limits). |
| `attestation.json` | A **full `pqattest` attestation** of the signed pack: signed by **3 algorithm families** (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519) **AND** a **2-of-2 threshold PQ timestamp** **AND** an **RFC-6962 transparency-log inclusion proof** **AND** **2 witness co-signatures** on the tree head (equivocation resistance). The seal *countersigns* the timestamp + tree-head + thresholds, so it is **downgrade-detecting under the declared trust model** (correctly pinned keys + an honest TSA/witness threshold + sound primitives, per `ATTESTATION_SPEC.md` §4) — the demo proves a swapped-in same-hash timestamp makes verification fail. *(Not an eIDAS "qualified" timestamp; not a legal determination.)* |
| `expected-summary.json` | A diff-able snapshot, so `run-demo.mjs` doubles as a regression test (it exits non-zero on drift). |

## Verify the Evidence Pack yourself (don't trust — check)
```bash
node ../../verify-pack.mjs demo-out/evidence-pack.signed.json
# -> VERIFIED yes, but "trust-anchored: NO" (self-consistent only, no key pinned).
# For authenticity, pin the signer key you got out-of-band:
node ../../verify-pack.mjs demo-out/evidence-pack.signed.json --mldsa-pub <hex> --slh-pub <hex> --require-pinned
```

## What the sample target shows (on purpose)
- **It finds real risk:** `node-forge` + RSA/ECDSA/MD5 + `TLSv1.0` + `RS256` + `ssh-rsa` → grade **F**.
- **It's not just grep — two layers:** it reads declared crypto **dependencies** from `package.json` (`node-forge` → broken, `@noble/post-quantum` → safe), not only inline strings.
- **It knows modern from legacy:** `TLSv1.0` is flagged but `TLSv1.3` **on the same line** is not.
- **It doesn't over-grade docs:** the `RSA`/`3DES` mention inside a **comment** in `pq/handshake.mjs` is tagged *informational* — it does not drag the code grade.
- **It credits migration:** `ML-KEM-1024`, `ML-DSA-87`, `sntrup761`, `AES-256`, `SHA-512` are recognized as **quantum-safe**.
- **It has an escape hatch:** `sample-repo/.pqcbomignore` accepts the `classical-hybrid-ok` legs → they're **counted (suppressed), not graded**, so a team can turn the gate on.

## Honest scope (the point of the demo is that you can check it)
This is a **synthetic** target. The scanner is a two-layer **lexical + dependency-manifest** tool — findings are **leads to verify**, not a guaranteed-complete inventory (no full AST/data-flow, live-TLS, runtime, or binary discovery). The underlying SDK is an **unaudited reference implementation** — not a FIPS-140-3 validation or a certification. The Evidence Pack is an assurance artifact (tamper-evident given a pinned key), not a compliance attestation. See [`../../../program/products/ASSURANCE.md`](../../../program/products/ASSURANCE.md).
