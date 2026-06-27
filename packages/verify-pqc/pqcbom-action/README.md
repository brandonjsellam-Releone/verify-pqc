# TRELYAN Quantum-Safe Scorecard — GitHub Action

> Scan your repo for **quantum-vulnerable cryptography**, get a CycloneDX **CBOM** + an **A–F Quantum-Safe grade**, and (optionally) **fail the build** on banned crypto. Your first step toward CNSA 2.0 / NIS2 / CRA / DORA readiness.

[![Quantum-Safe](https://img.shields.io/endpoint?url=https://scan.trelyan.dev/badge%3Fgrade=A)](https://trelyan.dev/quantum-safe)

## Usage
```yaml
- name: Quantum-Safe Scorecard
  uses: trelyan/quantum-safe-scorecard@v1
  with:
    path: .
    fail-on: broken-classical,quantum-broken   # fail the build on banned crypto (optional)
    min-grade: B                                # fail below this grade (optional)
```
Outputs: `grade` (A–F), `score` (0–100), `sarif-file`, `cbom-file`. Artifacts: `cbom.cdx.json` (CycloneDX), `pqcbom.sarif` (SARIF 2.1.0), `quantum-safe-badge.json` (shields endpoint). A scorecard table is written to the job summary.

### See findings in the Security tab (SARIF → GitHub code-scanning)
The Action writes a SARIF 2.1.0 report (`pqcbom.sarif`) with **repo-relative** paths and `error`/`warning`/`note` levels by quantum risk — upload it so findings appear in the **Security ▸ Code scanning** tab and as **inline PR annotations**:
```yaml
- name: Quantum-Safe Scorecard
  id: pqc
  uses: trelyan/quantum-safe-scorecard@v1
  with: { path: . }
- name: Upload to code-scanning
  if: always()                                   # publish findings even if the gate failed the build
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.pqc.outputs.sarif-file }}
```
*(Requires GitHub code-scanning enabled — public repos, or private with GitHub Advanced Security.)*

### Suppressing accepted findings (so you can turn the gate on)
Real codebases have legacy or accepted crypto. Suppress without disabling the whole gate — suppressed occurrences are **counted and reported, not graded**:
- **Inline** — add `pqcbom-ignore` on the line: `const k = RSA.generateKey(2048); // pqcbom-ignore: accepted, sunset Q3`.
- **Allowlist file** — a `.pqcbomignore` at the scan root, one **algo label** *or* **risk class** per line (`#` comments allowed):
  ```
  # accept these during the migration window
  RSA
  quantum-weakened
  ```
The job summary notes how many occurrences were suppressed.

## What it detects
RSA / ECDSA / ECDH / DH / EC curves (quantum-broken by Shor) · AES-128/192, SHA-256/384 (quantum-weakened by Grover) · MD5 / SHA-1 / RC4 / 3DES (classically broken) · X25519 / Ed25519 (flagged as valid *hybrid* legs) · ML-KEM / ML-DSA / SLH-DSA / AES-256 / SHA-512 / ChaCha20 (quantum-safe). Each finding carries a migration recommendation to NIST PQC.

## Tiers
- **Free** (this Action + CLI): the A–F badge + CBOM artifact.
- **Team / Enterprise**: private-repo monitoring, the hosted verification API, and an auditor-ready PQC-readiness evidence pack signed with post-quantum signatures. → trelyan.dev/quantum-safe

## Honest limits
Lexical scan (flags algorithm names in code/comments — verify findings; production adds AST + cloud/cert/KMS discovery). The evidence-signing (ML-DSA-87) is real. Not legal advice; maps to but does not certify CNSA 2.0 / NIS2 / CRA / DORA.
