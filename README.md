# verify-pqc — post-quantum readiness scanner + verification toolkit

[![PQ Readiness](https://img.shields.io/badge/PQ%20readiness-scan%20your%20repo-6f42c1)](https://throndar.ai/cbom)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CycloneDX](https://img.shields.io/badge/CBOM-CycloneDX%201.6-blue)](https://cyclonedx.org/)

**Find where quantum-vulnerable cryptography lives in your codebase — get an A–F readiness grade and a CycloneDX 1.6
CBOM (Cryptographic Bill of Materials).** Free, open-source (MIT), dependency-free. The inventory that CNSA 2.0,
DORA, and NIS2 preparation starts with.

> **Try it in your browser first — nothing uploaded:** **https://throndar.ai/cbom**

## Scan your repo

**In CI (GitHub Action, no install):**
```yaml
# .github/workflows/pqc-readiness.yml
name: PQC readiness
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: brandonjsellam-Releone/pq-readiness-scorecard@v1
        with:
          path: .
          fail-on: broken-classical    # fail the build on classically-broken crypto
```
It writes a CycloneDX 1.6 CBOM, a SARIF report (upload it to see findings in the **Security** tab), and an A–F grade.

**Locally (CLI):**
```bash
npx -p @trelyan/verify-pqc pqcbom .        # scan the current directory
npx -p @trelyan/verify-pqc pqevidence pack . --keys signer.keys.json   # signed Evidence Pack
```

## What it detects

- **Quantum-broken (Shor):** RSA, ECDSA, ECDH, finite-field DH, EC curves, RSA/ECDSA JWTs, SSH RSA/ECDSA keys.
- **Quantum-weakened (Grover):** AES-128/192, SHA-256.
- **Classically broken (fix today):** MD5, SHA-1, RC4, 3DES, Blowfish, deprecated TLS, NTLM, WEP.
- **Quantum-resistant:** ML-KEM, ML-DSA, SLH-DSA (NIST FIPS 203/204/205), AES-256, SHA-384/512, ChaCha20.
- **Broken PQ candidates:** SIKE/SIDH (Castryck–Decru 2022) and GeMSS — so a project that *thinks* it migrated isn't
  left trusting something already broken.

Reads inline code, declared crypto libraries, numeric OIDs (certs/ASN.1), base64/PEM key blobs, and **hardcoded
JWT/JOSE token headers** (decodes the base64url header only — never the payload — and classifies the `alg`).
Key-establishment findings (KEM/DH/ECDH + RSA *key transport*) carry a **harvest-now-decrypt-later** urgency flag —
recorded ciphertext is decryptable once a CRQC exists, so those migrate first; signatures are forge-later. Skip test
fixtures with `--exclude` / `.pqcbomignore` path lines (excluded paths are counted in the output, never silent).

**Honest posture:** lexical scan — findings are **leads to verify, not a complete inventory**, and **not a
certification**. Algorithm names denote the public standards they're based on, not a CMVP/FIPS-140 validation. A scan
that examines zero files *refuses to grade* rather than reporting "A". Falcon is FN-DSA for the forthcoming FIPS 206
(in development), not yet standardized.

## The toolkit (`packages/verify-pqc/`)

Dependency-free JS (Node + browser) for post-quantum verification and provenance:

- **`pqcbom`** — the scanner above (CLI + GitHub Action).
- **`pqevidence`** — build/verify a signed **Evidence Pack**: scan → ML-DSA-87 ∧ SLH-DSA-signed report + CBOM +
  migration plan, self-verifying (an altered grade fails the signature).
- **`verifyPQC`** — inspect Falcon-1024 signatures and verify post-quantum inscriptions on Algorand (AVM
  `falcon_verify` opcode).
- **ML-DSA-87 STH / receipt verification** for THRONDAR provenance (offline, key-pinned).

```bash
npm i @trelyan/verify-pqc
```

## Need a signed, auditor-ready report?

An **Evidence Pack** turns the scan into a cryptographically signed, independently-verifiable deliverable your
auditors can check offline (verify against the published signer key). → **https://throndar.ai/evidence**

---

## Also in this repo: Falcon-on-Algorand interop conformance kit

A reusable kit proving two independent Falcon-1024 signers emit **byte-compatible signatures for the Algorand AVM
`falcon_verify` opcode**, plus a joint **PQ object + authority** demo (one Falcon keypair that both spends via
algo-pqc-kit `FalconLsig` and inscribes via a trelyan-pq write-once record — no Ed25519 in the authorization path).
Built to settle the encoding question the authoritative way: on-chain bytes. Full byte-level spec in
[`SPEC.md`](SPEC.md).

**The encoding verdict (adjudicated on-chain + against the Falcon ref):**

| Item | Resolution |
|---|---|
| `0xBA` header | `0x3A` (standard Falcon-1024 compressed) `\| 0x80` (trelyan-pq deterministic-wrapper bit) + a `0x00` version byte. The `0x80`/`0x00` are a **project convention, not a NIST Falcon / FIPS-206 field**. Never call it "the FN-DSA header." |
| `≤1423` vs `≤1232` | app 763809096's TEAL enforces `len(sig) ≤ 1423`; measured sig is **1236 B**. The AVM opcode has no sig-length check (only the 1793-B pubkey). `[1232]byte` is a nominal annotation. |
| Does the opcode get `0xBA`? | **Yes** — the contract strips only the 2-byte ABI prefix (`extract 2 0`); no header-stripping op across 405 TEAL lines; `falcon_verify` is `assert`-ed. |
| Authority | **On-chain acceptance.** App **763809096** passes `falcon_verify` with these bytes → empirically AVM-valid. A shared KAT settles cross-signer interop. |

**Conformance core (Python):** `falcon_interop.py` (`inspect`/`compare`/`kat`), `onchain_probe.py` (dumps the Falcon
bytes hitting `falcon_verify` on-chain), `kat/*.json` (golden vectors; the on-chain one is offline-reproducible via
`kat/verify_onchain_kat.py`), `test_interop_demo.py` (joint demo skeleton). **Two-layer anchor (`anchor/`):**
`anchor_sth.py prepare|verify` binds THRONDAR's transparency-log signed tree head to a Falcon inscription
(prepare/verify only; the Falcon-sign + inscribe step is a gated owner action — no key is read here). **Web tools
(`web/`):** drop-in, in-browser, no backend — `verify-live.html`, `verify-unified.html`, `pqbadge.js`, `anchor.html`.

```bash
python falcon_interop.py inspect my_sig.hex
python onchain_probe.py --app 763809096 --indexer https://testnet-idx.algonode.cloud
node packages/verify-pqc/test.js                 # SDK unit + live on-chain test
```

## License & credit

MIT, commons-first. The Falcon-on-Algorand interop kit was co-developed by **TRELYAN** and **algo-pqc-kit
(quantalabss)** — keep `Signed-off-by` on commits and credit both. It's a **reference implementation** of a PQ
object+authority flow on Algorand (don't over-claim "first").

> ⚠️ Do not modify the deployed contract / ABI / box prefixes of app 763809096. This repo only reads the chain and
> adds test/tooling around the existing interface.
