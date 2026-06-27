# Packaging & release plan (DRAFT — read before any `npm publish`)

This directory holds **two distinct things** that must ship as **two distinct packages**. Do not merge them.

## 1. `@trelyan/verify-pqc` — the lean, publishable browser verifier (LIVE-ELIGIBLE)
- **What:** dependency-free Falcon-1024 inspection + on-chain `falcon_verify` verification + optional ML-DSA-87/SLH-DSA STH verification. The polished `README.md` is its public face.
- **Surface (already correct):** `package.json` `files` = `index.js, mldsa.mjs, slhdsa.mjs, verify.mjs, throndar-sth-key.mjs, throndar-slh-key.mjs, README.md`; `@noble/*` are **optionalDependencies**. This is intentionally narrow.
- **⚠️ Guard:** the `files` allowlist deliberately **excludes** every SDK reference module (pqcbom*, pqgateway*, pqkt, pqtsa, pqsign, pqef, polarseek, pqratchet*, pqindex, pqassistant, pqverify-api, witness-service, fuzz/crosscheck, etc.). A plain `npm publish` therefore does **not** ship unaudited crypto. **Do not add SDK modules to `files`/`exports` of this package.**

## 2. `@trelyan/pq-sdk` — the full reference SDK (HELD until the third-party audit)
- **What:** `sdk.mjs` + the ~25 reference modules (the Tier-1 PQ stack, the CBOM revenue product, KT, gateway, etc.).
- **Status:** **NOT for publication yet.** Unaudited reference code, not FIPS-140-3 validated, not constant-time. See `SDK.md`, `SECURITY_REVIEW.md`, `THREAT_MODEL.md`, `AUDIT_READINESS.md`.
- **Intended manifest when the audit clears (owner action):** a separate package (own dir or workspace) with:
  - `"name": "@trelyan/pq-sdk"`, `"type": "module"`, `"private": true` until release.
  - `dependencies` (NOT optional): `@noble/post-quantum`, `@noble/hashes`, `@noble/ciphers`, `@noble/curves`.
  - `exports`: `.` → `sdk.mjs`, plus subpaths per module.
  - `bin`: `pqcbom` → `pqcbom-cli.mjs` (the scanner CLI / `npx` entry).
  - `scripts.test`: `node test-all.mjs`.
  - README that leads with the honest posture (preview/unaudited) until the audit is referenced.
- **Release gate:** third-party crypto + side-channel audit complete → drop `private`, set a real version, publish. Until then, distribute only as source for review.

## Why split
The verifier is small, dependency-free, and safe to share now; the SDK is large, depends on `@noble/*`, and is unaudited. Publishing them together would (a) ship unaudited crypto, and (b) break the verifier's dependency-free guarantee. Keep them separate.
