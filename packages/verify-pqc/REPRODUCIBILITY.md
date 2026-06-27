# Reproducibility — TRELYAN PQ SDK (audit input)

Everything in this package is **deterministic and offline** once dependencies are installed. An auditor can
reproduce every test, vector, and root from a clean checkout. Reference code, **unaudited**.

## Environment
- **Node.js ≥ 18** (CI/dev on **v24.16.0**). Pure-JS; **no native addons, no build step**.
- Dependencies (4, all `@noble`, pure-JS) — exact resolved versions in `sbom.cdx.json`:
  `@noble/post-quantum@0.6.1`, `@noble/hashes`, `@noble/ciphers@2.2.0`, `@noble/curves@2.2.0`.
- ⚠️ **Pin before audit:** a `@noble/hashes` **1.x↔2.x skew** exists in the tree (declared `^1.8.0`, `2.2.0` resolved
  under `@noble/curves`). Commit a `package-lock.json` so the dependency tree is byte-stable for the auditor.

## Reproduce
```bash
git checkout <commit>           # pin the exact tree
cd trelyan-interop/packages/verify-pqc
npm ci                          # install from the lockfile (NOT `npm i`) for a reproducible tree
node test-all.mjs               # all module self-tests + unified surface (~330 assertions)
node kat-conformance.mjs        # deterministic NIST-style KATs (seed-pinned)
node spine-vectors.mjs          # pinned transparency-spine vectors (roots + proof bytes)
node vectors-crosscheck.mjs     # 42,574-case differential vs an independent RFC-6962 reference
node fuzz-robustness.mjs        # negative/fuzz sweep (0 fail-open; verifier totality)
```
No network is required for any of the above (only `npm ci` touches the registry). The federal-sourcing tools
(`program/sam-scan.mjs`, `program/fed-grants.mjs`) DO make outbound calls and are NOT part of the deterministic core.

## Determinism guarantees
- **KATs** (`kat-conformance.mjs`): seed-pinned keygen + fixed-entropy signing + seeded encapsulation → frozen digests
  for ML-KEM-1024 / ML-DSA-87 / SLH-DSA-SHAKE-256s. Any engine drift fails.
- **Spine vectors** (`spine-vectors.mjs`): fixed 7-leaf tree (entries `{"v":"spine-leaf-i"}`, STH key seed `0x2A×32`,
  ts `1700000000`) → pinned `leaf0`, `root@3/4/7`, the index-3 audit path, and the 3→7 consistency proof, plus
  inclusion/consistency over edge sizes 1/2/8 and negative cases. `root@7` equals the signed STH root.
- **Canonicalization**: leaves AND STHs use the same sorted-key `canon` (`entryLeafHash`), so a second-language
  implementation reproduces the bytes (see `SPINE_SPEC.md §2`).
- **No wall-clock in deterministic paths**: KAT/vector timestamps are fixed constants.

## Integrity
After `npm ci`, the dependency tree should match `sbom.cdx.json` + the lockfile. Verify with `npm ls @noble/*` and
diff against the SBOM. Reproducible-build hardening (e.g., a pinned container image) is an owner step for release.
