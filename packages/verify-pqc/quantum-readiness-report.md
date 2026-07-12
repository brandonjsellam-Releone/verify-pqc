# Post-Quantum Readiness Scorecard — Grade F (0/100)

**Critical — broken crypto in use** · 134 files · 60 distinct algorithms

| risk | count |
|---|---|
| ⛔ broken-classical | 640 |
| 🔴 quantum-broken | 663 |
| 🟡 quantum-weakened | 294 |
| 🔵 classical (hybrid-ok) | 500 |
| 🟢 quantum-resistant | 1357 |

## Findings & migration

| risk | algorithm | file | rec |
|---|---|---|---|
| ⛔ | MD5 | accuracy-benchmark.mjs:22 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | SHA-1 | accuracy-benchmark.mjs:23 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | 3DES/DES | accuracy-benchmark.mjs:24 | REMOVE; use AES-256-GCM |
| ⛔ | RC4 | accuracy-benchmark.mjs:26 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | TLS<1.2 / SSL | accuracy-benchmark.mjs:27 | REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred) |
| ⛔ | JWT alg=none | accuracy-benchmark.mjs:29 | CRITICAL — unsigned JWT; never accept alg:none |
| ⛔ | MD5 (OID) | accuracy-benchmark.mjs:50 | MD5 by OID — REMOVE (collision-broken) |
| ⛔ | MD5 | assurance-properties.mjs:31 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | RC4 | assurance-properties.mjs:31 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | 3DES/DES | assurance-properties.mjs:31 | REMOVE; use AES-256-GCM |
| ⛔ | TLS<1.2 / SSL | assurance-properties.mjs:31 | REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred) |
| ⛔ | MD5 | cbom.cdx.json:27 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | SHA-1 | cbom.cdx.json:52 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | 3DES/DES | cbom.cdx.json:77 | REMOVE; use AES-256-GCM |
| ⛔ | RC4 | cbom.cdx.json:102 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | JWT alg=none | cbom.cdx.json:152 | CRITICAL — unsigned JWT; never accept alg:none |
| ⛔ | SIKE/SIDH (BROKEN PQ) | cbom.cdx.json:202 | BROKEN — Castryck-Decru 2022 classical poly-time key recovery; do NOT use; migrate to ML-KEM-1024 |
| ⛔ | Blowfish/CAST5 | cbom.cdx.json:227 | legacy 64-bit-block cipher (Sweet32) — REMOVE; use AES-256-GCM |
| ⛔ | GeMSS (BROKEN PQ) | cbom.cdx.json:252 | BROKEN multivariate scheme; do NOT use; migrate to ML-DSA-87 / SLH-DSA |
| ⛔ | MD4/MD2 | cbom.cdx.json:277 | REMOVE — badly broken hash; use SHA-512 / SHA3-512 |
| ⛔ | NTLM/WEP (legacy) | cbom.cdx.json:302 | legacy auth/wireless built on MD4/DES/RC4 — broken; REMOVE |
| ⛔ | PBKDF1 (weak KDF) | cbom.cdx.json:327 | PBKDF1 — deprecated/weak KDF; use PBKDF2/scrypt/Argon2 with SHA-256+ |
| ⛔ | GOST cipher/hash (legacy) | cbom.cdx.json:367 | GOST 28147/Magma (64-bit) / Kuznyechik / Streebog — non-NIST legacy; migrate to AES-256 / SHA-512 + PQC |
| ⛔ | MD5 | examples\demo\demo-out\cbom.cdx.json:27 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | 3DES/DES | examples\demo\demo-out\cbom.cdx.json:52 | REMOVE; use AES-256-GCM |
| ⛔ | MD5 | examples\demo\demo-out\evidence-pack.signed.json:40 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | 3DES/DES | examples\demo\demo-out\evidence-pack.signed.json:55 | REMOVE; use AES-256-GCM |
| ⛔ | SHA-1 | examples\demo\demo-out\evidence-pack.signed.json:907 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | RC4 | examples\demo\demo-out\evidence-pack.signed.json:907 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | SIKE/SIDH (BROKEN PQ) | examples\demo\demo-out\evidence-pack.signed.json:907 | BROKEN — Castryck-Decru 2022 classical poly-time key recovery; do NOT use; migrate to ML-KEM-1024 |
| ⛔ | Blowfish/CAST5 | examples\demo\demo-out\evidence-pack.signed.json:907 | legacy 64-bit-block cipher (Sweet32) — REMOVE; use AES-256-GCM |
| ⛔ | MD5 | examples\demo\run-demo.mjs:79 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | TLS<1.2 / SSL | examples\demo\run-demo.mjs:79 | REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred) |
| ⛔ | MD5 | examples\demo\sample-repo\auth\legacy.js:6 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | 3DES/DES | examples\demo\sample-repo\pq\handshake.mjs:2 | REMOVE; use AES-256-GCM |
| ⛔ | TLS<1.2 / SSL | examples\demo\sample-repo\tls\nginx.conf:4 | REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred) |
| ⛔ | MD5 | gen-sample-pack.mjs:17 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | TLS<1.2 / SSL | gen-sample-pack.mjs:18 | REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred) |
| ⛔ | 3DES/DES | gen-sample-pack.mjs:23 | REMOVE; use AES-256-GCM |
| ⛔ | MD5 | pqcbom-action\examples\vulnerable\app.js:2 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | SIKE/SIDH (BROKEN PQ) | pqcbom-action\pqcbom.mjs:17 | BROKEN — Castryck-Decru 2022 classical poly-time key recovery; do NOT use; migrate to ML-KEM-1024 |
| ⛔ | GeMSS (BROKEN PQ) | pqcbom-action\pqcbom.mjs:17 | BROKEN multivariate scheme; do NOT use; migrate to ML-DSA-87 / SLH-DSA |
| ⛔ | Blowfish/CAST5 | pqcbom-action\pqcbom.mjs:19 | legacy 64-bit-block cipher (Sweet32) — REMOVE; use AES-256-GCM |
| ⛔ | MD4/MD2 | pqcbom-action\pqcbom.mjs:19 | REMOVE — badly broken hash; use SHA-512 / SHA3-512 |
| ⛔ | NTLM/WEP (legacy) | pqcbom-action\pqcbom.mjs:19 | legacy auth/wireless built on MD4/DES/RC4 — broken; REMOVE |
| ⛔ | MD5 | pqcbom-action\pqcbom.mjs:21 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | SHA-1 | pqcbom-action\pqcbom.mjs:21 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | RC4 | pqcbom-action\pqcbom.mjs:27 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | 3DES/DES | pqcbom-action\pqcbom.mjs:27 | REMOVE; use AES-256-GCM |
| ⛔ | JWT alg=none | pqcbom-action\pqcbom.mjs:30 | CRITICAL — unsigned JWT; never accept alg:none |
| ⛔ | PBKDF1 (weak KDF) | pqcbom-action\pqcbom.mjs:37 | PBKDF1 — deprecated/weak KDF; use PBKDF2/scrypt/Argon2 with SHA-256+ |
| ⛔ | GOST cipher/hash (legacy) | pqcbom-action\pqcbom.mjs:38 | GOST 28147/Magma (64-bit) / Kuznyechik / Streebog — non-NIST legacy; migrate to AES-256 / SHA-512 + PQC |
| ⛔ | RC2 | pqcbom-action\pqcbom.mjs:115 | REMOVE — 64-bit legacy cipher; use AES-256-GCM |
| ⛔ | TLS<1.2 / SSL | pqcbom-action\pqcbom.mjs:120 | REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred) |
| ⛔ | MD5 (OID) | pqcbom-action\pqcbom.mjs:532 | MD5 by OID — REMOVE (collision-broken) |
| ⛔ | Skipjack (broken cipher) | pqcbom-action\pqcbom.mjs:569 | Skipjack — 80-bit NSA-era cipher, below modern security; REMOVE; use AES-256-GCM |
| ⛔ | IDEA (legacy cipher) | pqcbom-action\pqcbom.mjs:577 | IDEA — 64-bit-block legacy cipher (Sweet32 class); REMOVE; use AES-256-GCM |
| ⛔ | MD5 | pqcbom-action\run.mjs:11 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | MD5 | pqcbom-plan.mjs:19 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | SHA-1 | pqcbom-plan.mjs:19 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | RC4 | pqcbom-plan.mjs:19 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | 3DES/DES | pqcbom-plan.mjs:19 | REMOVE; use AES-256-GCM |
| ⛔ | SIKE/SIDH (BROKEN PQ) | pqcbom-plan.mjs:19 | BROKEN — Castryck-Decru 2022 classical poly-time key recovery; do NOT use; migrate to ML-KEM-1024 |
| ⛔ | Blowfish/CAST5 | pqcbom-plan.mjs:19 | legacy 64-bit-block cipher (Sweet32) — REMOVE; use AES-256-GCM |
| ⛔ | MD5 | pqcbom-report.mjs:171 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | MD5 | pqcbom-server.mjs:77 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | SIKE/SIDH (BROKEN PQ) | pqcbom.mjs:17 | BROKEN — Castryck-Decru 2022 classical poly-time key recovery; do NOT use; migrate to ML-KEM-1024 |
| ⛔ | GeMSS (BROKEN PQ) | pqcbom.mjs:17 | BROKEN multivariate scheme; do NOT use; migrate to ML-DSA-87 / SLH-DSA |
| ⛔ | Blowfish/CAST5 | pqcbom.mjs:19 | legacy 64-bit-block cipher (Sweet32) — REMOVE; use AES-256-GCM |
| ⛔ | MD4/MD2 | pqcbom.mjs:19 | REMOVE — badly broken hash; use SHA-512 / SHA3-512 |
| ⛔ | NTLM/WEP (legacy) | pqcbom.mjs:19 | legacy auth/wireless built on MD4/DES/RC4 — broken; REMOVE |
| ⛔ | MD5 | pqcbom.mjs:21 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | SHA-1 | pqcbom.mjs:21 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | RC4 | pqcbom.mjs:27 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | 3DES/DES | pqcbom.mjs:27 | REMOVE; use AES-256-GCM |
| ⛔ | JWT alg=none | pqcbom.mjs:30 | CRITICAL — unsigned JWT; never accept alg:none |
| ⛔ | PBKDF1 (weak KDF) | pqcbom.mjs:37 | PBKDF1 — deprecated/weak KDF; use PBKDF2/scrypt/Argon2 with SHA-256+ |
| ⛔ | GOST cipher/hash (legacy) | pqcbom.mjs:38 | GOST 28147/Magma (64-bit) / Kuznyechik / Streebog — non-NIST legacy; migrate to AES-256 / SHA-512 + PQC |
| ⛔ | RC2 | pqcbom.mjs:115 | REMOVE — 64-bit legacy cipher; use AES-256-GCM |
| ⛔ | TLS<1.2 / SSL | pqcbom.mjs:120 | REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred) |
| ⛔ | MD5 (OID) | pqcbom.mjs:532 | MD5 by OID — REMOVE (collision-broken) |
| ⛔ | Skipjack (broken cipher) | pqcbom.mjs:569 | Skipjack — 80-bit NSA-era cipher, below modern security; REMOVE; use AES-256-GCM |
| ⛔ | IDEA (legacy cipher) | pqcbom.mjs:577 | IDEA — 64-bit-block legacy cipher (Sweet32 class); REMOVE; use AES-256-GCM |
| ⛔ | MD5 | pqcompliance.mjs:34 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | SHA-1 | pqcompliance.mjs:34 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | RC4 | pqcompliance.mjs:34 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | 3DES/DES | pqcompliance.mjs:34 | REMOVE; use AES-256-GCM |
| ⛔ | MD5 | pqevidence-cli.mjs:98 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | TLS<1.2 / SSL | pqposture.mjs:58 | REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred) |
| ⛔ | MD5 | pqshield.mjs:54 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | RC4 | pqshield.mjs:54 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | 3DES/DES | pqshield.mjs:54 | REMOVE; use AES-256-GCM |
| ⛔ | SHA-1 | pqshield.mjs:168 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | MD5 | pqverify-api.mjs:116 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | 3DES/DES | sandbox-parity.mjs:24 | REMOVE; use AES-256-GCM |
| ⛔ | MD5 | tamper-binding.mjs:148 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | 3DES/DES | test-fixtures\structural-corpus.json:4 | REMOVE; use AES-256-GCM |
| ⛔ | SHA-1 | test-fixtures\structural-corpus.json:19 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |
| ⛔ | RC4 | test-fixtures\structural-corpus.json:34 | REMOVE; use AES-256-GCM / ChaCha20-Poly1305 |
| ⛔ | MD5 | test-fixtures\structural-corpus.json:49 | REMOVE — collision-broken; use SHA-512 / SHA3-512 |

_Generated by TRELYAN pqcbom (reference). Lexical scan — verify findings; production adds AST + cloud/cert/KMS discovery._