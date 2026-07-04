/*!
 * pqcbom — Cryptographic Bill of Materials scanner + quantum-readiness grader (reference, DRAFT, standalone).
 *
 * THE revenue + viral product (unanimous council): scan code/config for cryptography, classify quantum risk,
 * emit a CycloneDX-style CBOM + an A–F "Post-Quantum Readiness Scorecard". Free tier = the shareable badge (viral funnel,
 * SSL-Labs/HIBP model); paid tier = full CBOM + migration roadmap + auditor evidence (CNSA 2.0 / NIS2 / CRA / DORA).
 *
 * It is the on-ramp to the whole TRELYAN suite: scan -> find quantum-vulnerable crypto -> migrate to our PQC
 * SDK (ML-KEM/ML-DSA/SLH-DSA) -> sign + attest the migration evidence (pqsign/pqef/pqcouncil).
 *
 * v0.2: TWO detection layers — (1) inline pattern matching over code/config (algorithms, TLS/SSL versions, JWT/JOSE
 * algs, SSH key types, managed KMS/HSM), and (2) a higher-signal DEPENDENCY-MANIFEST layer that reads declared crypto
 * libraries from package.json / requirements / go.mod / Cargo / pom / Gemfile / .csproj (a declared dep ⇒ real usage,
 * far lower false-positive than a bare string). HONEST LIMITS (still true): no full AST/data-flow, no live TLS/cert
 * handshake probing, no runtime/binary/firmware or cloud-KMS-API discovery — findings are leads to verify, not a
 * guaranteed-complete inventory. "quantum-broken" = broken by Shor (RSA/ECC/DH); classical curves (X25519/Ed25519) are
 * flagged but OK as the CLASSICAL leg of a HYBRID. v0.3 ADDS: BROKEN PQ candidates (SIKE/SIDH, GeMSS — a project using
 * these has a FALSE sense of PQ security), stateful hash sigs (XMSS, NIST SP 800-208), more broken/legacy primitives
 * (Blowfish/CAST5, MD4/MD2, RIPEMD, 192-bit/binary-field EC curves, NTLM/WEP), and more libraries (wolfSSL/mbedTLS/
 * BoringSSL, CIRCL, PyNaCl, JWT/JOSE). v0.4 ADDS: cryptographic OID detection (RSA/ECDSA/DSA/EC-curve/Ed25519/X25519/
 * MD5/SHA-1 by standardized numeric OID — closes the published "OID" blind spot; certs/ASN.1/PKI configs name crypto by
 * OID, not by algorithm name). v0.5 ADDS: ENCODED-BLOB detection — decodes base64/PEM key+cert blobs and identifies the
 * algorithm by its DER OID (closes the "encoded-blob" blind spot; FP-safe — only a DER-anchored crypto OID counts).
 * v0.6 ADDS: standard fused ASN.1 algorithm identifiers (rsaEncryption/ecPublicKey/sha256WithRSA/ecdsa-with-sha* —
 * closes the "substring" blind spot for known names; bare "rsa"/"ec" in arbitrary words still don't trip).
 * v0.7 ADDS: a COMPOUND / glued-identifier layer driven by a cross-ecosystem corpus (node/java/python/go/config/dotnet/
 * php-ruby, test-fixtures/structural-corpus.json) — compound cipher-suite constants (RC4_128, TLS_ECDHE_RSA_WITH_3DES),
 * OpenSSL/JCA transform strings (des-ede3-cbc, DESede, PBEWithMD5AndDES), .NET provider classes (*CryptoServiceProvider/
 * *Managed), library spellings (ARCFOUR, DES3, nistP256, elliptic.P224), OpenSSL verbs (gendsa/dsaparam), JWT
 * algorithm:'none', PHP openssl_public/private_*, and DES-by-OID. Each is a SPECIFIC compound token (not a bare algo
 * word) so the FP guards stand; coverage 57/60 = 95% of statically-detectable corpus cases (the residual 3 need
 * constant-folding/data-flow — runtime string-concat + cross-line key-size binding — and stay honest blind spots,
 * alongside the 12 runtime/config-selected cases). Coverage harness: node structural-corpus.mjs.
 * v0.8 ADDS (adversarial red-team round): FP fixes (the surname "Gendsa", a "DESeded" build flavour, "none-cache", and
 * TLS_*_RSA_* filenames no longer mis-fire — suite rules now require WITH) + FN coverage — underscore/abbrev spellings
 * (des_ede3_cbc, MCRYPT_3DES, TDES, aes_128_ctr, arcfour128, MD-5, HmacSHA1, RSA512, md5WithRSAEncryption), weak
 * sizes/KDFs (RSA-512/768, openssl genrsa/dhparam, PBKDF1, SHA-224, secp160r1), and regional/legacy families (GOST /
 * Magma / Kuznyechik / Streebog, SM2 / SM4, SEED, Skipjack, IDEA, RC2 — all CONTEXT-ANCHORED so common words stay safe).
 * Self-test: node pqcbom.mjs
 */
const RULES = [
  // classically broken (a bug regardless of quantum)
  { re: /\bMD5\b/i, algo: 'MD5', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' },
  { re: /\bSHA-?1\b/i, algo: 'SHA-1', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' },
  { re: /\bRC4\b/i, algo: 'RC4', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM / ChaCha20-Poly1305' },
  { re: /\b(3DES|Triple-?DES|DESede(?!d)|DES-(EDE3?|CBC|ECB|OFB|CFB)|DES(?![\w-]))/i, algo: '3DES/DES', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM' }, // bare DES + DESede + DES modes; DES(?![\w-]) so "DES-less"/"description" are NOT matched; DESede(?!d) so the "DESeded" build flavour is NOT matched (adversary FP) while DESedeKeySpec still is
  // quantum-broken (Shor): public-key
  { re: /\bRSA(SSA|ES)?\b|RSA-?(512|768|1024|2048|3072|4096)|RSA_(public|private)_(en|de)crypt|RSA_PKCS1|PKCS#?1\b/i, algo: 'RSA', family: 'pubkey', risk: 'quantum-broken', rec: 'migrate KEM->ML-KEM-1024, sig->ML-DSA-87 (hybrid during transition)' }, // PKCS#?1\b so PKCS#11 (HSM) is NOT matched; +512/768 weak sizes + RSA_public/private_encrypt + RSA_PKCS1 underscore forms (adversary FN)
  { re: /(?<![\w-])DSA(?![\w-])(?!\s+\()/i, algo: 'DSA', family: 'signature', risk: 'quantum-broken', rec: 'migrate to ML-DSA-87 / SLH-DSA' }, // not preceded/followed by word-char or '-' so ML-DSA/SLH-DSA/ECDSA are NOT matched; (?!\s+\() so an acronym being DEFINED — "DSA (Digital Services Act)" / "DSA (Democratic..." — is NOT matched (adversary FP; DORA/NIS2 audience), while a call "DSA(key)" (no space) and prose "DSA signing" still are
  { re: /\bECDSA\b/i, algo: 'ECDSA', family: 'signature', risk: 'quantum-broken', rec: 'migrate to ML-DSA-87 (keep ECDSA only as a HYBRID leg)' },
  { re: /\bECDHE?\b|\bECIES\b/i, algo: 'ECDH', family: 'kem', risk: 'quantum-broken', rec: 'migrate to ML-KEM-1024 (+ X25519 in HYBRID)' }, // +ECDHE (council)
  { re: /\b(secp(224|256|384|521)(r1|k1)|prime256v1|P-(224|256|384|521)|brainpool)\b/i, algo: 'EC curve', family: 'pubkey', risk: 'quantum-broken', rec: 'EC curve is Shor-broken; move to ML-KEM/ML-DSA (hybrid)' }, // +secp384r1/521r1/224r1, P-224 (council)
  { re: /\b(Diffie-?Hellman|DHE|DH-(group|modp))\b/i, algo: 'finite-field DH', family: 'kem', risk: 'quantum-broken', rec: 'migrate to ML-KEM-1024' }, // +DHE ephemeral (council)
  // classical curves — quantum-broken alone, but valid as the CLASSICAL leg of a hybrid
  { re: /\b(X25519|X448|Curve25519)\b/i, algo: 'X25519/X448', family: 'kem', risk: 'classical-hybrid-ok', rec: 'OK only inside a HYBRID with ML-KEM-768/1024' },
  { re: /\b(Ed25519|Ed448)\b/i, algo: 'Ed25519/Ed448', family: 'signature', risk: 'classical-hybrid-ok', rec: 'OK only inside a HYBRID with ML-DSA-87' },
  // quantum-weakened (Grover halves the security level)
  { re: /\bAES-?(128|192)\b/i, algo: 'AES-128/192', family: 'cipher', risk: 'quantum-weakened', rec: 'use AES-256 (Grover halves the key strength)' },
  { re: /\bSHA-?256\b|\bSHA3-?256\b/i, algo: 'SHA-256', family: 'hash', risk: 'quantum-weakened', rec: 'SHA-256 collision resistance drops to ~2^85 under quantum attack (BHT); use SHA-384/512 for >=128-bit quantum collision resistance' }, // SHA-384 split out to quantum-resistant (Gemini/CNSA-2.0 correction): SHA-256 is the borderline case, SHA-384 is not
  // quantum-safe
  { re: /\bSHA-?384\b|\bSHA3-?384\b|\bSHA-?384(CryptoServiceProvider|Managed)\b/i, algo: 'SHA-384', family: 'hash', risk: 'quantum-safe', rec: 'OK — SHA-384 retains ~2^128 quantum collision resistance (CNSA 2.0-approved for the PQ era)' },
  { re: /\b(ML-KEM|ml_kem|Kyber|HQC|BIKE)\b/i, algo: 'ML-KEM/Kyber', family: 'kem', risk: 'quantum-safe', rec: 'OK — NIST FIPS 203' },
  { re: /\b(ML-DSA|ml_dsa|Dilithium)\b/i, algo: 'ML-DSA/Dilithium', family: 'signature', risk: 'quantum-safe', rec: 'OK — NIST FIPS 204' },
  { re: /\b(SLH-DSA|slh_dsa|SPHINCS)\b/i, algo: 'SLH-DSA/SPHINCS+', family: 'signature', risk: 'quantum-safe', rec: 'OK — NIST FIPS 205' },
  { re: /\b(Falcon|FN-DSA)\b/i, algo: 'Falcon/FN-DSA', family: 'signature', risk: 'quantum-safe', rec: 'OK — FIPS 206 in development (diversity/on-chain leg)' },
  { re: /\bAES-?256\b/i, algo: 'AES-256', family: 'cipher', risk: 'quantum-safe', rec: 'OK — 256-bit (128-bit quantum)' },
  { re: /\b(SHA-?512|SHA3-?512|SHAKE-?256)\b/i, algo: 'SHA-512/SHA3-512', family: 'hash', risk: 'quantum-safe', rec: 'OK' },
  { re: /\bChaCha20(-?Poly1305)?\b/i, algo: 'ChaCha20-Poly1305', family: 'cipher', risk: 'quantum-safe', rec: 'OK — 256-bit stream AEAD' },
  // --- v0.2 expanded coverage: protocols, JWT/JOSE, SSH, managed crypto, more PQ KEMs ---
  { re: /\b(SSLv?[23]|TLSv?-?1\.[01]|TLSv?1(?![.\d]))/i, algo: 'TLS<1.2 / SSL', family: 'protocol', risk: 'broken-classical', rec: 'REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred)' }, // TLSv?1(?![.\d]) so TLS 1.2/1.3 do NOT false-positive (council: both seats)
  { re: /\balg["'\s:=]{1,4}none(?![\w-])/i, algo: 'JWT alg=none', family: 'token', risk: 'broken-classical', rec: 'CRITICAL — unsigned JWT; never accept alg:none' }, // none(?![\w-]) so "none-cache" / "none-suffix" prose does NOT fire (adversary FP)
  { re: /\b(RS256|RS384|RS512|PS256|PS384|PS512)\b/, algo: 'JWT RSA (RS/PS)', family: 'signature', risk: 'quantum-broken', rec: 'RSA-signed JWT — plan ML-DSA-87 (hybrid)' },
  { re: /\b(ES256K?|ES384|ES512)\b/, algo: 'JWT ECDSA (ES)', family: 'signature', risk: 'quantum-broken', rec: 'ECDSA-signed JWT — plan ML-DSA-87 (hybrid)' },
  { re: /\bssh-rsa\b|\bssh-dss\b|\becdsa-sha2-/i, algo: 'SSH RSA/DSA/ECDSA key', family: 'signature', risk: 'quantum-broken', rec: 'SSH key Shor-broken; add sntrup761x25519 KEX + plan PQ' }, // +ssh-dss (council)
  { re: /\bssh-ed25519\b/i, algo: 'SSH Ed25519 key', family: 'signature', risk: 'classical-hybrid-ok', rec: 'OK as the classical leg; pair with PQ KEX (sntrup761x25519)' },
  { re: /\bsntrup761(x25519)?\b/i, algo: 'sntrup761 (SSH PQ KEX)', family: 'kem', risk: 'quantum-safe', rec: 'OK — PQ-hybrid SSH key exchange' },
  { re: /\b(AWS[-\s]?KMS|Azure[-\s]?Key[-\s]?Vault|(GCP|Google[-\s]?Cloud)[-\s]?KMS|CloudHSM|PKCS#?11|\bHSM\b)\b/i, algo: 'managed KMS/HSM', family: 'keymgmt', risk: 'classical-hybrid-ok', rec: 'managed crypto — verify the provider PQ roadmap + key-type support' },
  { re: /\b(Classic[-\s]?McEliece|FrodoKEM|NTRU(-?HPS|-?HRSS)?|NTRU[-\s]?Prime)\b/i, algo: 'Classic McEliece / Frodo / NTRU', family: 'kem', risk: 'quantum-safe', rec: 'OK — PQ KEM (NIST round/alternate)' },
  // --- v0.3: PQ candidates BROKEN during/after the NIST process — using these is a FALSE sense of PQ security (unique flag) ---
  { re: /\b(SIKE|SIDH)\b/, algo: 'SIKE/SIDH (BROKEN PQ)', family: 'kem', risk: 'broken-classical', rec: 'BROKEN — Castryck-Decru 2022 classical poly-time key recovery; do NOT use; migrate to ML-KEM-1024' }, // case-sensitive: avoid "sike"/"sidh" noise
  { re: /\bGeMSS\b/, algo: 'GeMSS (BROKEN PQ)', family: 'signature', risk: 'broken-classical', rec: 'BROKEN multivariate scheme; do NOT use; migrate to ML-DSA-87 / SLH-DSA' },
  // stateful hash-based signatures — quantum-safe (NIST SP 800-208) but one-time-state reuse is catastrophic
  { re: /\bXMSS(MT)?\b/, algo: 'XMSS (stateful hash sig)', family: 'signature', risk: 'quantum-safe', rec: 'OK — stateful hash-based sig (NIST SP 800-208); NEVER reuse one-time key state' }, // LMS/HSS dropped (Learning-Mgmt-System / telecom false positives)
  // --- v0.3: more classically broken / weak primitives ---
  { re: /\b(Blowfish|CAST-?5|CAST-?128)\b/i, algo: 'Blowfish/CAST5', family: 'cipher', risk: 'broken-classical', rec: 'legacy 64-bit-block cipher (Sweet32) — REMOVE; use AES-256-GCM' }, // IDEA/RC2 dropped ("idea" word / "rc2" release-candidate false positives)
  { re: /\b(MD4|MD2)\b/i, algo: 'MD4/MD2', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — badly broken hash; use SHA-512 / SHA3-512' },
  { re: /\bRIPEMD(-?(128|160|256|320))?\b/i, algo: 'RIPEMD', family: 'hash', risk: 'quantum-weakened', rec: 'legacy hash; prefer SHA-512 / SHA3-512' },
  { re: /\b(secp192(r1|k1)|prime192v1|P-192|sect(163|233|283|409|571)(k1|r1)?)\b/i, algo: 'EC curve (legacy)', family: 'pubkey', risk: 'quantum-broken', rec: 'Shor-broken legacy/binary-field EC curve; move to ML-KEM/ML-DSA (hybrid)' }, // 192-bit + binary-field curves (line above covers 224/256/384/521)
  { re: /\b(NTLMv?[12]?|WEP)\b/, algo: 'NTLM/WEP (legacy)', family: 'protocol', risk: 'broken-classical', rec: 'legacy auth/wireless built on MD4/DES/RC4 — broken; REMOVE' }, // case-sensitive (avoid lowercase noise)
  // --- v0.4: cryptographic OID detection (closes the published "OID" blind spot) — certs/ASN.1/PKI configs name crypto by
  //     numeric OID, not algorithm name. OIDs are unambiguous dotted-decimal tokens (no false-positive surface). Standardized
  //     values (RFC 3279/5480/8410, NIST). The lookbehind/lookahead anchor an EXACT OID (not a prefix/suffix of a longer one).
  { re: /(?<![\d.])1\.2\.840\.113549\.1\.1\.1(?![\d.])/, algo: 'RSA (OID rsaEncryption)', family: 'pubkey', risk: 'quantum-broken', rec: 'RSA key by OID — migrate KEM->ML-KEM-1024, sig->ML-DSA-87 (hybrid)' },
  { re: /(?<![\d.])1\.2\.840\.113549\.1\.1\.11(?![\d.])/, algo: 'RSA-SHA256 sig (OID)', family: 'signature', risk: 'quantum-broken', rec: 'sha256WithRSA cert/sig by OID — RSA is Shor-broken; plan ML-DSA-87' },
  { re: /(?<![\d.])1\.2\.840\.10045\.2\.1(?![\d.])/, algo: 'EC public key (OID)', family: 'pubkey', risk: 'quantum-broken', rec: 'EC public key by OID — Shor-broken; migrate to ML-KEM/ML-DSA' },
  { re: /(?<![\d.])1\.2\.840\.10045\.4\.3\.[234](?![\d.])/, algo: 'ECDSA sig (OID)', family: 'signature', risk: 'quantum-broken', rec: 'ECDSA-with-SHA2 by OID — migrate to ML-DSA-87 (keep ECDSA only as a hybrid leg)' },
  { re: /(?<![\d.])1\.2\.840\.10040\.4\.1(?![\d.])/, algo: 'DSA (OID)', family: 'signature', risk: 'quantum-broken', rec: 'DSA by OID — migrate to ML-DSA-87 / SLH-DSA' },
  { re: /(?<![\d.])1\.2\.840\.10045\.3\.1\.7(?![\d.])/, algo: 'P-256/prime256v1 curve (OID)', family: 'pubkey', risk: 'quantum-broken', rec: 'P-256 by OID — Shor-broken EC curve' },
  { re: /(?<![\d.])1\.3\.132\.0\.3[45](?![\d.])/, algo: 'P-384/P-521 curve (OID)', family: 'pubkey', risk: 'quantum-broken', rec: 'P-384/P-521 by OID — Shor-broken EC curve' },
  { re: /(?<![\d.])1\.3\.101\.11[23](?![\d.])/, algo: 'Ed25519/Ed448 (OID)', family: 'signature', risk: 'classical-hybrid-ok', rec: 'EdDSA by OID — OK only as the classical leg of a HYBRID with ML-DSA-87' },
  { re: /(?<![\d.])1\.3\.101\.11[01](?![\d.])/, algo: 'X25519/X448 (OID)', family: 'kem', risk: 'classical-hybrid-ok', rec: 'X25519/X448 by OID — OK only inside a HYBRID with ML-KEM' },
  { re: /(?<![\d.])1\.2\.840\.113549\.2\.5(?![\d.])/, algo: 'MD5 (OID)', family: 'hash', risk: 'broken-classical', rec: 'MD5 by OID — REMOVE (collision-broken)' },
  { re: /(?<![\d.])1\.3\.14\.3\.2\.26(?![\d.])/, algo: 'SHA-1 (OID)', family: 'hash', risk: 'broken-classical', rec: 'SHA-1 by OID — REMOVE (collision-broken)' },
  // --- v0.6: STANDARD fused ASN.1/OID-friendly algorithm identifiers (closes the "substring" blind spot for KNOWN names —
  //     these are specific compound tokens, NOT bare "rsa"/"ec" in arbitrary words, so the word-boundary FP guards stand) ---
  { re: /\b(rsaEncryption|ecPublicKey|ecdsa[-_]?with[-_]?sha\d+|(sha-?\d{1,3}|md[245])with(rsa|ecdsa|dsa)\w*)/i, algo: 'RSA/EC ASN.1 identifier (fused)', family: 'pubkey', risk: 'quantum-broken', rec: 'standard ASN.1 algorithm name (fused token) — RSA/EC is Shor-broken; migrate to ML-KEM/ML-DSA' }, // v0.7: \d{2,3}->{1,3} so SHA1withRSA's RSA leg is caught; v0.8: +md[245]with for md5WithRSAEncryption
  { re: /(?<![\d.])1\.3\.14\.3\.2\.7(?![\d.])/, algo: '3DES/DES', family: 'cipher', risk: 'broken-classical', rec: 'DES-CBC by OID (1.3.14.3.2.7) — REMOVE; use AES-256-GCM' }, // v0.7: DES by OID (.NET CryptoConfig.CreateFromName)
  { re: /(?<![\d.])1\.2\.840\.113549\.1\.1\.5(?![\d.])/, algo: 'RSA-SHA1 sig (OID)', family: 'signature', risk: 'quantum-broken', rec: 'sha1WithRSAEncryption by OID — RSA Shor-broken + SHA-1 collision-broken; plan ML-DSA-87' }, // v0.7
  // --- v0.7: COMPOUND / glued algorithm identifiers (corpus-driven, test-fixtures/structural-corpus.json). Real code
  //     names crypto inside compound cipher-suite constants, OpenSSL/JCA transform strings, .NET provider classes, and
  //     library spellings the word-boundary rules above deliberately skip. Each pattern is a SPECIFIC compound token
  //     (NOT a bare algo word), so the FP guards stand. Same {algo} labels -> findings MERGE. Coverage: structural-corpus.mjs ---
  { re: /\bDES3\b/i, algo: '3DES/DES', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM' }, // pycryptodome Crypto.Cipher.DES3
  { re: /\b(ARCFOUR|ARC4)\b/i, algo: 'RC4', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM / ChaCha20-Poly1305' }, // SunJCE / pycryptodome RC4 alias
  { re: /\bRC4[-_]\d/i, algo: 'RC4', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM / ChaCha20-Poly1305' }, // TLS suite RC4_128
  { re: /\bRC2[-_/](CBC|ECB|CFB|OFB)\b|\bRC2CryptoServiceProvider\b|RC2\.(new|MODE)|\bMCRYPT_RC2\b|(Create|CreateFromName)\(\s*["']RC2["']/i, algo: 'RC2', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE — 64-bit legacy cipher; use AES-256-GCM' }, // crypto-context only (bare RC2 = release-candidate FP); +RC2.new/RC2.MODE (pycryptodome) + MCRYPT_RC2 (php)
  { re: /\bbf-(cbc|ecb|cfb|ofb)\b/i, algo: 'Blowfish/CAST5', family: 'cipher', risk: 'broken-classical', rec: 'legacy 64-bit-block cipher (Sweet32) — REMOVE; use AES-256-GCM' }, // OpenSSL Blowfish names
  { re: /\bsha-?1with/i, algo: 'SHA-1', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' }, // SHA1withRSA / SHA1WithRSA / sha1WithRSAEncryption (hash leg)
  { re: /\bopenssl\s+gendsa\b|\bgendsa\s+-|\bdsaparam\b/i, algo: 'DSA', family: 'signature', risk: 'quantum-broken', rec: 'migrate to ML-DSA-87 / SLH-DSA' }, // OpenSSL DSA subcommands; gendsa requires command context so the surname "Gendsa" is NOT matched (adversary FP)
  { re: /\bnistp(192|224|256|384|521)\b|\.P(192|224|256|384|521)\(/i, algo: 'EC curve', family: 'pubkey', risk: 'quantum-broken', rec: 'EC curve is Shor-broken; move to ML-KEM/ML-DSA (hybrid)' }, // nistP256 (.NET), elliptic.P224() (Go)
  { re: /\bVersionTLS1[01]\b/i, algo: 'TLS<1.2 / SSL', family: 'protocol', risk: 'broken-classical', rec: 'REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred)' }, // Go tls.VersionTLS10/11
  // .NET provider classes (algorithm fused into the class name; bare-token \b guards miss the glued suffix)
  { re: /\bMD5(CryptoServiceProvider|Managed)\b/i, algo: 'MD5', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' },
  { re: /\bSHA-?1(CryptoServiceProvider|Managed)\b/i, algo: 'SHA-1', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' },
  { re: /\bSHA-?256(CryptoServiceProvider|Managed)\b/i, algo: 'SHA-256', family: 'hash', risk: 'quantum-weakened', rec: 'SHA-256 collision resistance drops to ~2^85 under quantum attack (BHT); use SHA-384/512' },
  { re: /\b(RSACryptoServiceProvider|RSACng|GetRSA(Private|Public)Key)\b/i, algo: 'RSA', family: 'pubkey', risk: 'quantum-broken', rec: 'migrate KEM->ML-KEM-1024, sig->ML-DSA-87 (hybrid during transition)' },
  { re: /\bDSA(CryptoServiceProvider|Cng)\b/i, algo: 'DSA', family: 'signature', risk: 'quantum-broken', rec: 'migrate to ML-DSA-87 / SLH-DSA' },
  { re: /\bDESCryptoServiceProvider\b/i, algo: '3DES/DES', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM' }, // TripleDESCryptoServiceProvider already caught by the Triple-?DES rule
  // TLS cipher-suite CONSTANT identifiers (Go/Java) — underscore-joined, so \b-bounded rules miss the inner algo tokens
  // require WITH (the TLS-1.2 cipher-suite shape) so benign filenames/identifiers like TLS_DRAFT_RSA_NOTES do NOT fire (adversary FP)
  { re: /\bTLS_[A-Z0-9_]*WITH[A-Z0-9_]*RC4[A-Z0-9_]*\b/, algo: 'RC4', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM / ChaCha20-Poly1305' },
  { re: /\bTLS_[A-Z0-9_]*WITH[A-Z0-9_]*(3DES|DES_EDE|DES40|DES_CBC)[A-Z0-9_]*\b/, algo: '3DES/DES', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM' },
  { re: /\bTLS_[A-Z0-9_]*RSA[A-Z0-9_]*WITH[A-Z0-9_]*\b/, algo: 'RSA', family: 'pubkey', risk: 'quantum-broken', rec: 'RSA in a TLS cipher-suite — Shor-broken; plan ML-KEM/ML-DSA (hybrid)' },
  { re: /\bTLS_ECDHE?_[A-Z0-9_]*WITH[A-Z0-9_]*\b/, algo: 'ECDH', family: 'kem', risk: 'quantum-broken', rec: 'ECDHE in a TLS cipher-suite — Shor-broken; migrate to ML-KEM-1024 (+ X25519 hybrid)' },
  { re: /\balgorithm\s*[:=]\s*["']none["']/i, algo: 'JWT alg=none', family: 'token', risk: 'broken-classical', rec: 'CRITICAL — unsigned JWT; never accept alg:none' }, // \b before 'algorithm' excludes compression_algorithm etc.
  { re: /\bPBE[-_]?With\w*MD5/i, algo: 'MD5', family: 'hash', risk: 'broken-classical', rec: 'PBEWithMD5* (PBKDF1/MD5) — REMOVE; use PBKDF2/scrypt/Argon2 with SHA-256+' }, // JCA PBE name
  { re: /\bPBE[-_]?With\w*DES\b/i, algo: '3DES/DES', family: 'cipher', risk: 'broken-classical', rec: 'PBEWith*AndDES — DES-based PBE; REMOVE; use AES-256-GCM' }, // JCA PBE name
  { re: /\bopenssl_(public|private)_(encrypt|decrypt)\b/i, algo: 'RSA', family: 'pubkey', risk: 'quantum-broken', rec: 'PHP openssl_public/private_* is RSA — Shor-broken; migrate KEM->ML-KEM-1024, sig->ML-DSA-87 (hybrid)' },
  // --- v0.8: adversary-driven (red-team workflow) — underscore/abbrev spellings, weak sizes/KDFs, more legacy/regional
  //     families. Each is anchored (mode/context/specific token), verified against the FP corpus so guards stand. ---
  { re: /\b(TDES|MCRYPT_3DES|des[_]ede\d?)/i, algo: '3DES/DES', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM' }, // TDES abbrev, MCRYPT_3DES, des_ede underscore
  { re: /\bdes[_](cbc|ecb|cfb|ofb)\b|\bdes40\b/i, algo: '3DES/DES', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM' }, // des_cbc underscore + export DES40
  { re: /\baes[_](128|192)(?!\d)/i, algo: 'AES-128/192', family: 'cipher', risk: 'quantum-weakened', rec: 'use AES-256 (Grover halves the key strength)' }, // aes_128_ctr underscore (no trailing \b: '_ctr' would break it)
  { re: /\bARCFOUR\d*\b/i, algo: 'RC4', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM / ChaCha20-Poly1305' }, // arcfour128/arcfour256 (SSH)
  { re: /\bMD-5\b/i, algo: 'MD5', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' }, // hyphenated MD-5
  { re: /hmac[-_]?sha-?1\b/i, algo: 'SHA-1', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' }, // HmacSHA1 / PBKDF2WithHmacSHA1 (no leading \b: 'WithHmac' glues it)
  { re: /\bmd[245]with/i, algo: 'MD5', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' }, // md5WithRSAEncryption hash leg (RSA leg caught by the fused rule)
  { re: /\bRSA512\b|\bRSA-?(512|768)\b/i, algo: 'RSA', family: 'pubkey', risk: 'quantum-broken', rec: 'RSA — Shor-broken (and 512/768-bit is classically weak); migrate to ML-KEM-1024 / ML-DSA-87' }, // glued RSA512
  { re: /\bopenssl\s+genrsa\b|\bgenrsa\s+-/i, algo: 'RSA', family: 'pubkey', risk: 'quantum-broken', rec: 'openssl genrsa — RSA, Shor-broken; migrate to ML-KEM/ML-DSA (hybrid)' }, // keygen verb (command context)
  { re: /\bopenssl\s+dhparam\b|\bdhparam\s+-/i, algo: 'finite-field DH', family: 'kem', risk: 'quantum-broken', rec: 'openssl dhparam — finite-field DH (Logjam/Shor); migrate to ML-KEM-1024' },
  { re: /\bPBKDF1\b/i, algo: 'PBKDF1 (weak KDF)', family: 'keymgmt', risk: 'broken-classical', rec: 'PBKDF1 — deprecated/weak KDF; use PBKDF2/scrypt/Argon2 with SHA-256+' },
  { re: /\bSHA-?224\b|\bsha224\b/i, algo: 'SHA-224', family: 'hash', risk: 'quantum-weakened', rec: 'SHA-224 ~112-bit collision strength (sub-128); use SHA-512 / SHA3-512' },
  { re: /\bsecp(128|160)r1\b/i, algo: 'EC curve (legacy)', family: 'pubkey', risk: 'quantum-broken', rec: 'short/legacy EC curve — Shor-broken + classically weak; move to ML-KEM/ML-DSA' },
  { re: /\b(EC-?KCDSA|KCDSA)\b/i, algo: 'DSA', family: 'signature', risk: 'quantum-broken', rec: 'KCDSA — DSA-family, Shor-broken; migrate to ML-DSA-87' },
  { re: /\bECMQV\b/i, algo: 'ECDH', family: 'kem', risk: 'quantum-broken', rec: 'EC-MQV key agreement — Shor-broken; migrate to ML-KEM-1024 (+ X25519 hybrid)' },
  { re: /(?<![\d.])1\.3\.36\.3\.3\.2\.8\.1\.1\.\d+(?![\d.])/, algo: 'EC curve (brainpool OID)', family: 'pubkey', risk: 'quantum-broken', rec: 'brainpool curve by OID — Shor-broken EC' },
  // regional / national legacy families (anchored to crypto context to avoid common-word FP)
  { re: /\bGOST[-_ ]?(R[-_ ]?)?34[._]?1[01]\b|\bGOST[-_ ]?(3410|2012)(?!\d)/i, algo: 'GOST R 34.10/34.11 (legacy)', family: 'signature', risk: 'quantum-broken', rec: 'GOST R 34.10 (EC/DLP sig, Shor-broken) / 34.11 (Streebog) — non-NIST; migrate to ML-DSA-87 / SHA-512' }, // (?!\d) so gost2012_256 matches ('_' not a digit)
  { re: /\bGOST[-_ ]?(28147|89|3412)\b|\b(Kuznyechik|Streebog)\b|\bmagma[-_/.](cbc|ecb|cfb|ofb|ctr|gcm|cipher|new)|\b(cipher|algorithm|algo|gost)[-_/:= ]{1,3}magma\b/i, algo: 'GOST cipher/hash (legacy)', family: 'cipher', risk: 'broken-classical', rec: 'GOST 28147/Magma (64-bit) / Kuznyechik / Streebog — non-NIST legacy; migrate to AES-256 / SHA-512 + PQC' }, // "Magma" anchored to crypto context (SEPARATOR+mode/.new, or a cipher/gost keyword) so the very common project name — Meta Magma mobile core, Magma CAS, magma DB — is NOT flagged (adversary FP, grade-F impact); real magma-cbc / magma.NewCipher / gost magma still caught
  { re: /\bSM3?with[-_]?SM2\b|\bSM2[-_](sign|sig|with|enc|cipher)/i, algo: 'SM2 (GM EC)', family: 'signature', risk: 'quantum-broken', rec: 'SM2 — GM/T elliptic-curve, Shor-broken; migrate to ML-DSA-87' },
  { re: /\bSM4[-_/](CBC|ECB|GCM|CTR|OFB|CFB)\b/i, algo: 'SM4 (GM cipher)', family: 'cipher', risk: 'quantum-weakened', rec: 'SM4 — 128-bit GM block cipher; Grover-weakened; prefer AES-256-GCM' },
  { re: /\bSEED[-/](CBC|ECB|CFB|OFB|GCM)\b/i, algo: 'SEED (legacy cipher)', family: 'cipher', risk: 'quantum-weakened', rec: 'SEED — 128-bit Korean legacy block cipher; prefer AES-256-GCM' },
  { re: /skipjack[-_/(]/i, algo: 'Skipjack (broken cipher)', family: 'cipher', risk: 'broken-classical', rec: 'Skipjack — 80-bit NSA-era cipher, below modern security; REMOVE; use AES-256-GCM' }, // anchored by [-_/(] (so "skipjack tuna" prose does NOT fire); no leading \b ('encrypt_skipjack')
  { re: /\bIDEA[-_/.](new|MODE|CBC|ECB|CFB|OFB)\b|cipher-algo\s+IDEA\b|Cipher\.IDEA\b/i, algo: 'IDEA (legacy cipher)', family: 'cipher', risk: 'broken-classical', rec: 'IDEA — 64-bit-block legacy cipher (Sweet32 class); REMOVE; use AES-256-GCM' },
];
const RISK_ORDER = ['broken-classical', 'quantum-broken', 'quantum-weakened', 'classical-hybrid-ok', 'quantum-safe'];

// ---- v0.2: dependency-MANIFEST crypto-LIBRARY detection (a higher-signal layer than inline strings) ----
// A declared crypto dependency is strong evidence the project ACTUALLY USES that crypto — far lower false-positive than
// a bare string match in code. This is the "beyond grep" layer: it reasons about the project's dependency graph entry
// points (package.json / requirements / go.mod / Cargo / pom / Gemfile / .csproj), not just text.
const MANIFEST = /(^|[\\/])(package(-lock)?\.json|requirements[\w.-]*\.txt|Pipfile(\.lock)?|pyproject\.toml|go\.(mod|sum)|Cargo\.(toml|lock)|pom\.xml|build\.gradle(\.kts)?|Gemfile(\.lock)?|composer\.json|[^\\/]+\.csproj)$/i;
const LIB_RULES = [
  { re: /\bnode-forge\b/i, algo: 'lib:node-forge', risk: 'quantum-broken', rec: 'JS crypto lib (RSA/ECC by default) — plan ML-KEM/ML-DSA' },
  { re: /\b(jsrsasign|jsencrypt)\b/i, algo: 'lib:jsrsasign/jsencrypt', risk: 'quantum-broken', rec: 'RSA/ECC JS lib — plan PQ migration' },
  { re: /\bcrypto-js\b/i, algo: 'lib:crypto-js', risk: 'quantum-weakened', rec: 'symmetric/hash JS lib — verify AES-256/SHA-512; no PQ' },
  { re: /\b(bouncycastle|bcprov|bcpkix|org\.bouncycastle)\b/i, algo: 'lib:BouncyCastle', risk: 'classical-hybrid-ok', rec: 'broad crypto lib (has PQ since 1.7x) — verify ML-KEM/ML-DSA are actually used' },
  { re: /\b(pycryptodome|pyopenssl)\b|cryptography[=>~]/i, algo: 'lib:pyca-cryptography', risk: 'classical-hybrid-ok', rec: 'Python crypto lib — verify algorithms in use; limited native PQ' },
  { re: /\b(liboqs|oqs|pqcrypto|pqclean|open-quantum-safe)\b/i, algo: 'lib:liboqs/pqcrypto', risk: 'quantum-safe', rec: 'OK — post-quantum library present' },
  { re: /@noble\/post-quantum/i, algo: 'lib:@noble/post-quantum', risk: 'quantum-safe', rec: 'OK — PQ primitives (FIPS 203/204/205)' },
  { re: /\b(libsodium|sodium-native|tweetnacl)\b/i, algo: 'lib:libsodium/nacl', risk: 'classical-hybrid-ok', rec: 'modern classical crypto (X25519/Ed25519/ChaCha20) — pair with PQ' },
  { re: /\brustls\b|(?<![\w-])ring(?![\w-])/i, manifests: /Cargo\.(toml|lock)$/i, algo: 'lib:rustls/ring', risk: 'classical-hybrid-ok', rec: 'Rust TLS/crypto — verify TLS 1.3 + plan a PQ KEM' }, // Rust-only crates: gate to Cargo manifests + require the exact `ring` token so the npm `ring-buffer`/`ring-*` packages (NOT the Rust crypto crate) do not false-positive (adversary FP)
  // --- v0.3: more crypto libraries (manifest-context keeps false positives low) ---
  { re: /\b(wolfssl|wolfcrypt|mbedtls|mbed[-_]?crypto|boringssl)\b/i, algo: 'lib:wolfSSL/mbedTLS/BoringSSL', risk: 'classical-hybrid-ok', rec: 'embedded TLS/crypto — verify TLS 1.3 + the provider PQ KEM support/roadmap' },
  { re: /\bcircl\b/i, algo: 'lib:CIRCL', risk: 'quantum-safe', rec: 'OK — Cloudflare CIRCL (ML-KEM/ML-DSA present); verify the PQ algos are actually used' },
  { re: /\b(kyber-py|dilithium-py|falcon-py)\b/i, algo: 'lib:kyber-py/dilithium-py', risk: 'quantum-safe', rec: 'OK — pure-Python PQ implementation' },
  { re: /\bpynacl\b/i, algo: 'lib:PyNaCl', risk: 'classical-hybrid-ok', rec: 'libsodium binding (X25519/Ed25519/ChaCha20) — pair with a PQ KEM/sig' },
  { re: /\b(jsonwebtoken|pyjwt|jjwt|node-jose|jose)\b/i, algo: 'lib:JWT/JOSE', risk: 'classical-hybrid-ok', rec: 'JWT/JOSE lib — RS*/ES* algs are quantum-broken; verify the alg + plan ML-DSA' },
];
function scanManifest(filename, text) {
  const found = new Map();
  for (const r of LIB_RULES) {
    if (r.manifests && !r.manifests.test(filename)) continue; // rule scoped to a manifest kind (e.g. Rust `ring`/`rustls` -> Cargo only)
    if (!r.re.test(String(text))) continue;
    found.set(r.algo, { file: filename, context: 'dependency', confidence: 'likely', algo: r.algo, family: 'library', risk: r.risk, rec: r.rec, count: 1, code_count: 1, comment_count: 0, lines: [] });
  }
  return [...found.values()];
}

// ---- v0.5: ENCODED-BLOB layer — decode base64/PEM blobs (certs/keys) + identify the algorithm by its DER OID (closes the
// "encoded-blob" blind spot; certs/keys are base64, not named). FP-SAFE: a blob is flagged ONLY if it decodes to a
// DER-ANCHORED crypto OID ('06'<len><body>), so non-crypto base64 (images/JWTs/tokens) never false-positives. The DER
// bodies were derived + verified programmatically. Cross-env base64 (Node Buffer + browser atob) so the funnel copy works. ----
const OID_DER = [
  { der: '06092a864886f70d010101', algo: 'RSA (encoded/PEM)', family: 'pubkey', risk: 'quantum-broken', rec: 'RSA key/cert in an encoded blob (DER OID) — migrate KEM->ML-KEM-1024, sig->ML-DSA-87' },
  { der: '06072a8648ce3d0201', algo: 'EC key (encoded/PEM)', family: 'pubkey', risk: 'quantum-broken', rec: 'EC key/cert in an encoded blob — Shor-broken; migrate to ML-KEM/ML-DSA' },
  { der: '06072a8648ce380401', algo: 'DSA (encoded/PEM)', family: 'signature', risk: 'quantum-broken', rec: 'DSA in an encoded blob — migrate to ML-DSA-87 / SLH-DSA' },
  { der: '06032b6570', algo: 'Ed25519 (encoded/PEM)', family: 'signature', risk: 'classical-hybrid-ok', rec: 'Ed25519 key in an encoded blob — OK only as the classical leg of a HYBRID' },
  { der: '06032b656e', algo: 'X25519 (encoded/PEM)', family: 'kem', risk: 'classical-hybrid-ok', rec: 'X25519 key in an encoded blob — OK only inside a HYBRID with ML-KEM' },
];
function b64ToHex(b64) {
  try {
    if (typeof Buffer !== 'undefined') return Buffer.from(b64, 'base64').toString('hex');
    const bin = atob(b64); let h = ''; for (let i = 0; i < bin.length; i++) h += bin.charCodeAt(i).toString(16).padStart(2, '0'); return h; // browser path
  } catch { return null; }
}
function scanEncodedBlobs(filename, text) {
  const s = String(text), candidates = [];
  for (let m, re = /-----BEGIN [^-]+-----([\s\S]*?)-----END/g; (m = re.exec(s)); ) candidates.push(m[1].replace(/[^A-Za-z0-9+/=]/g, '')); // PEM bodies (lines joined)
  for (const r of (s.match(/[A-Za-z0-9+/]{24,}={0,2}/g) || [])) candidates.push(r);                                                    // inline base64 runs (>=24 chars; OID-gate keeps it FP-safe)
  const found = new Map();
  for (const c of candidates) {
    const hex = b64ToHex(c.slice(0, 1500)); // the algorithm OID sits near the front of a DER key/cert
    if (!hex) continue;
    for (const o of OID_DER) if (hex.includes(o.der)) found.set(o.algo, { file: filename, context: 'encoded', confidence: 'likely', algo: o.algo, family: o.family, risk: o.risk, rec: o.rec, count: 1, code_count: 1, comment_count: 0, lines: [] });
  }
  return [...found.values()];
}

// comment detection (heuristic, SAFE-by-design): we scan the FULL line so real code is NEVER hidden (a false
// NEGATIVE is worse than a false positive in a security scanner); we only TAG each match code vs comment by its
// position. Handles /* */ block comments + line comments (# and // guarded against ://). Strings are not yet
// lexed, so a comment marker inside a string literal could mis-tag (under-tag as comment) — which is why grading
// stays on TOTAL counts by default (see scanFiles gradeContext).
function findLineCommentIdx(line, from = 0) {
  const cands = [];
  const h = line.indexOf('#', from); if (h !== -1) cands.push(h);
  for (let i = line.indexOf('//', from); i !== -1; i = line.indexOf('//', i + 1)) { if (i === 0 || line[i - 1] !== ':') { cands.push(i); break; } }
  return cands.length ? Math.min(...cands) : -1;
}
function commentRegions(line, startInBlock) {
  const regions = []; let i = 0, inBlock = startInBlock, regionStart = startInBlock ? 0 : -1;
  while (i < line.length) {
    if (inBlock) { const e = line.indexOf('*/', i); if (e === -1) { regions.push([regionStart, line.length]); return { regions, endInBlock: true }; } regions.push([regionStart, e + 2]); i = e + 2; inBlock = false; }
    else { const b = line.indexOf('/*', i); const lc = findLineCommentIdx(line, i);
      if (b !== -1 && (lc === -1 || b < lc)) { inBlock = true; regionStart = b; i = b + 2; }
      else if (lc !== -1) { regions.push([lc, line.length]); return { regions, endInBlock: false }; }
      else break; }
  }
  return { regions, endInBlock: inBlock };
}
const inComment = (idx, regions) => regions.some(([s, e]) => idx >= s && idx < e);

// inline suppression marker: a line containing `pqcbom-ignore` (e.g. `key = RSA.gen() // pqcbom-ignore: accepted, legacy`)
// suppresses findings on THAT line — counted (summary.suppressed), never graded. Adoption needs an escape hatch.
const IGNORE_MARK = /pqcbom-ignore/i;
export function scanText(filename, text) {
  const lines = String(text).split(/\r?\n/);
  const found = new Map(); // algo -> { ..., count, code_count, comment_count, lines:[] }
  let inBlock = false, suppressed = 0;
  for (let i = 0; i < lines.length; i++) {
    const { regions, endInBlock } = commentRegions(lines[i], inBlock); inBlock = endInBlock;
    const ignoreLine = IGNORE_MARK.test(lines[i]);
    for (const r of RULES) {
      const idx = lines[i].search(r.re); // full-line scan -> code is never hidden
      if (idx === -1) continue;
      if (ignoreLine) { suppressed += 1; continue; } // honor the inline ignore: counted, not graded, not listed
      const ctx = inComment(idx, regions) ? 'comment' : 'code';
      const f = found.get(r.algo) || { algo: r.algo, family: r.family, risk: r.risk, rec: r.rec, count: 0, code_count: 0, comment_count: 0, lines: [] };
      f.count += 1; if (ctx === 'code') f.code_count += 1; else f.comment_count += 1;
      if (f.lines.length < 5) f.lines.push(i + 1);
      found.set(r.algo, f);
    }
  }
  // CONFIDENCE (the triage the assessment promises, now tool-derived from the detection SOURCE — honest: the tool can't
  // CONFIRM runtime use, so the top tier is "likely"; a human assessor upgrades to "Confirmed"):
  //   likely        = a declared dependency (manifest) — strong evidence of real usage
  //   lead-to-verify = appears in CODE — real but lexical, verify it's a live path (not dead code / a test)
  //   informational = named only in a COMMENT/doc
  const inline = [...found.values()].map((f) => ({ file: filename, context: f.code_count > 0 ? 'code' : 'comment', confidence: f.code_count > 0 ? 'lead-to-verify' : 'informational', ...f }));
  // manifest files ALSO get the higher-signal dependency-library layer (beyond inline grep)
  const enc = scanEncodedBlobs(filename, text); // v0.5: decode base64/PEM key/cert blobs -> algorithm by DER OID
  const out = (MANIFEST.test(filename) ? inline.concat(scanManifest(filename, text)) : inline).concat(enc);
  out.suppressed = suppressed; // per-file inline-suppressed occurrence count (array property; read in scanFiles)
  return out;
}

// The 5 grade-driving risk tallies, computed FROM the findings. Exported so verifyEvidencePack can independently
// recompute them at verification time (so the grade is provably a function of the findings, not a trusted summary).
export function riskTally(findings, gradeContext = 'total') {
  const field = gradeContext === 'code' ? 'code_count' : 'count';
  const t = (risk) => findings.filter((f) => f.risk === risk).reduce((n, f) => n + (f[field] ?? f.count), 0);
  return {
    broken_classical: t('broken-classical'),
    quantum_broken: t('quantum-broken'),
    quantum_weakened: t('quantum-weakened'),
    classical_hybrid_ok: t('classical-hybrid-ok'),
    quantum_safe: t('quantum-safe'),
  };
}

// opts.gradeContext: 'total' (DEFAULT — pessimistic/safe, counts comment mentions too) or 'code' (grade on code
// occurrences only; comment/doc mentions become informational — use once you trust the parser).
export function scanFiles(files, opts = {}) {
  const per = files.map((f) => scanText(f.name, f.text));
  let findings = per.flat();
  let suppressed = per.reduce((n, a) => n + (a.suppressed || 0), 0); // inline `pqcbom-ignore` hits
  // allowlist: opts.ignoreAlgos (or a .pqcbomignore file via scanDirectory) — accept findings by exact algo label OR
  // risk class (case-insensitive). Accepted findings are DROPPED from grading + listing, counted in summary.suppressed.
  const igList = (opts.ignoreAlgos instanceof Set ? [...opts.ignoreAlgos] : Array.isArray(opts.ignoreAlgos) ? opts.ignoreAlgos : []).map((s) => String(s).toLowerCase());
  if (igList.length) {
    const ig = new Set(igList);
    findings = findings.filter((f) => { if (ig.has(f.algo.toLowerCase()) || ig.has(f.risk.toLowerCase())) { suppressed += f.count; return false; } return true; });
  }
  const summary = {
    files_scanned: files.length,
    ...riskTally(findings, opts.gradeContext),
    suppressed, // occurrences accepted via inline marker or allowlist (not graded) — surfaced for transparency
    comment_mentions: findings.reduce((n, f) => n + (f.comment_count || 0), 0), // crypto named only in comments/docs
    by_confidence: { // the triage breakdown (tool-derived; a human assessor confirms)
      likely: findings.filter((f) => f.confidence === 'likely').length,
      lead_to_verify: findings.filter((f) => f.confidence === 'lead-to-verify').length,
      informational: findings.filter((f) => f.confidence === 'informational').length,
    },
    distinct_algorithms: new Set(findings.map((f) => f.algo)).size,
    grade_context: opts.gradeContext === 'code' ? 'code' : 'total',
  };
  const grade = gradeOf(summary);
  return { summary, grade, findings: findings.sort((a, b) => RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk)) };
}

// A–F Post-Quantum Readiness Scorecard (the viral badge) + a 0–100 score
export function gradeOf(s) {
  let score = 100;
  score -= 40 * Math.min(s.broken_classical, 2);
  score -= 12 * Math.min(s.quantum_broken, 5);
  score -= 4 * Math.min(s.quantum_weakened, 5);
  score -= 1 * Math.min(s.classical_hybrid_ok, 5);
  score = Math.max(0, score);
  let letter;
  if (s.broken_classical > 0) letter = 'F';
  else if (s.quantum_broken > 0) letter = s.quantum_safe >= s.quantum_broken ? 'C' : 'D';
  else if (s.quantum_weakened > 0) letter = 'B';
  else letter = 'A';
  const labels = { A: 'Post-Quantum Readiness', B: 'Quantum-weakened (Grover)', C: 'Migrating (hybrid present)', D: 'Quantum-vulnerable — migrate', F: 'Critical — broken crypto in use' };
  return { letter, score, label: labels[letter], badge: 'PQ Readiness: ' + letter };
}

// CycloneDX-1.6-style CBOM (cryptography components) — the machine-readable evidence artifact
export function toCycloneDX(report) {
  const byAlgo = new Map();
  for (const f of report.findings) { const e = byAlgo.get(f.algo) || { ...f, occurrences: [] }; e.occurrences.push({ file: f.file, lines: f.lines }); byAlgo.set(f.algo, e); }
  return {
    bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
    metadata: { tools: [{ vendor: 'TRELYAN', name: 'pqcbom', version: '0.2.0-draft' }], properties: [{ name: 'trelyan:quantum-grade', value: report.grade.letter }, { name: 'trelyan:quantum-score', value: String(report.grade.score) }] },
    components: [...byAlgo.values()].map((e) => ({
      type: 'cryptographic-asset', name: e.algo,
      cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: e.family }, nistQuantumSecurityLevel: e.risk === 'quantum-safe' ? 5 : 0 },
      properties: [{ name: 'trelyan:quantumRisk', value: e.risk }, { name: 'trelyan:recommendation', value: e.rec }, { name: 'trelyan:occurrences', value: JSON.stringify(e.occurrences) }],
    })),
  };
}

// SARIF 2.1.0 — so findings surface in GitHub code-scanning (Security tab + inline PR annotations) and any SARIF-aware
// tool. risk -> level: broken/quantum-broken=error, weakened=warning, hybrid-ok/safe=note. opts.baseDir relativizes paths.
const SARIF_LEVEL = { 'broken-classical': 'error', 'quantum-broken': 'error', 'quantum-weakened': 'warning', 'classical-hybrid-ok': 'note', 'quantum-safe': 'note' };
const SARIF_SEV = { 'broken-classical': '9.0', 'quantum-broken': '8.0', 'quantum-weakened': '5.0', 'classical-hybrid-ok': '2.0', 'quantum-safe': '0.0' };
export function toSARIF(report, opts = {}) {
  const base = opts.baseDir ? opts.baseDir.replace(/\\/g, '/').replace(/\/+$/, '') + '/' : null;
  const rel = (file) => { let u = String(file || 'input').replace(/\\/g, '/'); if (base && u.startsWith(base)) u = u.slice(base.length); return u; };
  const ruleIndex = new Map(); const rules = [];
  for (const f of report.findings) {
    if (ruleIndex.has(f.algo)) continue;
    ruleIndex.set(f.algo, rules.length);
    rules.push({
      id: ('pqc-' + f.risk + '-' + f.algo).replace(/[^a-zA-Z0-9]+/g, '-').replace(/-+$/g, '').toLowerCase(),
      name: f.algo.replace(/[^a-zA-Z0-9]+/g, '') || 'crypto',
      shortDescription: { text: f.algo + ' — ' + f.risk },
      fullDescription: { text: String(f.rec || '') },
      defaultConfiguration: { level: SARIF_LEVEL[f.risk] || 'note' },
      properties: { 'security-severity': SARIF_SEV[f.risk] || '0.0', tags: ['cryptography', 'post-quantum', f.risk] },
      helpUri: 'https://trelyan.foundation/pqc',
    });
  }
  const results = report.findings.map((f) => {
    const lines = (f.lines && f.lines.length) ? f.lines : [1];
    return {
      ruleId: rules[ruleIndex.get(f.algo)].id, ruleIndex: ruleIndex.get(f.algo),
      level: SARIF_LEVEL[f.risk] || 'note',
      message: { text: f.algo + ' (' + f.risk + ', ' + (f.confidence || 'lead-to-verify') + '): ' + String(f.rec || '') },
      locations: lines.map((ln) => ({ physicalLocation: { artifactLocation: { uri: rel(f.file) }, region: { startLine: Math.max(1, ln | 0) } } })),
      partialFingerprints: { pqcbom: f.algo + ':' + rel(f.file) },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'pqcbom', informationUri: 'https://trelyan.foundation', version: '0.2.0-draft', rules } },
      results,
      properties: { 'trelyan:quantum-grade': report.grade.letter, 'trelyan:quantum-score': report.grade.score },
    }],
  };
}

// directory walker for the CLI / dogfood (node only)
export async function scanDirectory(dir, opts = {}) {
  const { readdirSync, readFileSync, lstatSync } = await import('fs');
  const { join, extname } = await import('path');
  // code + CONFIG extensions — TLS/SSH/JWT crypto lives in config files (.conf/.ini/.env/…), so scanning code-only
  // would leave the v0.2 protocol layer mostly dead in a directory/Action scan
  const exts = opts.exts || ['.mjs', '.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rs', '.java', '.kt', '.c', '.cc', '.cpp', '.h', '.json', '.yaml', '.yml', '.toml', '.tf', '.cs', '.rb', '.php', '.conf', '.cnf', '.cfg', '.ini', '.config', '.properties', '.xml', '.gradle', '.sh', '.bash', '.zsh', '.ps1', '.pem', '.crt'];
  // extensionless config files that commonly carry crypto/TLS/SSH settings
  const CONFIG_FILE = /(^|[\\/])(sshd?_config|ssh_config|Dockerfile|Caddyfile|\.env(\.[\w-]+)?)$/i;
  const skip = new Set(['node_modules', '.git', 'dist', 'build', '.next', '_extracted']);
  const files = [];
  // ROBUSTNESS (the Action scans untrusted repos): use lstatSync and SKIP symlinks — a symlink cycle would otherwise
  // recurse forever, and a symlink could point outside the tree. Every fs call is wrapped so one unreadable file/dir
  // is skipped (recorded), never aborts the whole scan/gate.
  const skipped = [];
  // include code/config by extension AND dependency manifests by filename (so the dependency layer fires for
  // requirements.txt / go.mod / pom.xml / Gemfile / *.csproj etc., which have no code-extension)
  const walk = (d) => {
    let entries; try { entries = readdirSync(d); } catch (e) { skipped.push(d); return; }
    for (const name of entries) {
      if (skip.has(name)) continue;
      const p = join(d, name);
      let st; try { st = lstatSync(p); } catch (e) { skipped.push(p); continue; }
      if (st.isSymbolicLink()) { skipped.push(p); continue; } // do not follow symlinks (cycle/out-of-tree safe)
      if (st.isDirectory()) { walk(p); continue; }
      if (!(exts.includes(extname(name)) || MANIFEST.test(name) || CONFIG_FILE.test(name)) || st.size >= 2_000_000) continue;
      try { files.push({ name: p, text: readFileSync(p, 'utf8') }); } catch (e) { skipped.push(p); }
    }
  };
  walk(dir);
  // allowlist file: `.pqcbomignore` at the scan root — one accepted algo label or risk class per line ('#' comments ok)
  let ignoreAlgos = opts.ignoreAlgos ? [...(opts.ignoreAlgos instanceof Set ? opts.ignoreAlgos : opts.ignoreAlgos)] : [];
  try {
    const ig = readFileSync(join(dir, '.pqcbomignore'), 'utf8');
    ignoreAlgos = ignoreAlgos.concat(ig.split(/\r?\n/).map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean));
  } catch { /* no allowlist file — fine */ }
  const res = scanFiles(files, { ...opts, ignoreAlgos }); // pass gradeContext through (a CI gate grades CODE, not comment mentions)
  if (skipped.length) res.summary.skipped_paths = skipped.length; // surfaced, never silent
  return res;
}

/* ---------- self-test: node pqcbom.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  const vulnerable = `
    const key = RSA.generateKeyPair(2048);
    sign(msg, ECDSA, 'secp256k1');
    cipher = AES-128-CBC; hash = MD5;
  `;
  const r1 = scanText('legacy.js', vulnerable);
  ok(r1.find((f) => f.algo === 'RSA' && f.risk === 'quantum-broken'), 'detects RSA -> quantum-broken');
  ok(r1.find((f) => f.algo === 'ECDSA' && f.risk === 'quantum-broken'), 'detects ECDSA -> quantum-broken');
  ok(r1.find((f) => f.algo === 'AES-128/192' && f.risk === 'quantum-weakened'), 'detects AES-128 -> quantum-weakened');
  ok(r1.find((f) => f.algo === 'MD5' && f.risk === 'broken-classical'), 'detects MD5 -> broken-classical');
  ok(r1.find((f) => f.algo === 'RSA').rec.includes('ML-KEM'), 'RSA finding carries an ML-KEM/ML-DSA migration recommendation');

  const safe = `
    import { ml_kem1024 } from 'pq'; import { ml_dsa87 } from 'pq';
    aead = AES-256-GCM; hash = SHA-512; kex = X25519 + ML-KEM-768;
  `;
  const r2 = scanText('modern.mjs', safe);
  ok(r2.find((f) => f.algo === 'ML-KEM/Kyber' && f.risk === 'quantum-safe'), 'detects ML-KEM -> quantum-safe');
  ok(r2.find((f) => f.algo === 'X25519/X448' && f.risk === 'classical-hybrid-ok'), 'X25519 flagged classical-hybrid-ok (valid as a hybrid leg)');

  // grading: the vulnerable file -> F (MD5 broken); the safe file -> A
  ok(scanFiles([{ name: 'legacy.js', text: vulnerable }]).grade.letter === 'F', 'vulnerable file -> grade F (critical)');
  ok(scanFiles([{ name: 'modern.mjs', text: safe }]).grade.letter === 'A', 'all-PQ-safe file -> grade A');

  // CycloneDX CBOM shape
  const cbom = toCycloneDX(scanFiles([{ name: 'legacy.js', text: vulnerable }]));
  ok(cbom.bomFormat === 'CycloneDX' && cbom.components.length >= 4 && cbom.components.every((c) => c.type === 'cryptographic-asset'), 'emits a CycloneDX CBOM of cryptographic-asset components');
  ok(cbom.metadata.properties.some((p) => p.name === 'trelyan:quantum-grade' && p.value === 'F'), 'CBOM carries the quantum grade');

  // SARIF 2.1.0 (GitHub code-scanning)
  const sarif = toSARIF(scanFiles([{ name: 'C:/repo/legacy.js', text: vulnerable }]), { baseDir: 'C:/repo' });
  ok(sarif.version === '2.1.0' && sarif.runs[0].tool.driver.name === 'pqcbom' && Array.isArray(sarif.runs[0].results) && sarif.runs[0].results.length >= 1, 'emits valid SARIF 2.1.0 (tool driver + results)');
  ok(sarif.runs[0].results.every((r) => r.ruleId && r.locations[0].physicalLocation.artifactLocation.uri && r.locations[0].physicalLocation.region.startLine >= 1), 'every SARIF result has a ruleId + located region (startLine>=1)');
  ok(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri === 'legacy.js', 'baseDir relativizes the SARIF artifact uri (repo-relative for GitHub)');
  ok(sarif.runs[0].tool.driver.rules.some((r) => r.defaultConfiguration.level === 'error'), 'broken/quantum-broken findings map to SARIF level "error"');

  // no false-positive on the word "description"
  ok(scanText('x.md', 'This is a description of the DES-less system.').length === 0, 'no false positive on "description"');

  // COMMENT-AWARENESS: crypto named only in comments/docs is TAGGED context:comment (cuts the documented false positive)
  const commented = '// TODO: migrate away from RSA and ECDSA\n/* legacy build used MD5 */\nlet ok = true;';
  const rc = scanText('notes.js', commented);
  ok(rc.find((f) => f.algo === 'RSA').context === 'comment', 'RSA in a // line comment -> tagged context:comment');
  ok(rc.find((f) => f.algo === 'MD5').context === 'comment', 'MD5 in a /* */ block comment -> tagged context:comment');
  // SAFETY: real code AFTER a URL (// guarded) is still detected as code, never hidden
  const mixed = 'const url = "http://x"; key = RSA.generate(2048); // uses ECDSA elsewhere';
  const rm = scanText('m.js', mixed);
  ok(rm.find((f) => f.algo === 'RSA').context === 'code', 'RSA in real code on a line with a URL + trailing comment -> still tagged code (not hidden)');
  ok(rm.find((f) => f.algo === 'ECDSA').context === 'comment', 'ECDSA only in the trailing // comment -> tagged comment');
  // DEFAULT grade stays pessimistic/safe; opt-in code grading discounts comment-only mentions
  ok(scanFiles([{ name: 'notes.js', text: commented }]).grade.letter !== 'A', 'DEFAULT grade is conservative (comment mentions still counted — safe, no silent optimism)');
  const codeGraded = scanFiles([{ name: 'notes.js', text: commented }], { gradeContext: 'code' });
  ok(codeGraded.grade.letter === 'A' && codeGraded.summary.comment_mentions >= 2, 'gradeContext:code -> comment-only crypto becomes informational (grade A + comment_mentions recorded)');

  // --- regression: pre-ship review (council) false-positive/negative fixes ---
  const algos = (s) => new Set(scanText('r.txt', s).map((f) => f.algo));
  // CRITICAL false positive (both council seats): modern TLS must NOT be flagged broken
  ok(!algos('ssl_protocols TLSv1.2 TLSv1.3;').has('TLS<1.2 / SSL'), 'TLS 1.2/1.3 are NOT flagged (the TLSv1\\b false-positive is fixed)');
  ok(algos('ssl_protocols TLSv1.1;').has('TLS<1.2 / SSL') && algos('SSLv3').has('TLS<1.2 / SSL'), 'deprecated TLS 1.1 / SSLv3 ARE still flagged');
  // false positives fixed
  ok(!algos('uses ML-DSA and SLH-DSA').has('DSA'), 'ML-DSA / SLH-DSA do NOT trip the legacy DSA rule');
  ok(algos('legacy DSA signing').has('DSA'), 'real standalone DSA is still caught');
  ok(!algos('PKCS#11 with CloudHSM').has('RSA') && algos('PKCS#11 with CloudHSM').has('managed KMS/HSM'), 'PKCS#11 (HSM) does NOT trip the RSA rule');
  // false negatives added (council)
  ok(algos('HostKey ssh-dss').has('SSH RSA/DSA/ECDSA key'), 'ssh-dss is caught');
  ok(algos('DHE-RSA').has('finite-field DH'), 'DHE (ephemeral DH) is caught');
  ok(algos('RSASSA-PSS').has('RSA'), 'RSASSA is caught as RSA');
  ok(algos('hash = SHA3-384').has('SHA-384'), 'SHA3-384 is caught');
  { const r = scanFiles([{ name: 'h.js', text: 'SHA-256; SHA-384; SHA-512' }]); const risk = (a) => r.findings.find((f) => f.algo === a)?.risk;
    ok(risk('SHA-256') === 'quantum-weakened' && risk('SHA-384') === 'quantum-safe' && risk('SHA-512/SHA3-512') === 'quantum-safe', 'SHA-256 is quantum-weakened but SHA-384/512 are quantum-resistant (CNSA-2.0 correction — TRELYAN PQEF itself uses SHA-384)'); }
  ok(algos('curve secp384r1').has('EC curve') && algos('P-224 curve').has('EC curve'), 'secp384r1 and P-224 EC curves are caught');
  ok(algos('ECDHE-ECDSA').has('ECDH'), 'ECDHE is caught');

  // --- v0.3 expanded coverage ---
  ok(algos('kem = SIKE').has('SIKE/SIDH (BROKEN PQ)') && scanText('s.txt', 'SIKE').find((f) => f.algo === 'SIKE/SIDH (BROKEN PQ)').risk === 'broken-classical', 'SIKE/SIDH flagged BROKEN (catches a FALSE sense of PQ security)');
  ok(algos('sig = XMSS').has('XMSS (stateful hash sig)'), 'XMSS flagged (stateful hash sig, quantum-safe)');
  ok(algos('cipher Blowfish').has('Blowfish/CAST5') && algos('hash MD4').has('MD4/MD2'), 'Blowfish + MD4 -> broken-classical');
  ok(algos('curve secp192r1').has('EC curve (legacy)'), 'legacy 192-bit EC curve caught');
  ok(scanManifest('go.mod', 'github.com/cloudflare/circl v1.3.7').some((f) => f.algo === 'lib:CIRCL' && f.risk === 'quantum-safe'), 'CIRCL dependency -> quantum-safe');
  ok(scanManifest('package.json', '"jsonwebtoken": "^9.0.0"').some((f) => f.algo === 'lib:JWT/JOSE'), 'JWT/JOSE library dependency flagged');
  // v0.3 FP guards: the collision-prone tokens we deliberately dropped must NOT trip
  ok(scanText('d.md', 'a great idea, see release rc2, in the LMS learning system').length === 0, 'v0.3 FP guard: "idea"/"rc2"/"LMS" do NOT false-positive');

  // --- v0.4: cryptographic OID detection (closes the published "OID" blind spot) ---
  ok(algos('SubjectPublicKeyInfo 1.2.840.113549.1.1.1').has('RSA (OID rsaEncryption)'), 'RSA key OID -> quantum-broken');
  ok(algos('sigAlg 1.2.840.10045.4.3.2').has('ECDSA sig (OID)') && algos('curve 1.2.840.10045.3.1.7').has('P-256/prime256v1 curve (OID)'), 'ECDSA + P-256 OIDs detected');
  ok(algos('1.3.101.112').has('Ed25519/Ed448 (OID)') && algos('digest 1.2.840.113549.2.5').has('MD5 (OID)'), 'Ed25519 OID -> hybrid-ok; MD5 OID -> broken-classical');
  ok(algos('1.2.840.113549.1.1.11').has('RSA-SHA256 sig (OID)') && !algos('1.2.840.113549.1.1.11').has('RSA (OID rsaEncryption)'), 'OID exactness: ...1.1.11 = RSA-SHA256 only (lookahead anchors the exact OID, no prefix mis-fire)');
  ok(scanText('v.txt', 'release 1.2.3, version 2.16.0, build 1.2.840 partial').length === 0, 'v0.4 FP guard: version-like dotted numbers do NOT trip OID rules');

  // --- v0.5: encoded-blob detection (closes the "encoded-blob" blind spot — base64/PEM certs+keys) ---
  ok(scanText('k.txt', 'pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"').some((f) => f.algo === 'RSA (encoded/PEM)' && f.risk === 'quantum-broken'), 'base64 RSA SubjectPublicKeyInfo blob -> RSA (decoded DER OID)');
  ok(scanText('cert.pem', '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----').some((f) => f.algo === 'RSA (encoded/PEM)'), 'PEM-wrapped RSA key detected (lines joined + decoded)');
  ok(scanText('img.txt', 'data = "' + 'QUJD'.repeat(30) + '"').filter((f) => f.context === 'encoded').length === 0, 'v0.5 FP guard: non-crypto base64 (no DER crypto OID) -> NO encoded finding');

  // --- v0.6: fused ASN.1 algorithm identifiers (closes the "substring" blind spot for known names) ---
  ok(algos('const k = rsaEncryption(2048);').has('RSA/EC ASN.1 identifier (fused)'), 'fused "rsaEncryption" identifier detected');
  ok(algos('sigAlg: sha256WithRSAEncryption').has('RSA/EC ASN.1 identifier (fused)') && algos('alg = ecPublicKey').has('RSA/EC ASN.1 identifier (fused)'), 'sha256WithRSAEncryption + ecPublicKey detected');
  ok(scanText('w.md', 'an rsannouncement about ecology and a description').length === 0, 'v0.6 FP guard: bare "rsa"/"ec"/"des" inside ordinary words do NOT trip');

  // --- v0.7: compound / glued algorithm identifiers (corpus-driven; test-fixtures/structural-corpus.json) ---
  ok(algos("crypto.createCipheriv('des-ede3-cbc', k, iv)").has('3DES/DES'), 'compound des-ede3-cbc -> 3DES');
  ok(algos('Crypto.Cipher.DES3.new(k)').has('3DES/DES'), 'DES3 -> 3DES');
  ok(algos('Cipher.getInstance("ARCFOUR")').has('RC4') && algos('cipher RC4_128 suite').has('RC4'), 'ARCFOUR + RC4_128 -> RC4');
  ok(algos('Signature.getInstance("SHA1withRSA")').has('SHA-1') && algos('Signature.getInstance("SHA1withRSA")').has('RSA/EC ASN.1 identifier (fused)'), 'SHA1withRSA -> SHA-1 (hash leg) + RSA (sig leg)');
  ok(algos('ECCurve.CreateFromFriendlyName("nistP256")').has('EC curve') && algos('elliptic.P224()').has('EC curve'), 'nistP256 + elliptic.P224() -> EC curve');
  ok(algos('new RSACryptoServiceProvider(2048)').has('RSA') && algos('using var h = new MD5CryptoServiceProvider()').has('MD5'), '.NET CSP classes -> RSA / MD5');
  ok(algos('SecretKeyFactory.getInstance("PBEWithMD5AndDES")').has('MD5') && algos('SecretKeyFactory.getInstance("PBEWithMD5AndDES")').has('3DES/DES'), 'PBEWithMD5AndDES -> MD5 + DES');
  ok(algos('openssl_public_encrypt($msg, $out, $pub)').has('RSA'), 'PHP openssl_public_encrypt -> RSA');
  ok(algos("opts.algorithm = 'none'").has('JWT alg=none'), "algorithm = 'none' -> JWT alg=none");
  ok(algos('Ciphers aes128-cbc,3des-cbc').has('3DES/DES') && algos('openssl enc -des-ede3-cbc -salt').has('3DES/DES'), 'config 3des-cbc / -des-ede3-cbc -> 3DES');
  ok(algos('openssl gendsa -out ca.key dsaparam.pem').has('DSA'), 'gendsa/dsaparam -> DSA');
  ok(algos('forge.cipher.createCipher("DES-CBC")').has('3DES/DES') && algos('var a = SymmetricAlgorithm.Create("RC2")').has('RC2'), 'DES-CBC + Create("RC2") -> 3DES/DES, RC2');
  // v0.7 FP guards — compound rules must NOT trip on benign tokens
  ok(scanText('rel.md', 'shipping build v2.0-RC2 and v1.9-RC2 today').filter((f) => f.algo === 'RC2').length === 0, 'v0.7 FP guard: release-candidate RC2 NOT flagged (crypto-context RC2 only)');
  ok(scanText('cfg.yml', "compression_algorithm: 'none'").filter((f) => f.algo === 'JWT alg=none').length === 0, 'v0.7 FP guard: compression_algorithm:none is NOT JWT alg=none (\\b excludes _algorithm)');
  ok(scanText('p.txt', 'sensor model P256 rev DES3000-A AES1000 board').filter((f) => /EC curve|3DES|RC4|RC2/.test(f.algo)).length === 0, 'v0.7 FP guard: bare P256 / DES3000 / AES1000 part numbers do NOT trip');

  // --- v0.8: adversary-driven FP fixes + FN additions (red-team workflow) ---
  ok(scanText('id.py', 'OWNER_SURNAME = "Gendsa"').filter((f) => f.algo === 'DSA').length === 0, 'v0.8 FP: surname "Gendsa" is not DSA (gendsa needs command context)');
  ok(scanText('e.cs', 'enum { Debug, Release, DESeded }').filter((f) => /3DES|DES/.test(f.algo)).length === 0, 'v0.8 FP: "DESeded" build flavour is not 3DES');
  ok(scanText('p.txt', 'set header alg: none-cache to bypass').filter((f) => /JWT/.test(f.algo)).length === 0, 'v0.8 FP: "none-cache" is not JWT alg=none');
  ok(scanText('c.md', 'added TLS_DRAFT_RSA_NOTES.md').filter((f) => f.algo === 'RSA').length === 0, 'v0.8 FP: TLS_DRAFT_RSA_NOTES filename is not RSA (suite rule requires WITH)');
  ok(scanText('t.md', 'a great idea for the rewrite').filter((f) => /IDEA/.test(f.algo)).length === 0 && scanText('t.md', 'skipjack tuna season report').filter((f) => /Skipjack/.test(f.algo)).length === 0, 'v0.8 FP: prose "idea" / "skipjack tuna" do not fire IDEA / Skipjack');
  ok(algos('openssl gendsa -out ca.key dsaparam.pem').has('DSA') && algos('DESedeKeySpec ks').has('3DES/DES') && algos('header = { alg: "none" }').has('JWT alg=none'), 'v0.8: real gendsa / DESedeKeySpec / alg:none still caught');
  ok(algos('tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA').has('RSA') && algos('tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA').has('RC4'), 'v0.8: real TLS suite const still RSA + RC4');
  ok(algos('transform = des_ede3_cbc').has('3DES/DES') && algos('algorithm: TDES').has('3DES/DES') && algos('mcrypt_encrypt(MCRYPT_3DES, k)').has('3DES/DES'), 'v0.8 FN: des_ede3_cbc / TDES / MCRYPT_3DES -> 3DES');
  ok(algos("ENC = 'aes_128_ctr'").has('AES-128/192') && algos('Ciphers arcfour128,arcfour256').has('RC4'), 'v0.8 FN: aes_128_ctr / arcfour128 underscore forms');
  ok(algos('getInstance("MD-5")').has('MD5') && algos('getInstance("PBKDF2WithHmacSHA1")').has('SHA-1') && algos('sig = "md5WithRSAEncryption"').has('MD5'), 'v0.8 FN: MD-5 / HmacSHA1 / md5WithRSAEncryption');
  ok(algos('openssl genrsa -out s.key 1024').has('RSA') && algos('openssl dhparam -out dh.pem 1024').has('finite-field DH') && algos('var k = RSA512.Create()').has('RSA'), 'v0.8 FN: genrsa / dhparam / RSA512');
  ok(algos('getInstance("SM3withSM2")').has('SM2 (GM EC)') && algos('getInstance("SEED/CBC/PKCS5Padding")').has('SEED (legacy cipher)'), 'v0.8 FN: SM2 / SEED');
  ok(algos('encrypt_skipjack(buf, key)').has('Skipjack (broken cipher)') && algos('gpg --cipher-algo IDEA file').has('IDEA (legacy cipher)') && algos('Crypto.Cipher.IDEA.new(k)').has('IDEA (legacy cipher)'), 'v0.8 FN: Skipjack / IDEA (anchored)');
  ok(algos('gost28147.NewCipher(key)').has('GOST cipher/hash (legacy)') && algos('newkey gost2012_256').has('GOST R 34.10/34.11 (legacy)'), 'v0.8 FN: GOST 28147 cipher + GOST 2012 sig');
  ok(algos('hashlib.sha224(x)').has('SHA-224') && algos('kdf = PBKDF1(pw, salt)').has('PBKDF1 (weak KDF)') && algos('getParameterSpec("secp160r1")').has('EC curve (legacy)'), 'v0.8 FN: SHA-224 / PBKDF1 / secp160r1');
  ok(algos('RC2.new(key, RC2.MODE_ECB)').has('RC2') && algos('mcrypt_encrypt(MCRYPT_RC2, k)').has('RC2'), 'v0.8 FN: RC2.new / MCRYPT_RC2');

  // --- v0.9: empirical FP corpus (popular OSS project names / target-audience acronyms that collided) ---
  // Magma is a very common project name (Meta Magma mobile core, Magma CAS, magma DB) — bare "Magma" must NOT flag GOST (was grade-F)
  ok(scanManifest('package.json', '{"dependencies":{"magma":"^1.2.0"}}').filter((f) => /GOST/.test(f.algo)).length === 0, 'v0.9 FP: "magma" dependency is NOT GOST (popular project name)');
  ok(scanText('r.md', 'We deploy on Magma, the mobile core; magma-cooled reactors.').filter((f) => /GOST/.test(f.algo)).length === 0, 'v0.9 FP: "Magma" project/word is NOT GOST');
  ok(algos('cipher = magma-cbc').has('GOST cipher/hash (legacy)') && algos('gost magma').has('GOST cipher/hash (legacy)') && algos('magma.NewCipher(k)').has('GOST cipher/hash (legacy)'), 'v0.9: real GOST Magma (magma-cbc / gost magma / magma.new) still caught');
  // Rust `ring`/`rustls` are Cargo-only — the npm `ring-buffer` / `ring-*` packages must NOT trip the crypto-lib rule
  ok(scanManifest('package.json', '{"dependencies":{"ring-buffer":"^1.0.0","clustering":"^2.0.0"}}').filter((f) => /ring/.test(f.algo)).length === 0, 'v0.9 FP: npm ring-buffer is NOT the Rust `ring` crate (gated to Cargo + exact token)');
  ok(scanManifest('Cargo.toml', 'ring = "0.17"\nrustls = "0.23"').some((f) => f.algo === 'lib:rustls/ring'), 'v0.9: real Cargo ring/rustls dependency still caught');
  ok(scanManifest('Cargo.toml', 'ring-channel = "0.12"').filter((f) => /ring/.test(f.algo)).length === 0, 'v0.9 FP: even in Cargo, ring-channel (hyphenated) is not the ring crate');
  // "DSA" as a defined acronym — Digital Services Act (DORA/NIS2 audience) / Democratic Socialists — must NOT flag DSA
  ok(scanText('policy.md', 'Compliance under the DSA (Digital Services Act) and the DSA (Democratic Socialists).').filter((f) => f.algo === 'DSA').length === 0, 'v0.9 FP: "DSA (Digital Services Act)" acronym-definition is not the DSA algorithm');
  ok(algos('legacy DSA signing').has('DSA') && algos('KeyPairGenerator.getInstance("DSA")').has('DSA') && algos('DSA(key)').has('DSA'), 'v0.9: real DSA (prose "DSA signing" / getInstance("DSA") / DSA(key) call) still caught');

  // --- suppression: inline `pqcbom-ignore` + allowlist (adoption escape hatch) ---
  const inlIgnore = scanFiles([{ name: 'a.js', text: 'const k = RSA.gen(2048); // pqcbom-ignore: accepted legacy' }]);
  ok(!inlIgnore.findings.some((f) => f.algo === 'RSA') && inlIgnore.summary.suppressed >= 1, 'inline pqcbom-ignore suppresses the line (counted, not graded)');
  const partial = scanFiles([{ name: 'a.js', text: 'a = RSA.gen();\nb = RSA.gen(); // pqcbom-ignore' }]);
  ok(partial.findings.find((f) => f.algo === 'RSA') && partial.findings.find((f) => f.algo === 'RSA').count === 1 && partial.summary.suppressed === 1, 'ignore is per-line — an un-ignored RSA on another line is still reported (count 1)');
  const allowAlgo = scanFiles([{ name: 'a.js', text: 'x = RSA.gen(); y = MD5(p);' }], { ignoreAlgos: ['RSA'] });
  ok(!allowAlgo.findings.some((f) => f.algo === 'RSA') && allowAlgo.findings.some((f) => f.algo === 'MD5'), 'allowlist drops the named algo (RSA) but keeps others (MD5)');
  const allowRisk = scanFiles([{ name: 'a.js', text: 'RSA.gen(); ECDSA.sign();' }], { ignoreAlgos: ['quantum-broken'] });
  ok(allowRisk.summary.quantum_broken === 0 && allowRisk.summary.suppressed >= 2, 'allowlist by risk CLASS drops the whole class (quantum-broken) and counts it');

  console.log('pqcbom self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqcbom\.mjs$/.test(process.argv[1] || '')) selfTest();
