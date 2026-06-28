/*!
 * pqcbom — Cryptographic Bill of Materials scanner + quantum-readiness grader (reference, DRAFT, standalone).
 *
 * THE revenue + viral product (unanimous council): scan code/config for cryptography, classify quantum risk,
 * emit a CycloneDX-style CBOM + an A–F "Quantum-Safe Scorecard". Free tier = the shareable badge (viral funnel,
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
 * Self-test: node pqcbom.mjs
 */
const RULES = [
  // classically broken (a bug regardless of quantum)
  { re: /\bMD5\b/i, algo: 'MD5', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' },
  { re: /\bSHA-?1\b/i, algo: 'SHA-1', family: 'hash', risk: 'broken-classical', rec: 'REMOVE — collision-broken; use SHA-512 / SHA3-512' },
  { re: /\bRC4\b/i, algo: 'RC4', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM / ChaCha20-Poly1305' },
  { re: /\b(3DES|Triple-?DES|DESede|DES-(EDE3?|CBC|ECB|OFB|CFB)|DES(?![\w-]))/i, algo: '3DES/DES', family: 'cipher', risk: 'broken-classical', rec: 'REMOVE; use AES-256-GCM' }, // bare DES + DESede + DES modes; DES(?![\w-]) so "DES-less"/"description" are NOT matched (council + self-test guard)
  // quantum-broken (Shor): public-key
  { re: /\bRSA(SSA|ES)?\b|RSA-?(1024|2048|3072|4096)|PKCS#?1\b/i, algo: 'RSA', family: 'pubkey', risk: 'quantum-broken', rec: 'migrate KEM->ML-KEM-1024, sig->ML-DSA-87 (hybrid during transition)' }, // PKCS#?1\b so PKCS#11 (HSM) is NOT matched; +RSASSA/RSAES (council)
  { re: /(?<![\w-])DSA(?![\w-])/i, algo: 'DSA', family: 'signature', risk: 'quantum-broken', rec: 'migrate to ML-DSA-87 / SLH-DSA' }, // not preceded/followed by word-char or '-' so ML-DSA/SLH-DSA/ECDSA are NOT matched
  { re: /\bECDSA\b/i, algo: 'ECDSA', family: 'signature', risk: 'quantum-broken', rec: 'migrate to ML-DSA-87 (keep ECDSA only as a HYBRID leg)' },
  { re: /\bECDHE?\b|\bECIES\b/i, algo: 'ECDH', family: 'kem', risk: 'quantum-broken', rec: 'migrate to ML-KEM-1024 (+ X25519 in HYBRID)' }, // +ECDHE (council)
  { re: /\b(secp(224|256|384|521)(r1|k1)|prime256v1|P-(224|256|384|521)|brainpool)\b/i, algo: 'EC curve', family: 'pubkey', risk: 'quantum-broken', rec: 'EC curve is Shor-broken; move to ML-KEM/ML-DSA (hybrid)' }, // +secp384r1/521r1/224r1, P-224 (council)
  { re: /\b(Diffie-?Hellman|DHE|DH-(group|modp))\b/i, algo: 'finite-field DH', family: 'kem', risk: 'quantum-broken', rec: 'migrate to ML-KEM-1024' }, // +DHE ephemeral (council)
  // classical curves — quantum-broken alone, but valid as the CLASSICAL leg of a hybrid
  { re: /\b(X25519|X448|Curve25519)\b/i, algo: 'X25519/X448', family: 'kem', risk: 'classical-hybrid-ok', rec: 'OK only inside a HYBRID with ML-KEM-768/1024' },
  { re: /\b(Ed25519|Ed448)\b/i, algo: 'Ed25519/Ed448', family: 'signature', risk: 'classical-hybrid-ok', rec: 'OK only inside a HYBRID with ML-DSA-87' },
  // quantum-weakened (Grover halves the security level)
  { re: /\bAES-?(128|192)\b/i, algo: 'AES-128/192', family: 'cipher', risk: 'quantum-weakened', rec: 'use AES-256 (Grover halves the key strength)' },
  { re: /\bSHA-?256\b|\bSHA3-?256\b|\bSHA-?384\b|\bSHA3-?384\b/i, algo: 'SHA-256/384', family: 'hash', risk: 'quantum-weakened', rec: 'use SHA-512 / SHA3-512 for >=256-bit quantum security' }, // +SHA3-384 (council)
  // quantum-safe
  { re: /\b(ML-KEM|ml_kem|Kyber|HQC|BIKE)\b/i, algo: 'ML-KEM/Kyber', family: 'kem', risk: 'quantum-safe', rec: 'OK — NIST FIPS 203' },
  { re: /\b(ML-DSA|ml_dsa|Dilithium)\b/i, algo: 'ML-DSA/Dilithium', family: 'signature', risk: 'quantum-safe', rec: 'OK — NIST FIPS 204' },
  { re: /\b(SLH-DSA|slh_dsa|SPHINCS)\b/i, algo: 'SLH-DSA/SPHINCS+', family: 'signature', risk: 'quantum-safe', rec: 'OK — NIST FIPS 205' },
  { re: /\b(Falcon|FN-DSA)\b/i, algo: 'Falcon/FN-DSA', family: 'signature', risk: 'quantum-safe', rec: 'OK — draft FIPS 206 (diversity/on-chain leg)' },
  { re: /\bAES-?256\b/i, algo: 'AES-256', family: 'cipher', risk: 'quantum-safe', rec: 'OK — 256-bit (128-bit quantum)' },
  { re: /\b(SHA-?512|SHA3-?512|SHAKE-?256)\b/i, algo: 'SHA-512/SHA3-512', family: 'hash', risk: 'quantum-safe', rec: 'OK' },
  { re: /\bChaCha20(-?Poly1305)?\b/i, algo: 'ChaCha20-Poly1305', family: 'cipher', risk: 'quantum-safe', rec: 'OK — 256-bit stream AEAD' },
  // --- v0.2 expanded coverage: protocols, JWT/JOSE, SSH, managed crypto, more PQ KEMs ---
  { re: /\b(SSLv?[23]|TLSv?-?1\.[01]|TLSv?1(?![.\d]))/i, algo: 'TLS<1.2 / SSL', family: 'protocol', risk: 'broken-classical', rec: 'REMOVE deprecated TLS/SSL; require TLS 1.2+ (1.3 preferred)' }, // TLSv?1(?![.\d]) so TLS 1.2/1.3 do NOT false-positive (council: both seats)
  { re: /\balg["'\s:=]{1,4}none\b/i, algo: 'JWT alg=none', family: 'token', risk: 'broken-classical', rec: 'CRITICAL — unsigned JWT; never accept alg:none' },
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
  { re: /\b(rustls|ring)\b/i, algo: 'lib:rustls/ring', risk: 'classical-hybrid-ok', rec: 'Rust TLS/crypto — verify TLS 1.3 + plan a PQ KEM' },
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

// A–F Quantum-Safe Scorecard (the viral badge) + a 0–100 score
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
  const labels = { A: 'Quantum-safe', B: 'Quantum-weakened (Grover)', C: 'Migrating (hybrid present)', D: 'Quantum-vulnerable — migrate', F: 'Critical — broken crypto in use' };
  return { letter, score, label: labels[letter], badge: 'Quantum-Safe: ' + letter };
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
  ok(algos('hash = SHA3-384').has('SHA-256/384'), 'SHA3-384 is caught (quantum-weakened)');
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
