/*!
 * accuracy-benchmark — measures the scanner's precision/recall against a LABELED ground-truth corpus of the cases that
 * actually matter (true positives + the known false-positive traps the council/red-team surfaced). Produces hard
 * numbers (P/R/F1) + writes BENCHMARK.md. Exits non-zero on ANY labeled false-positive or false-negative (regression).
 *
 * HONEST FRAMING: this is a SELF-ASSESSMENT against a corpus WE publish (below), not an independent third-party
 * benchmark on real-world repositories. It is falsifiable (the corpus is right here — critique it). An external
 * benchmark on real codebases (OpenSSL/libsodium/…) with a ground-truth inventory is future work + an audit deliverable.
 *
 * Run: node accuracy-benchmark.mjs
 */
import { scanText } from './pqcbom.mjs';
import { writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// each case: text + `find` (algo labels that MUST be detected) + `notFind` (labels that MUST NOT be — false-positive traps)
const CORPUS = [
  // --- true positives: quantum-broken / broken-classical ---
  { id: 'rsa', text: 'const k = RSA.generateKey(2048);', find: ['RSA'], notFind: [] },
  { id: 'ecdsa', text: 'ECDSA.sign(m, "secp256k1");', find: ['ECDSA', 'EC curve'], notFind: [] },
  { id: 'md5', text: 'const h = MD5(password);', find: ['MD5'], notFind: [] },
  { id: 'sha1', text: 'digest = SHA1(x);', find: ['SHA-1'], notFind: [] },
  { id: 'des-real', text: 'cipher := DES-CBC;', find: ['3DES/DES'], notFind: [] },
  { id: '3des', text: 'legacy = 3DES;', find: ['3DES/DES'], notFind: [] },
  { id: 'rc4', text: 'stream = RC4;', find: ['RC4'], notFind: [] },
  { id: 'tls-old', text: 'ssl_protocols TLSv1.0;', find: ['TLS<1.2 / SSL'], notFind: [] },
  { id: 'sslv3', text: 'SSLv3 enabled', find: ['TLS<1.2 / SSL'], notFind: [] },
  { id: 'jwt-none', text: 'header = { alg: "none" }', find: ['JWT alg=none'], notFind: [] },
  { id: 'jwt-rs256', text: 'jwt.verify(t, k, { algorithms: ["RS256"] });', find: ['JWT RSA (RS/PS)'], notFind: [] },
  { id: 'ssh-rsa', text: 'HostKey ssh-rsa', find: ['SSH RSA/DSA/ECDSA key'], notFind: [] },
  { id: 'ssh-dss', text: 'HostKey ssh-dss', find: ['SSH RSA/DSA/ECDSA key'], notFind: [] },
  { id: 'dhe', text: 'KEX = DHE-RSA', find: ['finite-field DH', 'RSA'], notFind: [] },
  // --- true positives: quantum-weakened ---
  { id: 'aes128', text: 'AES-128-CBC', find: ['AES-128/192'], notFind: ['AES-256'] },
  { id: 'sha256', text: 'hash = SHA-256', find: ['SHA-256/384'], notFind: [] },
  // --- true positives: classical-hybrid-ok ---
  { id: 'x25519', text: 'kex = X25519', find: ['X25519/X448'], notFind: [] },
  { id: 'ed25519', text: 'sig = Ed25519', find: ['Ed25519/Ed448'], notFind: [] },
  // --- true positives: quantum-safe (recognized as already-migrated) ---
  { id: 'mlkem', text: 'kem = ML-KEM-1024', find: ['ML-KEM/Kyber'], notFind: [] },
  { id: 'aes256', text: 'aead = AES-256-GCM', find: ['AES-256'], notFind: ['AES-128/192'] },
  { id: 'sha512', text: 'kdf = HKDF-SHA-512', find: ['SHA-512/SHA3-512'], notFind: [] },
  { id: 'chacha', text: 'ChaCha20-Poly1305', find: ['ChaCha20-Poly1305'], notFind: [] },
  { id: 'sntrup', text: 'KexAlgorithms sntrup761x25519-sha512@openssh.com', find: ['sntrup761 (SSH PQ KEX)'], notFind: [] },
  // --- true positives: OID layer (v0.4 — certs/ASN.1/PKI name crypto by numeric OID, not by algorithm name) ---
  { id: 'rsa-by-oid', text: 'keyAlgorithm = "1.2.840.113549.1.1.1"', find: ['RSA (OID rsaEncryption)'], notFind: [] },
  { id: 'ecdsa-by-oid', text: 'signatureAlgorithm: 1.2.840.10045.4.3.2', find: ['ECDSA sig (OID)'], notFind: [] },
  { id: 'p256-by-oid', text: 'namedCurve 1.2.840.10045.3.1.7', find: ['P-256/prime256v1 curve (OID)'], notFind: [] },
  { id: 'md5-by-oid', text: 'digestAlgorithm 1.2.840.113549.2.5', find: ['MD5 (OID)'], notFind: [] },
  // --- true positives: encoded-blob layer (v0.5 — base64/PEM key+cert blobs, algorithm by decoded DER OID) ---
  { id: 'encoded-rsa', text: 'pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A";', find: ['RSA (encoded/PEM)'], notFind: [] },
  // --- FALSE-POSITIVE TRAPS (the hard part — these must NOT mis-fire) ---
  { id: 'mldsa-not-dsa', text: 'sig = ML-DSA-87', find: ['ML-DSA/Dilithium'], notFind: ['DSA'] },
  { id: 'slhdsa-not-dsa', text: 'use SLH-DSA for diversity', find: ['SLH-DSA/SPHINCS+'], notFind: ['DSA'] },
  { id: 'tls13-not-flagged', text: 'ssl_protocols TLSv1.2 TLSv1.3;', find: [], notFind: ['TLS<1.2 / SSL'] },
  { id: 'pkcs11-not-rsa', text: 'PKCS#11 with CloudHSM', find: ['managed KMS/HSM'], notFind: ['RSA'] },
  { id: 'des-less', text: 'we ship a DES-less design now', find: [], notFind: ['3DES/DES'] },
  { id: 'description', text: 'this is a description of the system', find: [], notFind: ['3DES/DES'] },
  { id: 'aes256-not-128', text: 'AES-256-GCM only', find: ['AES-256'], notFind: ['AES-128/192'] },
];

// BLIND SPOTS — cases a LEXICAL scanner is EXPECTED to miss (this is WHY findings are "leads to verify"). We verify
// they are indeed not detected, and publish them as documented limitations rather than pretending 100% coverage.
// (v0.4: the former 'rsa-by-oid' blind spot is CLOSED — OID detection was added; it is now a true-positive corpus case above.)
const BLIND_SPOTS = [
  { id: 'rsa-substring', text: 'const k = rsaEncryption(2048);', why: 'algorithm embedded in a longer identifier (no word boundary)' },
  { id: 'custom-wrapper', text: 'const sig = companyCryptoSign(payload);', why: 'crypto hidden behind a custom wrapper name' },
  { id: 'runtime-alias', text: 'const C = loadCipher(cfg); C.encrypt(x);', why: 'algorithm resolved at runtime via a variable' },
  // (v0.5: 'encoded-key' CLOSED — base64/PEM blobs are now decoded + identified by DER OID; moved to a true-positive case above.)
];

export function run() {
  let TP = 0, FP = 0, FN = 0, TN = 0;
  const failures = [];
  for (const c of CORPUS) {
    const found = new Set(scanText('case.txt', c.text).map((f) => f.algo));
    for (const a of c.find) { if (found.has(a)) TP++; else { FN++; failures.push(`${c.id}: MISSED "${a}" (false negative)`); } }
    for (const a of c.notFind) { if (found.has(a)) { FP++; failures.push(`${c.id}: WRONGLY found "${a}" (false positive)`); } else TN++; }
  }
  const precision = TP / (TP + FP || 1), recall = TP / (TP + FN || 1);
  const f1 = 2 * precision * recall / (precision + recall || 1);
  const pct = (x) => (x * 100).toFixed(1) + '%';

  // blind spots: confirm the documented limitations are indeed not detected (honest "we do NOT detect")
  const blind = BLIND_SPOTS.map((b) => {
    const hits = scanText('b.txt', b.text).map((f) => f.algo);
    return { ...b, detected: hits.length > 0, hits };
  });
  const confirmedBlind = blind.filter((b) => !b.detected).length;

  const md = [
    '# Scanner Accuracy Benchmark (self-assessment)',
    '',
    '> **Honest framing:** this measures the scanner against a **labeled ground-truth corpus we publish in `accuracy-benchmark.mjs`** — true positives plus the false-positive traps a multi-model red-team surfaced (e.g. `TLSv1.3` must not be flagged; `ML-DSA`/`SLH-DSA` must not trip the legacy `DSA` rule; `PKCS#11` must not trip `RSA`; `DES-less` must not trip `DES`). It is **not** an independent third-party benchmark on real-world repositories — that is future work and an audit deliverable. The corpus is right here; critique it.',
    '',
    `**Corpus:** ${CORPUS.length} labeled cases · ${TP + FN} positive labels · ${TN + FP} negative (must-not-find) labels.`,
    '',
    '| Metric | Value |',
    '|---|---|',
    `| True positives | ${TP} |`,
    `| False negatives (missed) | ${FN} |`,
    `| False positives (mis-fired) | ${FP} |`,
    `| True negatives (correctly not flagged) | ${TN} |`,
    `| **Precision** | **${pct(precision)}** |`,
    `| **Recall** | **${pct(recall)}** |`,
    `| **F1** | **${pct(f1)}** |`,
    '',
    failures.length ? '## Failures\n' + failures.map((f) => '- ' + f).join('\n') : '_No labeled false positives or false negatives on this corpus — i.e. no regressions on the known-hard cases._',
    '',
    '## Documented blind spots (we do NOT claim to detect these)',
    `A lexical scanner cannot see crypto with no recognizable token. ${confirmedBlind}/${BLIND_SPOTS.length} confirmed not detected — this is *why* findings are "leads to verify," not a complete inventory:`,
    '',
    ...blind.map((b) => `- ${b.detected ? '⚠️ unexpectedly detected' : '✓ confirmed blind spot'} — \`${b.id}\`: ${b.why}`),
    '',
    '_A 100% score above means "no regressions on the labeled corpus," NOT "100% accurate in the wild" — the blind spots are real and listed. An independent benchmark on real-world repos (with a ground-truth inventory) is future work + an audit deliverable._',
    '',
    '_Reproduce: `node accuracy-benchmark.mjs`. A two-layer lexical + dependency scan; findings are leads to verify, not a complete inventory. SDK is an unaudited reference implementation._',
  ].join('\n');

  const here = dirname(fileURLToPath(import.meta.url));
  writeFileSync(join(here, '..', '..', '..', 'program', 'products', 'BENCHMARK.md'), md);
  console.log(`accuracy-benchmark: precision ${pct(precision)} · recall ${pct(recall)} · F1 ${pct(f1)} · ${failures.length} labeled error(s) · ${CORPUS.length} cases · ${confirmedBlind}/${BLIND_SPOTS.length} blind spots confirmed`);
  if (failures.length) failures.forEach((f) => console.error('  FAIL: ' + f));
  if (typeof process !== 'undefined' && process.exit) process.exit(failures.length ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /accuracy-benchmark\.mjs$/.test(process.argv[1] || '')) run();
