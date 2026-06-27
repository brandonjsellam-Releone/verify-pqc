/*!
 * gen-sample-pack — produces a SAMPLE (demo) signed PQC Migration Evidence Pack for sales/landing use.
 * Uses a DEMO signing key (deterministic seed — NOT a production key). Run: node gen-sample-pack.mjs
 */
import { scanFiles } from './pqcbom.mjs';
import { buildEvidencePack, signEvidencePack, verifyEvidencePack } from './pqcbom-report.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { writeFileSync, mkdirSync } from 'fs';

const OUT = 'C:/Users/User/OneDrive - releone llc/Desktop/New folder/program/products/sample-evidence-pack';
mkdirSync(OUT, { recursive: true });

// A realistic "legacy app mid-migration" codebase — mix of quantum-broken, weak, and already-PQ crypto.
const files = [
  { name: 'auth/legacy.js', text: 'const kp = RSA.generateKeyPair(2048); const sig = ECDSA.sign(msg, "secp256k1"); const h = MD5(password);' },
  { name: 'tls/nginx.conf', text: 'ssl_protocols TLSv1.1 TLSv1.2; ssl_ciphers HIGH; # AES-128 + ECDHE-RSA' },
  { name: 'api/jwt.js', text: 'jwt.verify(token, key, { algorithms: ["RS256"] });' },
  { name: 'package.json', text: '{"dependencies":{"node-forge":"^1.3.1","crypto-js":"^4.2.0","@noble/post-quantum":"^0.6.1"}}' },
  { name: 'infra/sshd_config', text: 'HostKey ssh-rsa\nKexAlgorithms sntrup761x25519-sha512@openssh.com' },
  { name: 'pq/handshake.mjs', text: 'kex = ML-KEM-1024; sig = ML-DSA-87; aead = AES-256-GCM; hash = SHA-512;' },
  { name: 'storage/blob.go', text: 'aead := AES-256-GCM; kdf := HKDF-SHA-256; legacy := 3DES;' },
];
const scan = scanFiles(files, { gradeContext: 'code' });
// DEMO signers — deterministic seeds, clearly NOT production keys. The sample is HYBRID dual-signed
// (ML-DSA-87 ∧ SLH-DSA-256f) to showcase the apex defense-in-depth posture.
const demo = ml_dsa87.keygen(new Uint8Array(32).fill(123));
const demoSlh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(124));
const pack = buildEvidencePack({ scan, meta: { org: 'SAMPLE — Acme Fintech (demo, not a real client)', scope: 'TLS + auth + storage', generated_ts: 1782000000 } });
const signed = signEvidencePack(pack, demo.secretKey, demo.publicKey, { slhdsa: demoSlh });
const v = verifyEvidencePack(signed, demo.publicKey, { trustedSlhPub: demoSlh.publicKey });

writeFileSync(OUT + '/SAMPLE_Evidence_Pack.md', signed.markdown);
writeFileSync(OUT + '/SAMPLE_Evidence_Pack.signed.json', JSON.stringify(signed, null, 2));
console.log('grade=' + signed.grade.letter + ' (' + signed.grade.score + ')  verified=' + v.verified + '  hybrid=' + v.hybrid + '  slhValid=' + v.slhValid + '  trustAnchored=' + v.trustAnchored);
console.log('findings=' + scan.findings.length + '  files=' + scan.summary.files_scanned + '  ML-DSA=' + bytesToHex(demo.publicKey).slice(0, 16) + '…  SLH=' + bytesToHex(demoSlh.publicKey).slice(0, 16) + '…');
console.log('wrote SAMPLE_Evidence_Pack.md + .signed.json → ' + OUT);
