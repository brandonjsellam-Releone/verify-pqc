/*!
 * sandbox-parity — drift-guard for the PQ Trust Sandbox's "same scoring engine as the SDK" claim.
 *
 * website/v2/sandbox.html ships a faithful in-browser JS PORT of pqshield's baseRisk/scoreAsset/aggregate (pure
 * functions, no crypto deps) so a visitor gets an instant A–F grade. The risk: pqshield's model evolves and the
 * browser port silently diverges, making the public "same engine as the SDK" claim false. This pins pqshield's grade
 * on each sandbox SAMPLE estate; if pqshield's model changes such that a sample's grade changes, THIS FAILS — update
 * sandbox.html's port + this test together. (The SAMPLES below MUST mirror website/v2/sandbox.html SAMPLES verbatim.)
 *
 * Self-test: node sandbox-parity.mjs
 */
import { createShieldReport } from './pqshield.mjs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const issuer = { ed: { secretKey: new Uint8Array(32).fill(1), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(1)) }, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(2)) };

// ⚠️ MUST mirror website/v2/sandbox.html `SAMPLES` verbatim.
const SAMPLES = {
  vuln: [
    { label: 'edge-tls', algorithm: 'RSA-2048', internet_facing: true, sensitive: true }, // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
    { label: 'vpn-gw', algorithm: 'ECDH-P256', internet_facing: true }, // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
    { label: 'code-signing', algorithm: 'RSA-4096' }, // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
    { label: 'legacy-api', algorithm: '3DES', sensitive: true, long_retention: true }, // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
    { label: 'svc-mesh', algorithm: 'Ed25519', internet_facing: true },
  ],
  mixed: [
    { label: 'edge-tls', algorithm: 'HYBRID-X25519-ML-KEM-768', internet_facing: true, sensitive: true },
    { label: 'vpn-gw', algorithm: 'HYBRID-X25519-ML-KEM-768', internet_facing: true },
    { label: 'data-at-rest', algorithm: 'AES-256' },
    { label: 'code-signing', algorithm: 'RSA-2048' }, // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
  ],
  pq: [
    { label: 'edge-tls', algorithm: 'HYBRID-X25519-ML-KEM-1024', internet_facing: true, sensitive: true },
    { label: 'signing', algorithm: 'ML-DSA-87' },
    { label: 'data-at-rest', algorithm: 'AES-256' },
    { label: 'archive', algorithm: 'SLH-DSA-256f', long_retention: true },
  ],
};
// the grades the sandbox demonstrates (the F→D→A migration arc). Pinned.
const EXPECT = { vuln: 'F', mixed: 'D', pq: 'A' };

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  for (const [k, assets] of Object.entries(SAMPLES)) {
    const r = createShieldReport({ issuerKeys: issuer, target: k, assets, generatedAt: 1 });
    ok(r.grade === EXPECT[k], `sandbox sample "${k}": pqshield grade=${r.grade} (expected ${EXPECT[k]}) — "same engine as the SDK" holds`);
  }
  console.log('sandbox-parity: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /sandbox-parity\.mjs$/.test(process.argv[1] || '')) selfTest();
