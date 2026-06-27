import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// Confirm noble ML-DSA actually binds context (different context -> verify fails)
const kp = ml_dsa87.keygen(new Uint8Array(32).fill(1));
const msg = utf8ToBytes('hello');
const ctxA = utf8ToBytes('trelyan-pqcbom-evidence-pack-v1');
const ctxB = utf8ToBytes('trelyan-pqcompliance-report-v1');
const sig = ml_dsa87.sign(msg, kp.secretKey, { context: ctxA });
console.log('same-ctx verify:', ml_dsa87.verify(sig, msg, kp.publicKey, { context: ctxA }), '(expect true)');
console.log('cross-ctx verify:', ml_dsa87.verify(sig, msg, kp.publicKey, { context: ctxB }), '(expect false = domain sep works)');
console.log('no-ctx verify of ctxA sig:', ml_dsa87.verify(sig, msg, kp.publicKey), '(expect false)');
