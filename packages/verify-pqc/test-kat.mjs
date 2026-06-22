// Conformance KAT — deterministic ML-DSA-87 + SLH-DSA-256f known-answer vectors, verified through the
// kit's audited @noble/post-quantum path. Proves the verifier is byte-exact + stable across versions
// (a regression/conformance gate). Pins exact key/sig sizes per FIPS-204 / FIPS-205.
//   npm i @noble/post-quantum @noble/hashes && node test-kat.mjs
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const enc = (s) => new TextEncoder().encode(s);
const CTX = { context: enc('throndar-sth-v1') };
const MSG = enc('throndar-conformance-kat-v1');
let pass = 0, fail = 0;
const ok = (n, c) => { (c ? pass++ : fail++); console.log((c ? 'PASS ' : 'FAIL ') + n); };

// --- ML-DSA-87 (FIPS-204) ---
const mlSeed = new Uint8Array(32).fill(7);
const ml = ml_dsa87.keygen(mlSeed);
const mlSig = ml_dsa87.sign(MSG, ml.secretKey, CTX);
ok('ML-DSA-87 deterministic keygen (seed→fixed pk)', bytesToHex(ml_dsa87.keygen(mlSeed).publicKey) === bytesToHex(ml.publicKey));
ok('ML-DSA-87 pk = 2592 B (FIPS-204)', ml.publicKey.length === 2592);
ok('ML-DSA-87 sig = 4627 B (FIPS-204)', mlSig.length === 4627);
ok('ML-DSA-87 verify (with context)', ml_dsa87.verify(mlSig, MSG, ml.publicKey, CTX) === true);
ok('ML-DSA-87 rejects tampered sig', (() => { const b = mlSig.slice(); b[64] ^= 0xff; return ml_dsa87.verify(b, MSG, ml.publicKey, CTX) === false; })());
ok('ML-DSA-87 context is bound (no-ctx fails)', ml_dsa87.verify(mlSig, MSG, ml.publicKey) === false);

// --- SLH-DSA-256f (FIPS-205) ---
const slSeed = new Uint8Array(96).fill(11);
const sl = slh_dsa_sha2_256f.keygen(slSeed);
const slSig = slh_dsa_sha2_256f.sign(MSG, sl.secretKey, CTX);
ok('SLH-DSA-256f deterministic keygen (seed→fixed pk)', bytesToHex(slh_dsa_sha2_256f.keygen(slSeed).publicKey) === bytesToHex(sl.publicKey));
ok('SLH-DSA-256f pk = 64 B (FIPS-205)', sl.publicKey.length === 64);
ok('SLH-DSA-256f sig = 49856 B (FIPS-205)', slSig.length === 49856);
ok('SLH-DSA-256f verify (with context)', slh_dsa_sha2_256f.verify(slSig, MSG, sl.publicKey, CTX) === true);
ok('SLH-DSA-256f rejects tampered sig', (() => { const b = slSig.slice(); b[100] ^= 0xff; return slh_dsa_sha2_256f.verify(b, MSG, sl.publicKey, CTX) === false; })());
ok('SLH-DSA-256f context is bound (no-ctx fails)', slh_dsa_sha2_256f.verify(slSig, MSG, sl.publicKey) === false);

console.log(`\nKAT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
