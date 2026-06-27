/*!
 * kat-conformance — deterministic KNOWN-ANSWER vectors for the apex PQC suite (ML-KEM-1024 / ML-DSA-87 /
 * SLH-DSA-SHAKE-256s). Seed-pinned: fixed seeds + fixed extraEntropy → deterministic keygen/sign/encaps,
 * frozen to expected SHA-256 digests (+ the ML-KEM shared secret in full). Catches ANY implementation drift /
 * version regression in @noble's FIPS-mode output.
 *
 * HONEST SCOPE: this pins OUR engine's deterministic output (regression + cross-machine reproducibility); it is
 * NOT the official NIST ACVP test vectors. To cross-validate against NIST, drop the usnistgov/ACVP-Server JSON
 * vectors in and assert encaps/sign/verify against them (owner step — large external files). Self-test: node kat-conformance.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { slh_dsa_shake_256s as slh } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

const H = (b) => bytesToHex(sha256(b));
const MSG = utf8ToBytes('TRELYAN-KAT-v1');
const E32 = new Uint8Array(32); // fixed all-zero extraEntropy -> deterministic signing

const KAT = {
  mldsa: { seed: 11, pk: '06a38ef5ca39ef4724673c358bfe7ce7ecffb0a51485ef18c9e1cdb2aae16e50', sk: '92bbac1b4961828dd3279cf7ff8372a7cb25cd92ba2adb73e8cc91a65948f37e', sig: '23d1fcfba36b329637f8a348aa05fdd3eb8f315b066181081c80affb1b90f352' },
  mlkem: { kseed: 22, eseed: 33, pk: '568af780827e49d684ddffd71fc0e0ce948c8795efdad6758630df0105da60d0', sk: '834f1a3030ea664c089fb23274da1353ca337a105bc9998b1af553ea30e771fc', ct: '6fbe64380fc4b7be480a07893ae2346ef5913991226e3a54282ef82503a83180', ss: '389f3f350e5f6c5d323aa491c5e423031c0070fecd1045c33c31d82d19c76356' },
  slh: { seed: 44, pk: '943770826c1951c56be1398fbac3f9720328911064a9cbbbe7a79b7968ddde89', sk: 'a1f4fdfba66589ea4a80f4602008d3275a05bf8d2e7745c4d3b5450fcd133a3b', sig: '2a10a2749f8b5c5e769c33b8a05b91479441e7d57d7b9910aec96e6a4483c7cc' },
};

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // ML-DSA-87 KAT
  const d = ml_dsa87.keygen(new Uint8Array(32).fill(KAT.mldsa.seed));
  ok(H(d.publicKey) === KAT.mldsa.pk && H(d.secretKey) === KAT.mldsa.sk, 'ML-DSA-87 keygen(seed) matches pinned KAT pk/sk');
  const dsig = ml_dsa87.sign(MSG, d.secretKey, { extraEntropy: E32 });
  ok(H(dsig) === KAT.mldsa.sig, 'ML-DSA-87 deterministic sign matches pinned KAT signature');
  ok(ml_dsa87.verify(dsig, MSG, d.publicKey) === true, 'ML-DSA-87 KAT signature verifies');
  const dbad = dsig.slice(); dbad[100] ^= 1;
  ok(ml_dsa87.verify(dbad, MSG, d.publicKey) === false, 'ML-DSA-87 flipped signature -> verify false');

  // ML-KEM-1024 KAT
  const k = ml_kem1024.keygen(new Uint8Array(64).fill(KAT.mlkem.kseed));
  ok(H(k.publicKey) === KAT.mlkem.pk && H(k.secretKey) === KAT.mlkem.sk, 'ML-KEM-1024 keygen(seed) matches pinned KAT pk/sk');
  const enc = ml_kem1024.encapsulate(k.publicKey, new Uint8Array(32).fill(KAT.mlkem.eseed));
  ok(H(enc.cipherText) === KAT.mlkem.ct && bytesToHex(enc.sharedSecret) === KAT.mlkem.ss, 'ML-KEM-1024 deterministic encaps matches pinned KAT ct + shared secret');
  ok(bytesToHex(ml_kem1024.decapsulate(enc.cipherText, k.secretKey)) === KAT.mlkem.ss, 'ML-KEM-1024 decaps recovers the pinned shared secret');

  // SLH-DSA-SHAKE-256s KAT
  const s = slh.keygen(new Uint8Array(96).fill(KAT.slh.seed));
  ok(H(s.publicKey) === KAT.slh.pk && H(s.secretKey) === KAT.slh.sk, 'SLH-DSA-SHAKE-256s keygen(seed) matches pinned KAT pk/sk');
  const ssig = slh.sign(MSG, s.secretKey, { extraEntropy: E32 });
  ok(H(ssig) === KAT.slh.sig, 'SLH-DSA-SHAKE-256s deterministic sign matches pinned KAT signature');
  ok(slh.verify(ssig, MSG, s.publicKey) === true, 'SLH-DSA-SHAKE-256s KAT signature verifies');

  console.log('kat-conformance self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /kat-conformance\.mjs$/.test(process.argv[1] || '')) selfTest();
