/*!
 * fips-conformance — asserts the FIPS 203/204/205 operational properties on TRELYAN's ACTUAL @noble usage.
 * Turns the corpus deep-read corrections (hedged ML-DSA default, exact sizes, ML-KEM implicit rejection,
 * length-rejection on verify) from "should hold" into TESTED facts. Self-test: node fips-conformance.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { slh_dsa_shake_256s as slh256s } from '@noble/post-quantum/slh-dsa.js';
import { randomBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

const eq = (a, b) => bytesToHex(a) === bytesToHex(b);
// the SDK's verify pattern everywhere: any malformed/wrong-length input -> false, never an uncaught throw.
const safeVerifyDsa = (sig, msg, pk, ctx) => { try { return ml_dsa87.verify(sig, msg, pk, ctx); } catch { return false; } };

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // FIPS 204 — ML-DSA-87 (Category 5) exact sizes
  const k = ml_dsa87.keygen(new Uint8Array(32).fill(1));
  ok(k.publicKey.length === 2592 && k.secretKey.length === 4896, 'FIPS 204: ML-DSA-87 pk=2592, sk=4896');
  const msg = utf8ToBytes('conformance');
  const s1 = ml_dsa87.sign(msg, k.secretKey);
  ok(s1.length === 4627, 'FIPS 204: ML-DSA-87 signature = 4627 bytes');

  // FIPS 204 §3.4 — HEDGED signing is the default: two signatures of the same message DIFFER, and both verify.
  const s2 = ml_dsa87.sign(msg, k.secretKey);
  ok(!eq(s1, s2), 'FIPS 204: ML-DSA signing is HEDGED by default (two sigs of the same message differ)');
  ok(ml_dsa87.verify(s1, msg, k.publicKey) && ml_dsa87.verify(s2, msg, k.publicKey), 'both hedged signatures verify');

  // FIPS 204 §3.6.2 — verify MUST reject malformed/wrong-length inputs (our wrappers -> false, no uncaught throw)
  ok(safeVerifyDsa(s1.slice(0, -1), msg, k.publicKey) === false, 'wrong-length signature -> verify false (not accepted, not thrown)');
  ok(safeVerifyDsa(s1, msg, k.publicKey.slice(0, -1)) === false, 'wrong-length public key -> verify false');
  // context separation: a sig made under a context must NOT verify without it
  const sc = ml_dsa87.sign(msg, k.secretKey, { context: utf8ToBytes('ctx-A') });
  ok(ml_dsa87.verify(sc, msg, k.publicKey, { context: utf8ToBytes('ctx-A') }) === true && safeVerifyDsa(sc, msg, k.publicKey) === false, 'FIPS 204 ctx: sig under a context fails without the matching context');

  // FIPS 203 — ML-KEM-1024 exact sizes + IMPLICIT REJECTION (corrupt ct -> no throw, pseudorandom ss, constant-time)
  const kk = ml_kem1024.keygen();
  ok(kk.publicKey.length === 1568 && kk.secretKey.length === 3168, 'FIPS 203: ML-KEM-1024 ek=1568, dk=3168');
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(kk.publicKey);
  ok(cipherText.length === 1568 && sharedSecret.length === 32, 'FIPS 203: ML-KEM-1024 ct=1568, ss=32');
  const bad = cipherText.slice(); bad[0] ^= 1; // corrupt one byte (same length)
  let implicit = false, ssBad = null;
  try { ssBad = ml_kem1024.decapsulate(bad, kk.secretKey); implicit = true; } catch { implicit = false; }
  ok(implicit && ssBad && ssBad.length === 32 && !eq(ssBad, sharedSecret), 'FIPS 203: corrupted ciphertext -> IMPLICIT REJECTION (no throw; different 32-byte ss)');

  // FIPS 205 — SLH-DSA-256s (hash-based diversity leg) exact sizes
  const sk = slh256s.keygen();
  ok(sk.publicKey.length === 64, 'FIPS 205: SLH-DSA-256s pk = 64 bytes');
  ok(slh256s.sign(msg, sk.secretKey).length === 29792, 'FIPS 205: SLH-DSA-256s signature = 29792 bytes');

  console.log('fips-conformance self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /fips-conformance\.mjs$/.test(process.argv[1] || '')) selfTest();
