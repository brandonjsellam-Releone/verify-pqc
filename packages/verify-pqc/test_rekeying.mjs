import { omegaIdentity, establishSession } from './omega-nexus.mjs';
import { initAlice, initBob, newBobPrekeys, ratchetEncrypt, ratchetDecrypt } from './pqratchet.mjs';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

const idSeed = (id) => sha256(utf8ToBytes('test:' + id)).slice(0, 32);

const alice = omegaIdentity(idSeed('alice'));
const bob = omegaIdentity(idSeed('bob'));

console.log('=== Testing that ratchet keys are properly separated ===\n');

const sess = establishSession(alice, bob, { trustedIkSigPub: bob.sig.publicKey });
let A = sess.aliceState;
let B = sess.bobState;

// Alice and Bob exchange messages
const m1 = ratchetEncrypt(A, 'msg1');
console.log('Alice msg1:');
console.log('  DHs:', m1.header.dh.substring(0, 16) + '...');
console.log('  PN (previous message count):', m1.header.pn);
console.log('  N (this message #):', m1.header.n);

ratchetDecrypt(B, m1);
console.log('\nBob decrypts msg1 (DHs seen, CKr seeded, new DHs generated)');

const m2 = ratchetEncrypt(B, 'msg2');
console.log('\nBob msg2 (reply):');
console.log('  DHs:', m2.header.dh.substring(0, 16) + '...');
console.log('  PN (Alice\'s previous count):', m2.header.pn);
console.log('  N (this message #):', m2.header.n);
console.log('  PN changed? Expected 1 (Alice sent 1 message)', m2.header.pn === 1 ? '✓' : '✗');

ratchetDecrypt(A, m2);
console.log('\nAlice decrypts msg2 (ratchets forward with Bob\'s DHs)');

// Check state separation
console.log('\n=== State separation check ===');
console.log('After 1 message each:');
console.log('  A.DHs === B.DHs?', 
  A.DHs.pub.toString() === B.DHs.pub.toString() ? 'SAME (ERROR!)' : 'DIFFERENT (correct)');
console.log('  A.DHr === B.DHr?',
  A.DHr.toString() === B.DHr.toString() ? 'SAME (ERROR!)' : 'DIFFERENT (correct)');
console.log('  A.CKs === B.CKs?',
  A.CKs.toString() === B.CKs.toString() ? 'SAME (ERROR!)' : 'DIFFERENT (correct)');
console.log('  A.CKr === B.CKr?',
  A.CKr.toString() === B.CKr.toString() ? 'SAME (ERROR!)' : 'DIFFERENT (correct)');

console.log('\nMessage encryption is separate:');
console.log('  m1 ciphertext:', m1.ct.substring(0, 20) + '...');
console.log('  m2 ciphertext:', m2.ct.substring(0, 20) + '...');
console.log('  Same?', m1.ct === m2.ct ? 'SAME (ERROR!)' : 'DIFFERENT (correct)');
