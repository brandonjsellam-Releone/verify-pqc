/*!
 * POLARSEEK PQ-KMS core — reference implementation (DRAFT, standalone).
 *
 * The Tier-1 "root": post-quantum envelope key-custody. Seals secrets under a HYBRID
 * X25519 + ML-KEM-1024 KEK (HNDL-safe), wraps a per-secret AES-256-GCM data key, and emits an
 * ML-DSA-87-SIGNED custody record (provenance / append-log seed). Crypto-agility via a suite id.
 *
 * THIS IS NEW, SELF-CONTAINED REFERENCE CODE. It does NOT import, touch, or modify the live
 * bridge custody (custody.py) or any production key/secret. Run the self-test:  node polarseek.mjs
 *
 * Primitives: ML-KEM-1024 (FIPS 203) + X25519 hybrid KEM; AES-256-GCM (DEK + key-wrap);
 * ML-DSA-87 (FIPS 204) custody signatures. Combiner is the transcript-bound X-Wing-style form
 * from TRELYAN_PQEF_SPEC §A2 (ML-KEM-1024 needs its own code point — not CFRG X-Wing/768).
 *
 * Design note (council review): custody seals to a LONG-TERM custody key BY DESIGN — secrets must
 * be unsealable later, so this is KMS key-custody, NOT messaging forward-secrecy. The ML-KEM leg
 * provides harvest-now-decrypt-later (HNDL) protection of the wrapped key. Replay/freshness windows
 * and issuer-trust pinning are app-layer responsibilities, not this primitive's.
 */
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { randomBytes, bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

export const SUITE_ID = 'TRLN-KMS-1';
export const SUITE = 'TRLN-KMS-1: X25519+ML-KEM-1024 / AES-256-GCM / ML-DSA-87';
const KEK_LABEL = utf8ToBytes('TRELYAN-KMS-v1-kek');
const CUSTODY_CTX = utf8ToBytes('trelyan-kms-custody-v1');

/* ---------- keys ---------- */
// Custody (recipient) key = the pair secrets are sealed TO. Two components (hybrid).
export function generateCustodyKey() {
  const mk = ml_kem1024.keygen();
  const xPriv = randomBytes(32), xPub = x25519.getPublicKey(xPriv);
  return {
    pub: { mlkem: mk.publicKey, x25519: xPub },
    sec: { mlkem: mk.secretKey, x25519: xPriv },
  };
}
// Authority key = signs custody records (the provenance/attestation root). ML-DSA-87.
export function generateAuthorityKey(seed) { return ml_dsa87.keygen(seed || randomBytes(32)); }

/* ---------- transcript-bound hybrid combiner (PQEF §A2) ---------- */
function deriveKEK(ss_x, ss_m, transcriptParts) {
  const transcript = sha3_256(concatBytes(...transcriptParts));
  // HKDF-Extract(salt=transcript, ikm = ss_x || ss_m) -> Expand(label) -> 32-byte KEK
  return hkdf(sha256, concatBytes(ss_x, ss_m), transcript, KEK_LABEL, 32);
}
function canonRecordCore(r) {
  // fixed key order; signed bytes
  return utf8ToBytes(JSON.stringify({ op: r.op, suite_id: r.suite_id, key_id: r.key_id, envelope_hash: r.envelope_hash, ts: Number(r.ts) }));
}
// Canonical envelope hash (council fix): explicit fixed-order concatenation of the hex fields,
// NOT JSON.stringify (which is key-order fragile). Binds every envelope byte to the custody record.
function envelopeHash(env) {
  return sha256(utf8ToBytes([env.suite_id, env.mlkem_ct, env.x25519_eph, env.wrap_nonce, env.wrapped_dek, env.data_nonce, env.ciphertext].join('|')));
}

/* ---------- seal ---------- */
export function seal(plaintext, custodyPub, authoritySecret, opts = {}) {
  const pt = typeof plaintext === 'string' ? utf8ToBytes(plaintext) : plaintext;
  const dek = randomBytes(32);

  // hybrid encapsulate to custody pub
  const ephPriv = randomBytes(32), ephPub = x25519.getPublicKey(ephPriv);
  const ss_x = x25519.getSharedSecret(ephPriv, custodyPub.x25519);
  const { cipherText: mlkem_ct, sharedSecret: ss_m } = ml_kem1024.encapsulate(custodyPub.mlkem);
  const kek = deriveKEK(ss_x, ss_m, [utf8ToBytes(SUITE_ID), ephPub, mlkem_ct, custodyPub.x25519, custodyPub.mlkem]);

  // wrap DEK under KEK, then encrypt plaintext under DEK (envelope encryption)
  const wrapNonce = randomBytes(12), wrappedDek = gcm(kek, wrapNonce).encrypt(dek);
  const dataNonce = randomBytes(12), ct = gcm(dek, dataNonce).encrypt(pt);

  const envelope = {
    suite_id: SUITE_ID,
    mlkem_ct: bytesToHex(mlkem_ct), x25519_eph: bytesToHex(ephPub),
    wrap_nonce: bytesToHex(wrapNonce), wrapped_dek: bytesToHex(wrappedDek),
    data_nonce: bytesToHex(dataNonce), ciphertext: bytesToHex(ct),
  };
  const record = {
    op: opts.op || 'seal', suite_id: SUITE_ID, key_id: opts.key_id || 'custody-1',
    envelope_hash: bytesToHex(envelopeHash(envelope)), ts: opts.ts ?? Date.now(),
  };
  record.sig = bytesToHex(ml_dsa87.sign(canonRecordCore(record), authoritySecret, { context: CUSTODY_CTX }));
  return { envelope, custody_record: record };
}

/* ---------- unseal ---------- */
export function unseal(envelope, custodySec) {
  if (envelope.suite_id !== SUITE_ID) throw new Error('unknown suite_id: ' + envelope.suite_id);
  const ephPub = hexToBytes(envelope.x25519_eph), mlkem_ct = hexToBytes(envelope.mlkem_ct);
  const ss_x = x25519.getSharedSecret(custodySec.x25519, ephPub);
  const ss_m = ml_kem1024.decapsulate(mlkem_ct, custodySec.mlkem);
  // recompute transcript with the custody PUBLIC parts (derivable from the secret)
  const custodyXPub = x25519.getPublicKey(custodySec.x25519);
  const custodyMlkemPub = deriveMlkemPub(custodySec.mlkem);
  const kek = deriveKEK(ss_x, ss_m, [utf8ToBytes(SUITE_ID), ephPub, mlkem_ct, custodyXPub, custodyMlkemPub]);
  const dek = gcm(kek, hexToBytes(envelope.wrap_nonce)).decrypt(hexToBytes(envelope.wrapped_dek)); // throws on tamper
  return gcm(dek, hexToBytes(envelope.data_nonce)).decrypt(hexToBytes(envelope.ciphertext));       // throws on tamper
}
// ML-KEM secret key embeds the public key; @noble exposes it via getPublicKey(secretKey).
function deriveMlkemPub(sk) { return ml_kem1024.getPublicKey ? ml_kem1024.getPublicKey(sk) : sk.slice(sk.length - 1568); }

/* ---------- verify custody record ---------- */
export function verifyCustodyRecord(record, authorityPub) {
  try { return ml_dsa87.verify(hexToBytes(record.sig), canonRecordCore(record), authorityPub, { context: CUSTODY_CTX }); }
  catch { return false; }
}
// Confirm a signed custody record actually binds THIS envelope (canonical hash). Use BOTH:
// verifyCustodyRecord (authority signed it) AND verifyCustodyBinding (it's for this envelope).
export function verifyCustodyBinding(envelope, record) { return bytesToHex(envelopeHash(envelope)) === record.envelope_hash; }

/* ---------- rotate (re-wrap to a new custody key) ---------- */
export function rotate(envelope, oldCustodySec, newCustodyPub, authoritySecret, opts = {}) {
  const pt = unseal(envelope, oldCustodySec);
  return seal(pt, newCustodyPub, authoritySecret, { ...opts, op: 'rotate' });
}

/* ---------- self-test: node polarseek.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const custody = generateCustodyKey(), authority = generateAuthorityKey(new Uint8Array(32).fill(3));
  const secret = 'TOP-SECRET ml-dsa signing seed: 0xDEADBEEF...';

  const sealed = seal(secret, custody.pub, authority.secretKey, { ts: 1000, key_id: 'k1' });
  ok(sealed.envelope.suite_id === SUITE_ID, 'sealed under the hybrid suite');
  const back = new TextDecoder().decode(unseal(sealed.envelope, custody.sec));
  ok(back === secret, 'unseal recovers the plaintext (got len ' + back.length + ')');
  ok(verifyCustodyRecord(sealed.custody_record, authority.publicKey) === true, 'custody record signature verifies (ML-DSA-87)');
  ok(verifyCustodyBinding(sealed.envelope, sealed.custody_record) === true, 'custody record binds the envelope (canonical hash)');
  const tBind = JSON.parse(JSON.stringify(sealed.envelope)); tBind.ciphertext = tBind.ciphertext.slice(0, -2) + (tBind.ciphertext.endsWith('00') ? '11' : '00');
  ok(verifyCustodyBinding(tBind, sealed.custody_record) === false, 'tampered envelope -> custody binding FAILS (canonical hash)');

  // tamper the ciphertext -> AES-GCM auth must reject
  const tEnv = JSON.parse(JSON.stringify(sealed.envelope));
  tEnv.ciphertext = tEnv.ciphertext.slice(0, -2) + (tEnv.ciphertext.endsWith('00') ? '11' : '00');
  let tamperRejected = false; try { unseal(tEnv, custody.sec); } catch { tamperRejected = true; }
  ok(tamperRejected, 'tampered ciphertext -> unseal rejected (GCM auth)');

  // tamper the custody record -> signature must fail
  const tRec = { ...sealed.custody_record, op: 'rotate' };
  ok(verifyCustodyRecord(tRec, authority.publicKey) === false, 'tampered custody record -> signature invalid');

  // wrong custody key cannot unseal
  const other = generateCustodyKey(); let wrongRejected = false;
  try { unseal(sealed.envelope, other.sec); } catch { wrongRejected = true; }
  ok(wrongRejected, 'wrong custody key -> unseal rejected');

  // rotate to a new custody key; new unseals, old does not
  const custody2 = generateCustodyKey();
  const rotated = rotate(sealed.envelope, custody.sec, custody2.pub, authority.secretKey, { ts: 2000, key_id: 'k2' });
  ok(new TextDecoder().decode(unseal(rotated.envelope, custody2.sec)) === secret, 'rotated envelope unseals under the NEW custody key');
  ok(rotated.custody_record.op === 'rotate' && verifyCustodyRecord(rotated.custody_record, authority.publicKey), 'rotation custody record signed + op=rotate');
  let oldCantOpenNew = false; try { unseal(rotated.envelope, custody.sec); } catch { oldCantOpenNew = true; }
  ok(oldCantOpenNew, 'OLD custody key cannot open the rotated envelope');

  console.log('POLARSEEK PQ-KMS self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /polarseek\.mjs$/.test(process.argv[1] || '')) selfTest();
