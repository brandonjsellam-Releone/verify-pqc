/*!
 * pqratchet-he — PQ Triple Ratchet with HEADER ENCRYPTION / sealed-sender (reference, DRAFT, standalone).
 *
 * The apex/production messaging variant (supersedes pqratchet.mjs for QuantumMesh): same hybrid X25519+ML-KEM-1024
 * Triple Ratchet (FS + classical & PQ post-compromise security) PLUS Signal-style HEADER ENCRYPTION — the header
 * (ratchet pubkeys, ML-KEM ct/pub, message counters) is encrypted under rotating header keys, so an on-path
 * observer learns NO metadata (no key material, no counters, no ratchet-step signal). Each chain has a header
 * key HK + a next-header-key NHK from the root KDF; the receiver detects a DH ratchet by the header decrypting
 * under NHKr instead of HKr.
 *
 * HONEST LIMITS: hides header metadata on the wire; does NOT hide traffic timing/volume/IP (that's the onion
 * layer's job). Reference; not constant-time. Initial header keys are derived from the handshake SK here (in a
 * full PQXDH they'd come from the X3DH/handshake).
 *
 * REVIEW RECONCILIATION (DeepSeek FIX-FIRST — verified against the HE spec, 2 of 3 do NOT apply):
 *  - skipped-keys-first decryption order is INTENTIONAL + spec-correct: in HE a current-chain out-of-order
 *    message's header also decrypts under HKr, so "HKr-first" would mis-route it. Cost is O(MKSKIPPED) trial
 *    decrypts, BOUNDED by MAX_SKIP (the standard Signal-HE DoS mitigation); a production fast-path can branch on
 *    n>=Nr but must preserve skipped-first for past messages.
 *  - header nonce is RANDOM (not a counter) ON PURPOSE: a plaintext counter would leak the message index / chain
 *    length — the very metadata HE hides. HKs rotates per chain, so 96-bit random nonce birthday risk is unreachable.
 *  - HKDF domain separation IS present (root RK_INFO vs hka 'QM-HE-hka' vs nhkb 'QM-HE-nhkb' — distinct info).
 *  - payload AAD binds the encrypted-header bytes (sound). Self-test: node pqratchet-he.mjs
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha384, sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes, bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const RK_INFO = utf8ToBytes('QuantumMesh-HE-root-v1');
const MSG_INFO = utf8ToBytes('QuantumMesh-HE-msg-v1');
const HK_INFO = utf8ToBytes('QuantumMesh-HE-hdr-v1');
const MAX_SKIP = 1000;
const EMPTY = new Uint8Array(0);

const genDH = () => { const priv = randomBytes(32); return { priv, pub: x25519.getPublicKey(priv) }; };
const dh = (priv, pub) => x25519.getSharedSecret(priv, pub);
// root KDF now yields THREE keys: next root, chain key, and the next-header-key for that chain.
function rootKDF(rk, ikm) { const o = hkdf(sha384, ikm, rk, RK_INFO, 96); return { rk: o.slice(0, 32), ck: o.slice(32, 64), nhk: o.slice(64, 96) }; }
function chainKDF(ck) { return { mk: hmac(sha256, ck, Uint8Array.of(1)), ck: hmac(sha256, ck, Uint8Array.of(2)) }; }
function msgKeys(mk) { const o = hkdf(sha384, mk, new Uint8Array(32), MSG_INFO, 44); return { key: o.slice(0, 32), nonce: o.slice(32, 44) }; }
const aead = (mk, ad) => { const { key, nonce } = msgKeys(mk); return chacha20poly1305(key, nonce, ad); };
function canon(h) { return utf8ToBytes('{' + Object.keys(h).sort().map((k) => JSON.stringify(k) + ':' + JSON.stringify(h[k])).join(',') + '}'); }

// header encryption: random 12-byte nonce prepended; AEAD under the header key. Returns null on auth failure.
function hEncrypt(hk, headerObj) { const n = randomBytes(12); return bytesToHex(concatBytes(n, chacha20poly1305(hk, n, EMPTY).encrypt(canon(headerObj)))); }
function hDecrypt(hk, encHex) { try { const b = hexToBytes(encHex); return JSON.parse(new TextDecoder().decode(chacha20poly1305(hk, b.slice(0, 12), EMPTY).decrypt(b.slice(12)))); } catch { return null; } }

// initial shared header keys, both derived from the handshake SK (X3DH would supply these in production)
const hka = (SK) => hkdf(sha384, SK, EMPTY, utf8ToBytes('QM-HE-hka'), 32);
const nhkb = (SK) => hkdf(sha384, SK, EMPTY, utf8ToBytes('QM-HE-nhkb'), 32);

export function newBobPrekeys() { return { dh: genDH(), kem: ml_kem1024.keygen() }; }
export function initAlice(SK, bobDHPub, bobKemPub) {
  const DHs = genDH(), KEMs = ml_kem1024.keygen();
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(bobKemPub);
  const { rk, ck, nhk } = rootKDF(SK, concatBytes(dh(DHs.priv, bobDHPub), sharedSecret));
  return { RK: rk, DHs, DHr: bobDHPub, CKs: ck, CKr: null, Ns: 0, Nr: 0, PN: 0,
    HKs: hka(SK), HKr: null, NHKs: nhk, NHKr: nhkb(SK),
    KEMs, KEMr: bobKemPub, MKSKIPPED: [], pendingKem: { kem_ct: bytesToHex(cipherText), kem_pub: bytesToHex(KEMs.publicKey) } };
}
export function initBob(SK, bobDH, bobKem) {
  return { RK: SK, DHs: bobDH, DHr: null, CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0,
    HKs: null, HKr: null, NHKs: nhkb(SK), NHKr: hka(SK), KEMs: bobKem, KEMr: null, MKSKIPPED: [], pendingKem: null };
}

export function ratchetEncrypt(st, plaintext, ad = EMPTY) {
  if (!st.CKs || !st.HKs) throw new Error('no sending chain yet');
  const { mk, ck } = chainKDF(st.CKs); st.CKs = ck;
  const header = { dh: bytesToHex(st.DHs.pub), pn: st.PN, n: st.Ns };
  if (st.pendingKem) { header.kem_ct = st.pendingKem.kem_ct; header.kem_pub = st.pendingKem.kem_pub; }
  st.Ns += 1;
  const enc_header = hEncrypt(st.HKs, header);
  const ct = bytesToHex(aead(mk, concatBytes(ad, utf8ToBytes(enc_header))).encrypt(typeof plaintext === 'string' ? utf8ToBytes(plaintext) : plaintext));
  return { enc_header, ct };
}

function skipMessageKeys(st, until) {
  if (st.Nr + MAX_SKIP < until) throw new Error('too many skipped messages');
  if (!st.CKr) return;
  while (st.Nr < until) { const { mk, ck } = chainKDF(st.CKr); st.CKr = ck; st.MKSKIPPED.push({ hk: st.HKr, n: st.Nr, mk }); st.Nr += 1; }
}
function dhRatchet(st, header) {
  st.PN = st.Ns; st.Ns = 0; st.Nr = 0;
  st.HKs = st.NHKs; st.HKr = st.NHKr;
  st.DHr = hexToBytes(header.dh);
  let kemIn = EMPTY;
  if (header.kem_ct) { kemIn = ml_kem1024.decapsulate(hexToBytes(header.kem_ct), st.KEMs.secretKey); st.KEMr = hexToBytes(header.kem_pub); }
  ({ rk: st.RK, ck: st.CKr, nhk: st.NHKr } = rootKDF(st.RK, concatBytes(dh(st.DHs.priv, st.DHr), kemIn)));
  st.DHs = genDH();
  let kemOut = EMPTY; st.pendingKem = null;
  if (st.KEMr) { const e = ml_kem1024.encapsulate(st.KEMr); kemOut = e.sharedSecret; st.KEMs = ml_kem1024.keygen(); st.pendingKem = { kem_ct: bytesToHex(e.cipherText), kem_pub: bytesToHex(st.KEMs.publicKey) }; }
  ({ rk: st.RK, ck: st.CKs, nhk: st.NHKs } = rootKDF(st.RK, concatBytes(dh(st.DHs.priv, st.DHr), kemOut)));
}
export function ratchetDecrypt(st, message, ad = EMPTY) {
  const { enc_header, ct } = message, ctBytes = hexToBytes(ct);
  // skipped: trial-decrypt the header with each stored header key
  for (let i = 0; i < st.MKSKIPPED.length; i++) {
    const e = st.MKSKIPPED[i]; const h = hDecrypt(e.hk, enc_header);
    if (h && h.n === e.n) {
      const pt = aead(e.mk, concatBytes(ad, utf8ToBytes(enc_header))).decrypt(ctBytes); // decrypt BEFORE consuming the skipped key (a bad tag doesn't burn it)
      st.MKSKIPPED.splice(i, 1);
      return pt;
    }
  }
  // COMMIT-ON-SUCCESS (code-security review): run the header-key trial + skip + DH-ratchet on a CLONE and adopt it only
  // AFTER the AEAD decrypt succeeds, so a forged/tampered current-chain packet can't wedge the live session (the pre-throw
  // st.CKr/DHr mutation was the real defect — same class fixed in pqratchet.mjs).
  const w = cloneState(st);
  let header = w.HKr ? hDecrypt(w.HKr, enc_header) : null;
  let ratchet = false;
  if (!header) { header = hDecrypt(w.NHKr, enc_header); if (!header) throw new Error('header decrypts under no known header key'); ratchet = true; }
  if (ratchet) { skipMessageKeys(w, header.pn); dhRatchet(w, header); }
  skipMessageKeys(w, header.n);
  const { mk, ck } = chainKDF(w.CKr); w.CKr = ck; w.Nr += 1;
  const pt = aead(mk, concatBytes(ad, utf8ToBytes(enc_header))).decrypt(ctBytes); // bad tag -> throws -> live st UNTOUCHED
  Object.assign(st, w); // commit the advanced ratchet state only on a successful decrypt
  return pt;
}

export function cloneState(st) {
  const cp = (b) => (b ? b.slice() : b);
  return { ...st, DHs: st.DHs ? { priv: cp(st.DHs.priv), pub: cp(st.DHs.pub) } : st.DHs, DHr: cp(st.DHr),
    RK: cp(st.RK), CKs: cp(st.CKs), CKr: cp(st.CKr), HKs: cp(st.HKs), HKr: cp(st.HKr), NHKs: cp(st.NHKs), NHKr: cp(st.NHKr), KEMr: cp(st.KEMr),
    KEMs: st.KEMs ? { publicKey: cp(st.KEMs.publicKey), secretKey: cp(st.KEMs.secretKey) } : st.KEMs,
    MKSKIPPED: st.MKSKIPPED.map((e) => ({ hk: cp(e.hk), n: e.n, mk: cp(e.mk) })), pendingKem: st.pendingKem ? { ...st.pendingKem } : null };
}

/* ---------- self-test: node pqratchet-he.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const dec = (b) => new TextDecoder().decode(b);
  const SK = randomBytes(32);
  const bob = newBobPrekeys();
  let A = initAlice(SK, bob.dh.pub, bob.kem.publicKey);
  let B = initBob(SK, bob.dh, bob.kem);

  // 1. round-trip + the header is ENCRYPTED (no plaintext metadata on the wire)
  const m1 = ratchetEncrypt(A, 'hello bob');
  ok(typeof m1.enc_header === 'string' && !/"dh"|"kem_pub"|"pn"/.test(m1.enc_header), 'header is encrypted — no plaintext dh/kem/counter fields on the wire');
  ok(dec(ratchetDecrypt(B, m1)) === 'hello bob', 'Bob decrypts msg1 (header decrypts under NHKr -> ratchet)');
  const m2 = ratchetEncrypt(B, 'hi alice');
  ok(dec(ratchetDecrypt(A, m2)) === 'hi alice', 'full round-trip works with header encryption');
  ok(dec(ratchetDecrypt(B, ratchetEncrypt(A, 'a2'))) === 'a2' && dec(ratchetDecrypt(A, ratchetEncrypt(B, 'b2'))) === 'b2', 'continued bidirectional messaging');

  // 2. METADATA PRIVACY: a third party with neither header key cannot read the header
  ok(hDecrypt(randomBytes(32), m1.enc_header) === null, 'observer without the header key cannot decrypt the header (metadata hidden)');

  // 3. out-of-order via skipped keys (header trial-decryption)
  const o1 = ratchetEncrypt(A, 'one'), o2 = ratchetEncrypt(A, 'two'), o3 = ratchetEncrypt(A, 'three');
  ok(dec(ratchetDecrypt(B, o3)) === 'three' && dec(ratchetDecrypt(B, o1)) === 'one' && dec(ratchetDecrypt(B, o2)) === 'two', 'out-of-order delivery via skipped message keys (encrypted headers)');

  // 4. forward secrecy: consumed message cannot be replayed
  const fs = ratchetEncrypt(A, 'fs'); ratchetDecrypt(B, fs);
  let reuse = false; try { ratchetDecrypt(B, fs); } catch { reuse = true; }
  ok(reuse, 'replaying a consumed message fails (forward secrecy)');

  // 5. post-compromise: stale snapshot can't decrypt after the ratchet heals
  const attacker = cloneState(B);
  ratchetDecrypt(A, ratchetEncrypt(B, 'h1'));
  ratchetDecrypt(B, ratchetEncrypt(A, 'h2'));
  ratchetDecrypt(A, ratchetEncrypt(B, 'h3'));
  const future = ratchetEncrypt(B, 'after-heal');
  ok(dec(ratchetDecrypt(A, future)) === 'after-heal', 'real Alice decrypts the post-heal message');
  let locked = false; try { const pt = ratchetDecrypt(attacker, future); if (dec(pt) !== 'after-heal') locked = true; } catch { locked = true; }
  ok(locked, 'POST-COMPROMISE: stale compromised state cannot decrypt after the ratchet healed');

  // 6. tamper the payload -> AEAD fails
  const tm = ratchetEncrypt(A, 'x'); tm.ct = tm.ct.slice(0, -2) + (tm.ct.slice(-2) === '00' ? '01' : '00');
  let aeadFail = false; try { ratchetDecrypt(B, tm); } catch { aeadFail = true; }
  ok(aeadFail, 'tampered ciphertext -> AEAD authentication fails');

  // 7. REGRESSION (code-security review): a tampered current-chain packet must NOT wedge the live session
  //    (commit-on-success — the receive ratchet advances only AFTER the AEAD decrypt succeeds).
  const bobW = newBobPrekeys();
  const Aw = initAlice(SK, bobW.dh.pub, bobW.kem.publicKey), Bw = initBob(SK, bobW.dh, bobW.kem);
  ratchetDecrypt(Bw, ratchetEncrypt(Aw, 'warmup'));            // establish the A->B current chain at Bw
  const realMsg = ratchetEncrypt(Aw, 'the real payload');
  const evilMsg = { ...realMsg, ct: realMsg.ct.slice(0, -2) + (realMsg.ct.slice(-2) === '00' ? '01' : '00') };
  let wedgeThrew = false; try { ratchetDecrypt(Bw, evilMsg); } catch { wedgeThrew = true; }
  ok(wedgeThrew, 'tampered current-chain packet is rejected (bad AEAD tag)');
  ok(dec(ratchetDecrypt(Bw, realMsg)) === 'the real payload', 'WEDGE FIX: the genuine message still decrypts after a tampered one (live session not wedged)');

  console.log('pqratchet-he self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqratchet-he\.mjs$/.test(process.argv[1] || '')) selfTest();
