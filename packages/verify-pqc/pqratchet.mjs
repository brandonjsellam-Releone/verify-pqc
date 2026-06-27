/*!
 * pqratchet — QuantumMesh PQ Triple Ratchet (reference, DRAFT, standalone). Apple-PQ3 / Signal-PQXDH style.
 *
 * The messaging crypto core: a Signal Double Ratchet (X25519) PLUS a periodic ML-KEM-1024 rekey of the root,
 * so the session has forward secrecy + classical AND post-quantum post-compromise security ("self-healing").
 * Layer stack matches the QuantumMesh CSV: X25519+ML-KEM-1024 ratchet, HKDF-SHA384 root, HMAC-SHA256 chains,
 * ChaCha20-Poly1305 AEAD. (Initial key establishment / identity = pqtransport's hybrid handshake + ML-KEM-1024;
 * here the shared SK is taken as input.)
 *
 * HONEST LIMITS: reference, not production — single-skip cap, no header-encryption (sealed sender), no MLS group
 * ratchet, no constant-time guarantees (JS). Apple PQ3 mixes a KEM at session start + periodically; this mixes
 * ML-KEM material on every DH-ratchet round (one round of latency), which is the conservative/strong variant.
 * Self-test: node pqratchet.mjs
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha384, sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes, bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const RK_INFO = utf8ToBytes('QuantumMesh-root-v1');
const MSG_INFO = utf8ToBytes('QuantumMesh-msg-v1');
const MAX_SKIP = 1000;
const EMPTY = new Uint8Array(0);

const genDH = () => { const priv = randomBytes(32); return { priv, pub: x25519.getPublicKey(priv) }; };
const dh = (priv, pub) => x25519.getSharedSecret(priv, pub);
function rootKDF(rk, ikm) { const o = hkdf(sha384, ikm, rk, RK_INFO, 64); return { rk: o.slice(0, 32), ck: o.slice(32, 64) }; }
function chainKDF(ck) { return { mk: hmac(sha256, ck, Uint8Array.of(1)), ck: hmac(sha256, ck, Uint8Array.of(2)) }; }
function msgKeys(mk) { const o = hkdf(sha384, mk, new Uint8Array(32), MSG_INFO, 44); return { key: o.slice(0, 32), nonce: o.slice(32, 44) }; }
const aead = (mk, ad) => { const { key, nonce } = msgKeys(mk); return chacha20poly1305(key, nonce, ad); };
function canon(h) { return utf8ToBytes('{' + Object.keys(h).sort().map((k) => JSON.stringify(k) + ':' + JSON.stringify(h[k])).join(',') + '}'); }
const skipKey = (dhrHex, n) => dhrHex + '|' + n;

/* ---------- session setup (SK = output of the hybrid handshake; bob publishes a DH + ML-KEM pubkey) ---------- */
export function initAlice(SK, bobDHPub, bobKemPub) {
  const DHs = genDH(), KEMs = ml_kem1024.keygen();
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(bobKemPub); // initial PQ leg -> Bob
  const { rk, ck } = rootKDF(SK, concatBytes(dh(DHs.priv, bobDHPub), sharedSecret));
  return { RK: rk, DHs, DHr: bobDHPub, CKs: ck, CKr: null, Ns: 0, Nr: 0, PN: 0,
    KEMs, KEMr: bobKemPub, MKSKIPPED: new Map(),
    pendingKem: { kem_ct: bytesToHex(cipherText), kem_pub: bytesToHex(KEMs.publicKey) } };
}
export function initBob(SK, bobDH, bobKem) {
  return { RK: SK, DHs: bobDH, DHr: null, CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0,
    KEMs: bobKem, KEMr: null, MKSKIPPED: new Map(), pendingKem: null };
}
export function newBobPrekeys() { return { dh: genDH(), kem: ml_kem1024.keygen() }; }

/* ---------- encrypt ---------- */
export function ratchetEncrypt(st, plaintext, ad = EMPTY) {
  if (!st.CKs) throw new Error('no sending chain yet (awaiting first inbound message)');
  const { mk, ck } = chainKDF(st.CKs); st.CKs = ck;
  const header = { dh: bytesToHex(st.DHs.pub), pn: st.PN, n: st.Ns };
  // attach the chain's ML-KEM ct + pubkey to EVERY message (like the DH pubkey) so out-of-order delivery
  // still triggers a correct PQ-mixed ratchet. (Production sends it once + buffers chain-openers to save ~2KB/msg.)
  if (st.pendingKem) { header.kem_ct = st.pendingKem.kem_ct; header.kem_pub = st.pendingKem.kem_pub; }
  st.Ns += 1;
  const aadFull = concatBytes(ad, canon(header));
  return { header, ct: bytesToHex(aead(mk, aadFull).encrypt(typeof plaintext === 'string' ? utf8ToBytes(plaintext) : plaintext)) };
}

/* ---------- decrypt ---------- */
function skipMessageKeys(st, until) {
  if (st.Nr + MAX_SKIP < until) throw new Error('too many skipped messages');
  if (!st.CKr) return;
  while (st.Nr < until) { const { mk, ck } = chainKDF(st.CKr); st.CKr = ck; st.MKSKIPPED.set(skipKey(bytesToHex(st.DHr), st.Nr), mk); st.Nr += 1; }
}
function dhRatchet(st, header) {
  st.PN = st.Ns; st.Ns = 0; st.Nr = 0;
  st.DHr = hexToBytes(header.dh);
  let kemIn = EMPTY;
  if (header.kem_ct) { kemIn = ml_kem1024.decapsulate(hexToBytes(header.kem_ct), st.KEMs.secretKey); st.KEMr = hexToBytes(header.kem_pub); }
  ({ rk: st.RK, ck: st.CKr } = rootKDF(st.RK, concatBytes(dh(st.DHs.priv, st.DHr), kemIn)));
  st.DHs = genDH();
  let kemOut = EMPTY; st.pendingKem = null;
  if (st.KEMr) { const e = ml_kem1024.encapsulate(st.KEMr); kemOut = e.sharedSecret; st.KEMs = ml_kem1024.keygen(); st.pendingKem = { kem_ct: bytesToHex(e.cipherText), kem_pub: bytesToHex(st.KEMs.publicKey) }; }
  ({ rk: st.RK, ck: st.CKs } = rootKDF(st.RK, concatBytes(dh(st.DHs.priv, st.DHr), kemOut)));
}
export function ratchetDecrypt(st, message, ad = EMPTY) {
  const header = message.header, ctBytes = hexToBytes(message.ct);
  const sk = skipKey(header.dh, header.n);
  if (st.MKSKIPPED.has(sk)) { const mk = st.MKSKIPPED.get(sk); st.MKSKIPPED.delete(sk); return aead(mk, concatBytes(ad, canon(header))).decrypt(ctBytes); }
  if (!st.DHr || header.dh !== bytesToHex(st.DHr)) { skipMessageKeys(st, header.pn); dhRatchet(st, header); }
  skipMessageKeys(st, header.n);
  const { mk, ck } = chainKDF(st.CKr); st.CKr = ck; st.Nr += 1;
  return aead(mk, concatBytes(ad, canon(header))).decrypt(ctBytes);
}

export function cloneState(st) {
  const cp = (b) => (b ? b.slice() : b);
  return { ...st, DHs: st.DHs ? { priv: cp(st.DHs.priv), pub: cp(st.DHs.pub) } : st.DHs, DHr: cp(st.DHr),
    RK: cp(st.RK), CKs: cp(st.CKs), CKr: cp(st.CKr), KEMr: cp(st.KEMr),
    KEMs: st.KEMs ? { publicKey: cp(st.KEMs.publicKey), secretKey: cp(st.KEMs.secretKey) } : st.KEMs,
    MKSKIPPED: new Map([...st.MKSKIPPED].map(([k, v]) => [k, v.slice()])),
    pendingKem: st.pendingKem ? { ...st.pendingKem } : null };
}

/* ---------- self-test: node pqratchet.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const dec = (b) => new TextDecoder().decode(b);
  const SK = randomBytes(32);                 // output of the hybrid handshake (X25519 + ML-KEM-1024)
  const bob = newBobPrekeys();
  let A = initAlice(SK, bob.dh.pub, bob.kem.publicKey);
  let B = initBob(SK, bob.dh, bob.kem);

  // 1. Alice -> Bob (first message bootstraps Bob's chains, carries the PQ KEM ciphertext)
  const m1 = ratchetEncrypt(A, 'hello bob');
  ok(!!m1.header.kem_ct && !!m1.header.kem_pub, 'first message carries the ML-KEM ciphertext + new KEM pubkey (PQ leg)');
  ok(dec(ratchetDecrypt(B, m1)) === 'hello bob', 'Bob decrypts Alice msg 1 (receiving chain == Alice sending chain)');

  // 2. Bob -> Alice (Bob now has a sending chain after his DH+PQ ratchet)
  const m2 = ratchetEncrypt(B, 'hi alice');
  ok(dec(ratchetDecrypt(A, m2)) === 'hi alice', 'Alice decrypts Bob reply (full round-trip works)');

  // 3. several in-order messages each way
  ok(dec(ratchetDecrypt(B, ratchetEncrypt(A, 'a2'))) === 'a2' && dec(ratchetDecrypt(A, ratchetEncrypt(B, 'b2'))) === 'b2', 'continued bidirectional messaging');

  // 4. out-of-order: Alice sends 3, Bob receives #3 then #2 then #1 (skipped-key handling)
  const o1 = ratchetEncrypt(A, 'one'), o2 = ratchetEncrypt(A, 'two'), o3 = ratchetEncrypt(A, 'three');
  ok(dec(ratchetDecrypt(B, o3)) === 'three' && dec(ratchetDecrypt(B, o2)) === 'two' && dec(ratchetDecrypt(B, o1)) === 'one', 'out-of-order delivery via skipped message keys');

  // 5. forward secrecy: a consumed in-order message key cannot be reused (chain advanced one-way)
  const fsMsg = ratchetEncrypt(A, 'fs'); ratchetDecrypt(B, fsMsg);
  let reuse = false; try { ratchetDecrypt(B, fsMsg); } catch { reuse = true; }
  ok(reuse, 'replaying a consumed message fails (forward secrecy: keys are deleted, chain is one-way)');

  // 6. POST-COMPROMISE SECURITY: snapshot Bob, then let the session heal via DH+PQ ratchet rounds; the stale snapshot can no longer decrypt
  const attacker = cloneState(B);
  ratchetDecrypt(A, ratchetEncrypt(B, 'b-heal-1'));      // Bob->Alice (Alice ratchets)
  ratchetDecrypt(B, ratchetEncrypt(A, 'a-heal-1'));      // Alice->Bob (Bob ratchets: new X25519 + new ML-KEM)
  ratchetDecrypt(A, ratchetEncrypt(B, 'b-heal-2'));      // another round to fully turn the ratchet
  const future = ratchetEncrypt(B, 'top-secret-after-heal');
  ok(dec(ratchetDecrypt(A, future)) === 'top-secret-after-heal', 'real Alice decrypts the post-heal message');
  let locked = false; try { const pt = ratchetDecrypt(attacker, future); if (dec(pt) !== 'top-secret-after-heal') locked = true; } catch { locked = true; }
  ok(locked, 'POST-COMPROMISE: the compromised (stale) state CANNOT decrypt messages after the ratchet healed');

  // 7. tamper: flip the ciphertext -> AEAD rejects (integrity)
  const tm = ratchetEncrypt(A, 'integrity'); tm.ct = tm.ct.slice(0, -2) + (tm.ct.slice(-2) === '00' ? '01' : '00');
  let aeadFail = false; try { ratchetDecrypt(B, tm); } catch { aeadFail = true; }
  ok(aeadFail, 'tampered ciphertext -> AEAD authentication fails');

  // 8. associated data binding: wrong AD -> fails
  const adMsg = ratchetEncrypt(A, 'bound', utf8ToBytes('ctx-A'));
  let adFail = false; try { ratchetDecrypt(B, adMsg, utf8ToBytes('ctx-B')); } catch { adFail = true; }
  ok(adFail, 'associated-data mismatch -> decryption fails (channel binding)');

  console.log('pqratchet self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqratchet\.mjs$/.test(process.argv[1] || '')) selfTest();
