/*!
 * pqtransport — HYBRID-PQ secure-transport handshake (reference, DRAFT, standalone).
 *
 * HYBRID PQ/classical (X25519 is classical; post-quantum confidentiality rests on ML-KEM-1024).
 * Mutually-authenticated + forward-secret (ephemeral X25519 + ephemeral ML-KEM-1024 both sides).
 * SIGMA/TLS-1.3-class, hardened per the 11-seat council review:
 *   - Both identity public keys are BOUND INTO the signed transcript (defeats unknown-key-share).
 *   - Initiator vs responder sign under DISTINCT contexts (defeats reflection/role-confusion).
 *   - Channel uses DETERMINISTIC per-direction COUNTER nonces + seq in AAD (no GCM nonce reuse);
 *     separate i2r / r2i AES-256-GCM keys.
 *   - Auth = ML-DSA-87 signature over the transcript hash + out-of-band identity pinning.
 *
 * New, self-contained reference (no production keys). Caller manages per-direction seq counters
 * and rekeys before wrap. Deferred: encrypt identities for initiator privacy; explicit key-confirm
 * message + a strict "no key use before msg3 verified" state machine. Self-test: node pqtransport.mjs
 */
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { randomBytes, bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

export const SUITE_ID = 'TRLN-TLS-1'; // hybrid X25519+ML-KEM-1024 / ML-DSA-87 auth / AES-256-GCM
const AUTH_CTX_I = utf8ToBytes('trelyan-transport-auth-v1/initiator');
const AUTH_CTX_R = utf8ToBytes('trelyan-transport-auth-v1/responder');
const KEK_LABEL = utf8ToBytes('TRELYAN-TRANSPORT-v1');

export function generateIdentity(seed) { return ml_dsa87.keygen(seed || randomBytes(32)); }

// transcript binds BOTH identities + all ephemeral contributions + the suite (downgrade + UKS defence).
// LENGTH-FRAMED (uint32-BE length prefix per field, code-security review) so the concatenation is INJECTIVE — a
// shifted field boundary can never yield the same transcript hash, even for a future variable-length field or suite.
function transcriptHash(t) {
  const lp = (b) => { const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, b.length, false); return concatBytes(n, b); };
  return sha3_256(concatBytes(
    lp(utf8ToBytes(t.suite_id)), lp(t.i_identity_pub), lp(t.i_random), lp(t.i_eph_x), lp(t.i_eph_mlkem),
    lp(t.r_identity_pub), lp(t.r_random), lp(t.r_eph_x), lp(t.mlkem_ct)));
}
function deriveSession(ss_x, ss_m, th) {
  const kek = hkdf(sha256, concatBytes(ss_x, ss_m), th, KEK_LABEL, 32);
  return { i2r: hkdf(sha256, kek, th, utf8ToBytes('i2r'), 32), r2i: hkdf(sha256, kek, th, utf8ToBytes('r2i'), 32) };
}

/* ---------- 3-message handshake ---------- */
// I -> R : msg1 (now carries I's identity so it can be bound into th)
export function initiatorStart(iIdentity, opts = {}) {
  const i_eph_x_priv = randomBytes(32), i_eph_x = x25519.getPublicKey(i_eph_x_priv);
  const mk = ml_kem1024.keygen();
  const i_random = opts.i_random || randomBytes(32);
  const msg1 = { suite_id: SUITE_ID, i_identity_pub: bytesToHex(iIdentity.publicKey), i_random: bytesToHex(i_random), i_eph_x: bytesToHex(i_eph_x), i_eph_mlkem: bytesToHex(mk.publicKey) };
  return { state: { i_eph_x_priv, i_eph_mlkem_priv: mk.secretKey, i_random, i_eph_x, i_eph_mlkem: mk.publicKey, i_identity_pub: iIdentity.publicKey }, msg1 };
}

// R receives msg1 -> derives keys, signs (responder context) -> msg2
// pin check: `undefined` = explicit TOFU (ok, but NOT identity-anchored); a provided-but-empty / non-string pin is a
// MISCONFIGURATION and FAILS CLOSED (never silently accept-anyone); a real pin must match the presented identity exactly.
function pinCheck(expectedHex, actualHex) {
  if (expectedHex === undefined) return { ok: true, pinned: false };
  if (typeof expectedHex !== 'string' || expectedHex.length === 0) return { ok: false, pinned: false };
  return { ok: actualHex.toLowerCase() === expectedHex.toLowerCase(), pinned: true };
}

export function responderRespond(msg1, rIdentity, opts = {}) {
  if (msg1.suite_id !== SUITE_ID) throw new Error('unsupported suite: ' + msg1.suite_id);
  const i_identity_pub = hexToBytes(msg1.i_identity_pub), i_random = hexToBytes(msg1.i_random), i_eph_x = hexToBytes(msg1.i_eph_x), i_eph_mlkem = hexToBytes(msg1.i_eph_mlkem);
  const r_eph_x_priv = randomBytes(32), r_eph_x = x25519.getPublicKey(r_eph_x_priv);
  const r_random = opts.r_random || randomBytes(32);
  const { cipherText: mlkem_ct, sharedSecret: ss_m } = ml_kem1024.encapsulate(i_eph_mlkem);
  const ss_x = x25519.getSharedSecret(r_eph_x_priv, i_eph_x);
  const t = { suite_id: SUITE_ID, i_identity_pub, i_random, i_eph_x, i_eph_mlkem, r_identity_pub: rIdentity.publicKey, r_random, r_eph_x, mlkem_ct };
  const th = transcriptHash(t);
  const r_sig = ml_dsa87.sign(th, rIdentity.secretKey, { context: AUTH_CTX_R });
  const session = deriveSession(ss_x, ss_m, th);
  const msg2 = { r_random: bytesToHex(r_random), r_eph_x: bytesToHex(r_eph_x), mlkem_ct: bytesToHex(mlkem_ct), r_identity_pub: bytesToHex(rIdentity.publicKey), r_sig: bytesToHex(r_sig) };
  return { state: { th, session, i_identity_pub }, msg2 };
}

// I receives msg2 -> derives keys, verifies R (responder context + pin), signs (initiator context) -> msg3
export function initiatorFinish(msg2, iState, iIdentity, expectedRIdentityPubHex) {
  const r_identity_pub = hexToBytes(msg2.r_identity_pub), r_random = hexToBytes(msg2.r_random), r_eph_x = hexToBytes(msg2.r_eph_x), mlkem_ct = hexToBytes(msg2.mlkem_ct);
  const ss_x = x25519.getSharedSecret(iState.i_eph_x_priv, r_eph_x);
  const ss_m = ml_kem1024.decapsulate(mlkem_ct, iState.i_eph_mlkem_priv);
  const t = { suite_id: SUITE_ID, i_identity_pub: iState.i_identity_pub, i_random: iState.i_random, i_eph_x: iState.i_eph_x, i_eph_mlkem: iState.i_eph_mlkem, r_identity_pub, r_random, r_eph_x, mlkem_ct };
  const th = transcriptHash(t);
  let rSigOk = false; try { rSigOk = ml_dsa87.verify(hexToBytes(msg2.r_sig), th, r_identity_pub, { context: AUTH_CTX_R }); } catch { rSigOk = false; }
  const rPin = pinCheck(expectedRIdentityPubHex, msg2.r_identity_pub);
  const i_sig = ml_dsa87.sign(th, iIdentity.secretKey, { context: AUTH_CTX_I });
  const R_auth_ok = rSigOk && rPin.ok;
  // FAIL-CLOSED: never hand back usable session keys on a failed authentication — removes the seal-before-verify
  // footgun (a caller that ignores R_auth_ok cannot encrypt to a MITM, because there is simply no key to encrypt with).
  const session = R_auth_ok ? deriveSession(ss_x, ss_m, th) : null;
  // th = the public handshake transcript hash (binds suite + both identities + all ephemerals); exposed so a PQC
  // gateway can bind its session attestation to the REAL transcript (see pqgateway-session.mjs).
  return { msg3: { i_sig: bytesToHex(i_sig) }, session, th: bytesToHex(th), R_auth_ok, rSigOk, rPinOk: rPin.ok, R_pinned: rPin.pinned };
}

// R receives msg3 -> verifies I (initiator context + pin against the identity seen in msg1)
export function responderFinish(msg3, rState, expectedIIdentityPubHex) {
  let iSigOk = false; try { iSigOk = ml_dsa87.verify(hexToBytes(msg3.i_sig), rState.th, rState.i_identity_pub, { context: AUTH_CTX_I }); } catch { iSigOk = false; }
  const iPin = pinCheck(expectedIIdentityPubHex, bytesToHex(rState.i_identity_pub));
  const I_auth_ok = iSigOk && iPin.ok;
  // FAIL-CLOSED: withhold the session keys unless the initiator is authenticated (no use-before-verify on R's side).
  return { session: I_auth_ok ? rState.session : null, th: bytesToHex(rState.th), I_auth_ok, iSigOk, iPinOk: iPin.ok, I_pinned: iPin.pinned };
}

/* ---------- AEAD channel: deterministic per-direction COUNTER nonces (no reuse) ---------- */
function nonceFromSeq(seq) { const n = new Uint8Array(12); new DataView(n.buffer).setBigUint64(4, BigInt(seq)); return n; }
export function channelSeal(key, plaintext, seq) {
  const nonce = nonceFromSeq(seq), aad = nonce.slice(4);
  return { seq, ct: bytesToHex(gcm(key, nonce, aad).encrypt(typeof plaintext === 'string' ? utf8ToBytes(plaintext) : plaintext)) };
}
export function channelOpen(key, sealed) {
  const nonce = nonceFromSeq(sealed.seq), aad = nonce.slice(4);
  return gcm(key, nonce, aad).decrypt(hexToBytes(sealed.ct));
}
// MISUSE-RESISTANT channel (council/DeepSeek): the low-level channelSeal takes a caller-chosen seq — a caller that reuses
// a seq within a direction would reuse an AES-GCM nonce (catastrophic). openChannel removes that footgun: an INTERNAL
// monotonic send counter (the caller never picks the nonce) + a strictly-increasing receive guard (rejects replay/reorder).
// role: 'initiator' sends on i2r / receives on r2i; 'responder' is the mirror. For an in-order transport.
export function openChannel(session, role) {
  if (!session || !session.i2r || !session.r2i || (role !== 'initiator' && role !== 'responder')) throw new Error("openChannel(session, 'initiator'|'responder')");
  const sendKey = role === 'initiator' ? session.i2r : session.r2i;
  const recvKey = role === 'initiator' ? session.r2i : session.i2r;
  let sendSeq = 0, recvHigh = -1;
  return {
    send: (plaintext) => channelSeal(sendKey, plaintext, sendSeq++),
    recv: (sealed) => {
      if (!sealed || typeof sealed.seq !== 'number' || !Number.isInteger(sealed.seq) || sealed.seq <= recvHigh) throw new Error('replay/reorder rejected: seq must strictly increase');
      const pt = channelOpen(recvKey, sealed); // AEAD auth failure throws
      recvHigh = sealed.seq;
      return pt;
    },
  };
}

/* ---------- self-test: node pqtransport.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const I = generateIdentity(new Uint8Array(32).fill(1)), R = generateIdentity(new Uint8Array(32).fill(2));
  const Ipub = bytesToHex(I.publicKey), Rpub = bytesToHex(R.publicKey);

  const a = initiatorStart(I);
  const b = responderRespond(a.msg1, R);
  const c = initiatorFinish(b.msg2, a.state, I, Rpub);
  const d = responderFinish(c.msg3, b.state, Ipub);

  ok(bytesToHex(c.session.i2r) === bytesToHex(d.session.i2r) && bytesToHex(c.session.r2i) === bytesToHex(d.session.r2i), 'both sides derive identical session keys');
  ok(c.R_auth_ok === true, 'initiator authenticates responder (sig + pin)');
  ok(d.I_auth_ok === true, 'responder authenticates initiator (sig + pin)');

  // counter-nonce channel round-trip (I->R), seq 0 then 1
  const s0 = channelSeal(c.session.i2r, 'msg-0 over a hybrid-PQ tunnel', 0);
  const s1 = channelSeal(c.session.i2r, 'msg-1', 1);
  ok(new TextDecoder().decode(channelOpen(d.session.i2r, s0)) === 'msg-0 over a hybrid-PQ tunnel' && new TextDecoder().decode(channelOpen(d.session.i2r, s1)) === 'msg-1', 'AEAD counter-nonce channel I->R round-trips (seq 0,1)');
  let wrongDir = false; try { channelOpen(d.session.r2i, s0); } catch { wrongDir = true; }
  ok(wrongDir, 'wrong-direction key cannot open the message');

  // MISUSE-RESISTANT channel: internal send counter (no caller-chosen seq -> AES-GCM nonce reuse impossible) + replay reject
  const chI = openChannel(c.session, 'initiator'), chR = openChannel(d.session, 'responder');
  const m0 = chI.send('hello'), m1 = chI.send('world');
  ok(new TextDecoder().decode(chR.recv(m0)) === 'hello' && new TextDecoder().decode(chR.recv(m1)) === 'world', 'stateful channel: internal send counter round-trips (no caller-chosen seq / no nonce reuse)');
  let replayRej = false; try { chR.recv(m0); } catch { replayRej = true; }
  ok(replayRej, 'stateful channel: replay (seq <= last-received) -> REJECTED (nonce-reuse + replay resistant)');

  // UKS / MITM identity: attacker answers with its own identity -> pin fails AND sig binds attacker id
  const M = generateIdentity(new Uint8Array(32).fill(9));
  const bM = responderRespond(a.msg1, M);
  const cM = initiatorFinish(bM.msg2, a.state, I, Rpub); // initiator pins the REAL R
  ok(cM.R_auth_ok === false && cM.rPinOk === false, 'MITM with wrong identity -> responder auth FAILS (pin mismatch)');

  // reflection / role separation: R's signature (responder ctx) must NOT verify as an initiator sig
  let rSigAsInitiator = true; try { rSigAsInitiator = ml_dsa87.verify(hexToBytes(b.msg2.r_sig), b.state.th, R.publicKey, { context: AUTH_CTX_I }); } catch { rSigAsInitiator = false; }
  ok(rSigAsInitiator === false, "responder's signature does NOT verify under the initiator context (role separation)");

  // transcript tamper: flip r_eph_x -> recomputed th differs -> R sig fails
  const tamper = JSON.parse(JSON.stringify(b.msg2));
  tamper.r_eph_x = tamper.r_eph_x.slice(0, -2) + (tamper.r_eph_x.endsWith('00') ? '11' : '00');
  ok(initiatorFinish(tamper, a.state, I, Rpub).R_auth_ok === false, 'tampered transcript -> responder signature verification FAILS');

  // identity binding: if an attacker swaps the identity in msg1 (so th would differ), R signs a different th than I expects -> auth fails
  const downgradeRejected = (() => { try { responderRespond({ ...a.msg1, suite_id: 'WEAK-RSA-1' }, R); return false; } catch { return true; } })();
  ok(downgradeRejected, 'downgrade to an unsupported suite -> rejected');

  // FIX (red-team A): an empty-string / falsy pin must FAIL CLOSED, not silently become accept-anyone (TOFU)
  const cEmpty = initiatorFinish(bM.msg2, a.state, I, '');  // '' = misconfigured pin, against MITM M
  ok(cEmpty.R_auth_ok === false && cEmpty.R_pinned === false, "empty-string responder pin -> FAILS CLOSED (not silent accept-anyone)");
  // FIX (red-team B): session keys are WITHHELD on a failed authentication (no seal-before-verify leak to a MITM)
  ok(cM.session === null && cEmpty.session === null, 'failed auth -> session keys withheld (null): cannot encrypt to a MITM');
  // explicit TOFU (pin omitted) still authenticates on the signature, but reports it is NOT identity-anchored
  const cTofu = initiatorFinish(b.msg2, a.state, I, undefined);
  ok(cTofu.R_auth_ok === true && cTofu.R_pinned === false && cTofu.session !== null, 'omitted pin = TOFU: auth passes on signature, R_pinned:false (validity != anchored trust), keys issued');
  // responder side: empty initiator pin also fails closed + withholds keys
  const dEmpty = responderFinish(c.msg3, b.state, '');
  ok(dEmpty.I_auth_ok === false && dEmpty.session === null, 'empty-string initiator pin -> responder FAILS CLOSED + withholds keys');

  console.log('pqtransport self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqtransport\.mjs$/.test(process.argv[1] || '')) selfTest();
