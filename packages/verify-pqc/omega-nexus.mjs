/*!
 * omega-nexus — TRELYAN OMEGA Layer 6 (Nexus) secure-communication demo (reference, DRAFT). A thin composition over the
 * SHIPPED messaging cores: it establishes a 1:1 async post-quantum session between two OMEGA IDENTITIES (each an
 * ML-DSA-87 + X25519 identity that can be a board/vault key), PINNING the peer's identity out-of-band, via a PQXDH
 * handshake (pqx3dh: X25519 legs + ML-KEM-1024 prekey, transcript-bound, ML-DSA-87 bundle signature) and then a PQ
 * TRIPLE RATCHET (pqratchet: X25519 + periodic ML-KEM-1024 rekey → forward secrecy + post-compromise security). It
 * exchanges a verified message end-to-end. Adds no crypto.
 *
 * HONEST SCOPE (Dorit Dor test) — what this is NOT (blueprint overclaims to reject):
 *  - NO "Quantum Voice / one-time-pad / impossible to decrypt retroactively": the ratchet is hybrid X25519+ML-KEM
 *    periodic rekey, NOT a Vernam OTP; forward secrecy holds under HNDL + endpoint integrity, and endpoint compromise
 *    breaks it. Do not claim OTP semantics or absolute retroactive security.
 *  - NO onion routing / Tor-grade metadata anonymity (out of scope; pqratchet-he only hides the on-wire HEADER).
 *  - NO group messaging (no MLS ratchet) and NO file/video streaming (no media module). 1:1 async messaging only.
 *  - A session verdict is TRUST only when the peer identity is PINNED (trustedIkSigPub) — else it's VALIDITY (self-
 *    consistent) and an active attacker can present their own identity. Self-test: node omega-nexus.mjs
 */
import { generateIdentity, publishPrekeyBundle, verifyPrekeyBundle, initiateHandshake, respondHandshake } from './pqx3dh.mjs';
import { initAlice, initBob, newBobPrekeys, ratchetEncrypt, ratchetDecrypt } from './pqratchet.mjs';
import { utf8ToBytes, bytesToUtf8 } from '@noble/hashes/utils.js';

/** omegaIdentity(seed) — an OMEGA communication identity (ML-DSA-87 signing key + X25519 DH). The signing key is the
 *  pinnable OMEGA identity (e.g. a board member's or a vault's key). */
export function omegaIdentity(seed) { return generateIdentity(seed); }

/**
 * establishSession(initiator, responder, opts) — run PQXDH + seed the ratchet between two OMEGA identities.
 *   opts.trustedIkSigPub : the responder's identity signing key learned OUT-OF-BAND (e.g. via pqkt key-transparency).
 *     In a REAL 2-party deployment PASS THIS — it is the actual trust anchor; do not rely on the responder object handed
 *     to this call. If omitted, opts.pinResponder (default true, secure) pins to the local responder's own key, which is
 *     only meaningful when the two parties are co-located (demo/self-test) — otherwise the verdict is VALIDITY, not TRUST.
 * Returns { ok, aliceState, bobState, reason }.
 */
export function establishSession(initiator, responder, opts = {}) {
  const { bundle, secrets } = publishPrekeyBundle(responder);
  const pin = opts.trustedIkSigPub ?? ((opts.pinResponder ?? true) ? responder.sig.publicKey : undefined);
  if (!verifyPrekeyBundle(bundle, pin ? { trustedIkSigPub: pin } : {})) return { ok: false, reason: 'responder bundle failed verification (identity pin mismatch or tampered bundle)' };
  const a = initiateHandshake(bundle, initiator);
  if (!a.ok) return { ok: false, reason: 'initiate: ' + a.reason };
  const b = respondHandshake(a.initialMessage, responder, bundle, secrets);
  if (!b.ok) return { ok: false, reason: 'respond: ' + b.reason };
  // both sides now share SK; seed the triple ratchet (responder provides ratchet prekeys)
  const rp = newBobPrekeys();
  const aliceState = initAlice(a.SK, rp.dh.pub, rp.kem.publicKey);
  const bobState = initBob(b.SK, rp.dh, rp.kem);
  return { ok: true, aliceState, bobState };
}

/** send(state, text) -> ratchet message (opaque). */
export function send(state, text) { return ratchetEncrypt(state, utf8ToBytes(text)); }
/** receive(state, message) -> { ok, text } (fail-closed on a bad/tampered message). */
export function receive(state, message) {
  try { const pt = ratchetDecrypt(state, message); return { ok: true, text: bytesToUtf8(pt) }; }
  catch (e) { return { ok: false, reason: 'decrypt failed (tampered/out-of-order/wrong key): ' + e.message }; }
}

/* ---------------------------------------- self-test: node omega-nexus.mjs ---------------------------------------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const seed = (n) => new Uint8Array(32).fill(n);
  const alice = omegaIdentity(seed(1));
  const bob = omegaIdentity(seed(2));

  // 1) establish a pinned session + round-trip a message both ways
  const s = establishSession(alice, bob, { pinResponder: true });
  ok(s.ok, 'establishSession: pinned session established');
  const m1 = send(s.aliceState, 'board approved: adopt OMEGA');
  const r1 = receive(s.bobState, m1);
  ok(r1.ok && r1.text === 'board approved: adopt OMEGA', 'session: Alice→Bob message decrypts');
  const m2 = send(s.bobState, 'acknowledged + counter-signed');
  const r2 = receive(s.aliceState, m2);
  ok(r2.ok && r2.text === 'acknowledged + counter-signed', 'session: Bob→Alice reply decrypts');

  // 2) identity pinning: pinning the WRONG identity must fail the handshake
  const mallory = omegaIdentity(seed(9));
  // simulate: initiator tries to pin bob but the responder is actually mallory → bundle is mallory's, pin is bob's
  const badBundle = publishPrekeyBundle(mallory).bundle;
  ok(!verifyPrekeyBundle(badBundle, { trustedIkSigPub: bob.sig.publicKey }), 'pinning: wrong-identity bundle rejected');
  ok(verifyPrekeyBundle(badBundle, { trustedIkSigPub: mallory.sig.publicKey }), 'pinning: correct-identity bundle accepted');

  // 2b) explicit out-of-band pin (the real-deployment path)
  ok(!establishSession(alice, bob, { trustedIkSigPub: mallory.sig.publicKey }).ok, 'session: wrong out-of-band pin rejects');
  ok(establishSession(alice, bob, { trustedIkSigPub: bob.sig.publicKey }).ok, 'session: correct out-of-band pin accepted');

  // 3) tampered ciphertext fails closed
  const s2 = establishSession(alice, bob);
  const m3 = send(s2.aliceState, 'secret');
  const tampered = JSON.parse(JSON.stringify(m3));
  if (tampered.ct) tampered.ct = tampered.ct.slice(0, -2) + (tampered.ct.endsWith('00') ? '01' : '00');
  ok(!receive(s2.bobState, tampered).ok, 'session: tampered ciphertext rejected (fail-closed)');

  console.log(`\nomega-nexus self-test: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) selfTest();
