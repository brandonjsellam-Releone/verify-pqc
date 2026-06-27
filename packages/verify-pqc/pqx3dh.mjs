/*!
 * pqx3dh — post-quantum asynchronous key agreement (Signal PQXDH-style) (reference, DRAFT, standalone).
 *
 * Bootstraps an end-to-end-encrypted session with an OFFLINE recipient from a SIGNED prekey bundle, deriving the
 * initial shared secret SK that seeds the PQ Triple Ratchet (pqratchet-he). Hybrid + post-quantum:
 *   - X3DH legs (X25519): DH(IK_A,SPK_B), DH(EK_A,IK_B), DH(EK_A,SPK_B), DH(EK_A,OPK_B?).
 *   - PQ leg: ML-KEM-1024 encapsulation, PREFERRING a ONE-TIME KEM prekey (PQ forward secrecy), falling back to a
 *     signed LAST-RESORT KEM prekey. The bundle's long-lived (IK_dh, SPK, last-resort-KEM) triple is ML-DSA-87-signed.
 *   - FULL TRANSCRIPT BINDING (council/Grok+OpenAI): SK = HKDF-Extract(salt = SHA-512(transcript), ikm = labelled
 *     DH+KEM secrets) then Expand — transcript = proto‖suite‖IK_A‖IK_B‖EK_A‖SPK_B‖KEM-prekey‖KEM_ct‖OPK?‖bundle_sig.
 *     Defeats unknown-key-share / transcript-collision; substituting a one-time prekey just makes the SKs disagree.
 *   - REPLAY defense: the responder CONSUMES one-time prekeys and rejects a duplicate handshake.
 *
 * HONEST LIMITS: one-time prekeys (KEM-OT, OPK) are authenticated via the transcript + the trusted prekey server
 * (a production deployment signs one-time-prekey batches); deniability is not analyzed; mutual auth is IMPLICIT (a
 * compromised long-term identity key breaks it); reference, not constant-time. Self-test: node pqx3dh.mjs
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes, bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const SUITE = 'X25519+ML-KEM-1024/ML-DSA-87';
const BUNDLE_CTX = utf8ToBytes('trelyan-pqx3dh-prekey-bundle-v1');
const SK_INFO = utf8ToBytes('trelyan-pqx3dh-sk-v1');
const hx = bytesToHex;
const L = (s) => utf8ToBytes(s);
const genDH = () => { const priv = randomBytes(32); return { priv, pub: x25519.getPublicKey(priv) }; };
const dh = (priv, pub) => x25519.getSharedSecret(priv, pub);
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
const transcriptHash = (t) => sha512(utf8ToBytes(canon(t))); // all PUBLIC handshake inputs
// labelled hybrid combiner; transcript hash is the HKDF SALT (full transcript binding).
function deriveSK(labelledParts, th) { return hkdf(sha512, concatBytes(new Uint8Array(32).fill(0xff), ...labelledParts), th, SK_INFO, 32); }

export function generateIdentity(seed) { return { dh: genDH(), sig: ml_dsa87.keygen(seed || randomBytes(32)) }; }

export function publishPrekeyBundle(identity, opts = {}) {
  const spk = genDH();
  const kemLast = ml_kem1024.keygen();                                    // signed last-resort KEM prekey
  const kemOt = (opts.oneTimeKem ?? true) ? ml_kem1024.keygen() : null;   // one-time KEM prekey (PQ forward secrecy)
  const opk = (opts.oneTime ?? true) ? genDH() : null;                    // one-time DH prekey
  const coreSigned = { ik_dh_pub: hx(identity.dh.pub), spk_pub: hx(spk.pub), kem_lastresort_pub: hx(kemLast.publicKey),
    kem_ot_pub: kemOt ? hx(kemOt.publicKey) : null, kem_ot_id: kemOt ? (opts.kemOtId ?? 'kemot-1') : null,
    onetime_pub: opk ? hx(opk.pub) : null, onetime_id: opk ? (opts.oneTimeId ?? 'opk-1') : null }; // one-time prekeys now SIGNED
  const bundle = {
    ik_dh_pub: coreSigned.ik_dh_pub, ik_sig_pub: hx(identity.sig.publicKey), spk_pub: coreSigned.spk_pub,
    kem_lastresort_pub: coreSigned.kem_lastresort_pub,
    kem_ot_pub: coreSigned.kem_ot_pub, kem_ot_id: coreSigned.kem_ot_id,
    onetime_pub: coreSigned.onetime_pub, onetime_id: coreSigned.onetime_id,
    bundle_sig: hx(ml_dsa87.sign(utf8ToBytes(canon(coreSigned)), identity.sig.secretKey, { context: BUNDLE_CTX })),
  };
  const secrets = { spk_priv: spk.priv, kem_lastresort_sk: kemLast.secretKey, kem_ot_sk: kemOt ? kemOt.secretKey : null, kem_ot_id: bundle.kem_ot_id, onetime_priv: opk ? opk.priv : null, onetime_id: bundle.onetime_id, consumed: new Set() };
  return { bundle, secrets };
}
// TRUST MODEL (council/DeepSeek red-team): with NO `trustedIkSigPub`, this verifies the bundle is internally consistent
// — VALIDITY, not trust: it proves the bundle was signed by WHOEVER owns the embedded `ik_sig_pub`, NOT that that key is
// the intended peer. A caller MUST pin the peer identity key out-of-band (e.g. via pqkt key-transparency) — pass it as
// `opts.trustedIkSigPub` (hex or bytes) and this rejects any bundle whose `ik_sig_pub` differs. Without a pin an active
// attacker can present a self-consistent bundle under their OWN identity key.
export function verifyPrekeyBundle(bundle, opts = {}) {
  try { // TOTAL (fuzz): fail-closed on any malformed bundle
    if (!bundle || typeof bundle !== 'object') return false;
    const pin = opts.trustedIkSigPub;
    if (pin != null) {
      const pinHex = (typeof pin === 'string' ? pin : hx(pin)).toLowerCase();
      if (typeof bundle.ik_sig_pub !== 'string' || bundle.ik_sig_pub.toLowerCase() !== pinHex) return false; // not the pinned identity
    }
    // ONE-TIME prekeys are signed too (tamper-binding harness + Signal PQXDH): under HNDL the classical legs are broken,
    // so an active attacker who substitutes an UNSIGNED one-time PQ-KEM prekey could defeat the PQ protection. Bind them.
    const coreSigned = { ik_dh_pub: bundle.ik_dh_pub, spk_pub: bundle.spk_pub, kem_lastresort_pub: bundle.kem_lastresort_pub,
      kem_ot_pub: bundle.kem_ot_pub ?? null, kem_ot_id: bundle.kem_ot_id ?? null, onetime_pub: bundle.onetime_pub ?? null, onetime_id: bundle.onetime_id ?? null };
    return ml_dsa87.verify(hexToBytes(bundle.bundle_sig), utf8ToBytes(canon(coreSigned)), hexToBytes(bundle.ik_sig_pub), { context: BUNDLE_CTX });
  } catch { return false; }
}

// INITIATOR (Alice). Returns { ok, SK, initialMessage }.
export function initiateHandshake(bobBundle, aliceIdentity) {
  if (!verifyPrekeyBundle(bobBundle)) return { ok: false, reason: 'bundle signature invalid (possible prekey substitution)' };
  const ek = genDH();
  const ikB = hexToBytes(bobBundle.ik_dh_pub), spkB = hexToBytes(bobBundle.spk_pub);
  const useOtKem = !!bobBundle.kem_ot_pub;
  const kemUsedPub = useOtKem ? bobBundle.kem_ot_pub : bobBundle.kem_lastresort_pub;
  const kemUsedId = useOtKem ? bobBundle.kem_ot_id : 'lastresort';
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(hexToBytes(kemUsedPub));
  const labelled = [L('pqx3dh-dh1'), dh(aliceIdentity.dh.priv, spkB), L('pqx3dh-dh2'), dh(ek.priv, ikB), L('pqx3dh-dh3'), dh(ek.priv, spkB)];
  if (bobBundle.onetime_pub) labelled.push(L('pqx3dh-dh4'), dh(ek.priv, hexToBytes(bobBundle.onetime_pub)));
  labelled.push(L('pqx3dh-kem'), sharedSecret);
  const th = transcriptHash({ proto: 'pqx3dh-v1', suite: SUITE, ik_a_dh: hx(aliceIdentity.dh.pub), ik_b_dh: bobBundle.ik_dh_pub, ek_a: hx(ek.pub), spk_b: bobBundle.spk_pub, kem_used_pub: kemUsedPub, kem_used_id: kemUsedId, kem_ct: hx(cipherText), opk_b: bobBundle.onetime_pub || null, opk_id: bobBundle.onetime_id || null, bundle_sig: bobBundle.bundle_sig });
  return { ok: true, SK: deriveSK(labelled, th), initialMessage: { ik_dh_pub: hx(aliceIdentity.dh.pub), ik_sig_pub: hx(aliceIdentity.sig.publicKey), ek_pub: hx(ek.pub), kem_ct: hx(cipherText), kem_used_id: kemUsedId, used_onetime_id: bobBundle.onetime_id || null } };
}

// RESPONDER (Bob). Needs his published bundle + its secrets. Consumes one-time prekeys (mutates bobSecrets).
export function respondHandshake(initialMessage, bobIdentity, bobBundle, bobSecrets) {
  if (bobSecrets.consumed.has(initialMessage.kem_ct)) return { ok: false, reason: 'replay: this handshake was already consumed' };
  let kemSk, kemUsedPub;
  if (initialMessage.kem_used_id === 'lastresort') { kemSk = bobSecrets.kem_lastresort_sk; kemUsedPub = bobBundle.kem_lastresort_pub; }
  else if (initialMessage.kem_used_id === bobSecrets.kem_ot_id && bobSecrets.kem_ot_sk) { kemSk = bobSecrets.kem_ot_sk; kemUsedPub = bobBundle.kem_ot_pub; }
  else return { ok: false, reason: 'unknown or already-consumed KEM prekey id' };
  const ikA = hexToBytes(initialMessage.ik_dh_pub), ekA = hexToBytes(initialMessage.ek_pub);
  const ss = ml_kem1024.decapsulate(hexToBytes(initialMessage.kem_ct), kemSk);
  const labelled = [L('pqx3dh-dh1'), dh(bobSecrets.spk_priv, ikA), L('pqx3dh-dh2'), dh(bobIdentity.dh.priv, ekA), L('pqx3dh-dh3'), dh(bobSecrets.spk_priv, ekA)];
  let opkPub = null, opkId = null;
  if (initialMessage.used_onetime_id && bobSecrets.onetime_priv && initialMessage.used_onetime_id === bobSecrets.onetime_id) { labelled.push(L('pqx3dh-dh4'), dh(bobSecrets.onetime_priv, ekA)); opkPub = hx(x25519.getPublicKey(bobSecrets.onetime_priv)); opkId = bobSecrets.onetime_id; }
  labelled.push(L('pqx3dh-kem'), ss);
  const th = transcriptHash({ proto: 'pqx3dh-v1', suite: SUITE, ik_a_dh: initialMessage.ik_dh_pub, ik_b_dh: bobBundle.ik_dh_pub, ek_a: initialMessage.ek_pub, spk_b: bobBundle.spk_pub, kem_used_pub: kemUsedPub, kem_used_id: initialMessage.kem_used_id, kem_ct: initialMessage.kem_ct, opk_b: opkPub, opk_id: opkId, bundle_sig: bobBundle.bundle_sig });
  const SK = deriveSK(labelled, th);
  bobSecrets.consumed.add(initialMessage.kem_ct);               // replay defense
  if (initialMessage.kem_used_id === bobSecrets.kem_ot_id) bobSecrets.kem_ot_sk = null; // consume one-time KEM
  if (opkId) bobSecrets.onetime_priv = null;                    // consume one-time DH prekey
  return { ok: true, SK };
}

/* ---------- self-test: node pqx3dh.mjs ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const alice = generateIdentity(new Uint8Array(32).fill(1));
  const bob = generateIdentity(new Uint8Array(32).fill(2));

  // 1. async offline handshake -> same SK; full transcript bound
  const { bundle, secrets } = publishPrekeyBundle(bob);
  ok(verifyPrekeyBundle(bundle) === true, 'prekey bundle signature verifies under Bob\'s identity');
  const a = initiateHandshake(bundle, alice);
  const b = respondHandshake(a.initialMessage, bob, bundle, secrets);
  ok(a.ok && b.ok && hx(a.SK) === hx(b.SK) && a.SK.length === 32, 'Alice & Bob derive the SAME 32-byte SK (async, offline Bob)');
  ok(a.initialMessage.kem_used_id === bundle.kem_ot_id, 'initiator preferred the ONE-TIME KEM prekey (PQ forward secrecy)');

  // 2. prekey substitution -> bundle sig fails
  const tampered = { ...bundle, kem_lastresort_pub: bundle.kem_lastresort_pub.slice(0, -2) + (bundle.kem_lastresort_pub.endsWith('00') ? '11' : '00') };
  ok(verifyPrekeyBundle(tampered) === false && initiateHandshake(tampered, alice).ok === false, 'substituted last-resort KEM prekey -> bundle verify FAILS, handshake refused');

  // 3. REPLAY (council/OpenAI): the same initial message replayed -> rejected (one-time consumed)
  const { bundle: bun2, secrets: sec2 } = publishPrekeyBundle(bob);
  const a2 = initiateHandshake(bun2, alice);
  const r1 = respondHandshake(a2.initialMessage, bob, bun2, sec2);
  const r2 = respondHandshake(a2.initialMessage, bob, bun2, sec2);
  ok(r1.ok === true && r2.ok === false, 'replayed handshake -> SECOND attempt rejected (one-time prekey consumed)');

  // 4. ONE-TIME-KEM prekey is now SIGNED (tamper-binding harness caught it unsigned; fixed to match Signal PQXDH) ->
  //    verifyPrekeyBundle REJECTS a substituted one-time KEM prekey AT THE SOURCE (stronger than the old transcript-only
  //    SK-disagreement: under HNDL the classical legs are broken, so an unsigned PQ prekey was a real substitution gap).
  const { bundle: bun3 } = publishPrekeyBundle(bob);
  const evilKem = ml_kem1024.keygen();
  const a3 = initiateHandshake({ ...bun3, kem_ot_pub: hx(evilKem.publicKey) }, alice); // attacker swapped the one-time KEM pub
  ok(a3.ok === false, 'substituted one-time KEM prekey -> bundle signature REJECTS it (initiateHandshake fails closed; one-time prekeys are signed)');

  // 5. full transcript binding: tamper EK in transit -> responder derives a different SK
  const { bundle: bun4, secrets: sec4 } = publishPrekeyBundle(bob);
  const a4 = initiateHandshake(bun4, alice);
  const b4 = respondHandshake({ ...a4.initialMessage, ek_pub: hx(genDH().pub) }, bob, bun4, sec4);
  ok(!b4.ok || hx(b4.SK) !== hx(a4.SK), 'tampered EK -> SK differs (ephemeral bound into the transcript/KDF)');

  // 6. END-TO-END: SK seeds pqratchet-he and a sealed message round-trips
  let composed = false;
  try {
    const rt = await import('./pqratchet-he.mjs');
    const { bundle: bun5, secrets: sec5 } = publishPrekeyBundle(bob);
    const a5 = initiateHandshake(bun5, alice); const b5 = respondHandshake(a5.initialMessage, bob, bun5, sec5);
    const bobRk = rt.newBobPrekeys();
    const A = rt.initAlice(a5.SK, bobRk.dh.pub, bobRk.kem.publicKey);
    const B = rt.initBob(b5.SK, bobRk.dh, bobRk.kem);
    const msg = rt.ratchetEncrypt(A, 'hello from an async PQXDH session');
    composed = new TextDecoder().decode(rt.ratchetDecrypt(B, msg)) === 'hello from an async PQXDH session';
  } catch (e) { console.error('compose error:', e.message); }
  ok(composed, 'PQXDH SK seeds pqratchet-he -> first sealed message decrypts (async E2EE session, end-to-end)');

  // 7. no one-time prekeys at all -> falls back to last-resort, still agrees
  const { bundle: bun6, secrets: sec6 } = publishPrekeyBundle(bob, { oneTime: false, oneTimeKem: false });
  const a6 = initiateHandshake(bun6, alice); const b6 = respondHandshake(a6.initialMessage, bob, bun6, sec6);
  ok(a6.initialMessage.kem_used_id === 'lastresort' && hx(a6.SK) === hx(b6.SK), 'no one-time prekeys -> last-resort KEM, SK still agrees');

  console.log('pqx3dh self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqx3dh\.mjs$/.test(process.argv[1] || '')) selfTest();
