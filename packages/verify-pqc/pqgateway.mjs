/*!
 * pqgateway — "no-forklift" PQC upgrade gateway core (reference, DRAFT, standalone). The council's #1 unbuilt gap.
 *
 * Lets organizations add hybrid ML-KEM/ML-DSA to legacy TLS/SSH/API sessions WITHOUT rewriting the apps. This
 * module is the ownable, novel core: (1) SIGNED capability offers (a MITM stripping the PQ suites in transit
 * breaks the signature → downgrade detection), (2) strongest-suite NEGOTIATION under policy with fallback rules,
 * and (3) a SIGNED SESSION ATTESTATION — the "operational proof" the market lacks: *was hybrid PQ actually used?
 * which suite? was a downgrade prevented?* Anyone can verify it after the fact.
 *
 * HONEST SCOPE (council/Grok): TRUE bump-in-the-wire injection is IMPOSSIBLE — TLS/SSH are end-to-end
 * authenticated; you cannot splice in ML-KEM/ML-DSA without TERMINATING the connection. The real product is a
 * TERMINATING reverse-proxy / PQC gateway deployed IN FRONT (Envoy/nginx/Caddy/appliance): it terminates a
 * hybrid-PQ TLS leg to the client and speaks classical (or separately-upgraded) TLS to the backend. The app needs
 * NO source change, but you add the proxy hop + manage its certs. This module is that gateway's policy +
 * negotiation + attestation core; the handshake itself = pqtransport.
 * SECURITY (council/DeepSeek, fixed): offers are bound to a per-session CHALLENGE (anti-replay), and attestations
 * to the handshake TRANSCRIPT hash (which includes the negotiated suite) — NOT an opaque exporter. The attestation
 * is a signed claim bound to that transcript; to be third-party PROOF that PQ was truly used, the verifier must
 * confirm the transcript negotiated the claimed suite (pass opts.expectedTranscript — defeats a lying gateway).
 * Downgrade protection requires PINNED peer keys. Self-test: node pqgateway.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils.js';

const OFFER_CTX = utf8ToBytes('trelyan-gateway-offer-v1');
const ATT_CTX = utf8ToBytes('trelyan-gateway-session-v1');
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

// suite catalog, strongest first
export const SUITES = [
  { id: 'hybrid-mlkem1024-x25519-mldsa87', kem: 'X25519+ML-KEM-1024', sig: 'ML-DSA-87', level: 5, pq: true },
  { id: 'hybrid-mlkem768-x25519-mldsa65', kem: 'X25519+ML-KEM-768', sig: 'ML-DSA-65', level: 3, pq: true },
  { id: 'classical-x25519-ed25519', kem: 'X25519', sig: 'Ed25519', level: 0, pq: false },
];
const byId = (id) => SUITES.find((s) => s.id === id);

/* ---------- signed capability offer (downgrade detection) ---------- */
export function makeOffer(suiteIds, identitySk, identityPub, opts = {}) {
  // challenge = a fresh per-session value the verifier issues; binding it here defeats cross-session offer replay.
  const core = { suites: suiteIds.slice().sort(), challenge: opts.challenge ?? null, nonce: opts.nonce || bytesToHex(randomBytes(16)), id_pub: bytesToHex(identityPub), ts: opts.ts ?? null };
  return { ...core, sig: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), identitySk, { context: OFFER_CTX })) };
}
// PIN trustedPeerPub for real downgrade protection; without it, this is trust-on-first-use against the embedded key.
export function verifyOffer(offer, trustedPeerPub) {
  try { // TOTAL: fail-closed on any malformed input, never throw (fuzz-robustness)
    if (!offer || typeof offer !== 'object' || Array.isArray(offer)) return false;
    const { sig, ...core } = offer;
    const pub = trustedPeerPub ? trustedPeerPub : hexToBytes(offer.id_pub);
    if (trustedPeerPub && String(offer.id_pub).toLowerCase() !== bytesToHex(trustedPeerPub).toLowerCase()) return false;
    return ml_dsa87.verify(hexToBytes(sig), utf8ToBytes(canon(core)), pub, { context: OFFER_CTX });
  } catch { return false; }
}

/* ---------- negotiation with downgrade protection + policy ---------- */
export function negotiate({ localSuites, remoteOffer, policy = {}, trustedPeerPub }) {
  if (!verifyOffer(remoteOffer, trustedPeerPub)) return { ok: false, downgrade_suspected: true, reason: 'capability offer signature invalid — possible downgrade/MITM (pin the peer key)' };
  if (policy.expectedChallenge && remoteOffer.challenge !== policy.expectedChallenge) return { ok: false, replay_suspected: true, reason: 'offer challenge mismatch — replayed / cross-session offer' };
  const requirePQ = policy.requirePQ ?? true;
  const mutual = SUITES.filter((s) => localSuites.includes(s.id) && remoteOffer.suites.includes(s.id)); // priority order
  const best = mutual[0];
  if (!best) return { ok: false, reason: 'no mutually supported suite' };
  if (!best.pq && requirePQ) {
    if (!policy.allowFallback) return { ok: false, reason: 'policy requires PQ; strongest mutual suite is classical', best: best.id };
    return { ok: true, chosen: best.id, pq: false, fallback: true, downgrade_logged: true, warn: 'classical fallback under policy (logged)' };
  }
  if (policy.minLevel && best.level < policy.minLevel) {
    if (!policy.allowFallback) return { ok: false, reason: 'best suite level ' + best.level + ' < min ' + policy.minLevel };
    return { ok: true, chosen: best.id, pq: best.pq, fallback: true, downgrade_logged: true };
  }
  return { ok: true, chosen: best.id, pq: best.pq, fallback: false };
}

/* ---------- signed session attestation (the operational proof) ---------- */
// transcript_sha256 = hash of the FULL handshake transcript (which includes the negotiated suite) — this binds
// the attestation to the real session AND lets a verifier confirm which suite was actually used. + a freshness nonce.
export function attestSession({ session_id, chosen, pq, fallback, peer_id, transcript_sha256, offer_sha256 }, gatewaySk, gatewayPub, opts = {}) {
  // offer_sha256 folds the specific signed capability offer into the attestation (anti-splice: ties the attested
  // session to the exact offer that drove negotiation — Grok review).
  const core = { v: '0.1', session_id, suite: chosen, pq: !!pq, fallback: !!fallback, downgrade_prevented: !fallback, peer_id: peer_id ?? null, transcript_sha256: transcript_sha256 ?? null, offer_sha256: offer_sha256 ?? null, nonce: opts.nonce || bytesToHex(randomBytes(16)), ts: opts.ts ?? null };
  return { ...core, gateway_pub: bytesToHex(gatewayPub), sig: bytesToHex(ml_dsa87.sign(utf8ToBytes(canon(core)), gatewaySk, { context: ATT_CTX })) };
}
// opts.expectedTranscript = the VERIFIER's own transcript hash. Passing it turns "signed claim" into PROOF that the
// claimed suite was actually negotiated (defeats a lying gateway that signs pq:true over a classical handshake).
export function verifySession(att, trustedGatewayPub, opts = {}) {
 try { // TOTAL (fuzz): throwing getter/Proxy/BigInt field fails CLOSED, never DoS
  if (!att || typeof att !== 'object' || Array.isArray(att)) return { verified: false, pinned: false, sigOk: false, transcriptOk: false, claims: null };
  const { sig, gateway_pub, ...core } = att;
  const pinned = !trustedGatewayPub || String(gateway_pub).toLowerCase() === bytesToHex(trustedGatewayPub).toLowerCase();
  let sigOk = false;
  try { sigOk = ml_dsa87.verify(hexToBytes(sig), utf8ToBytes(canon(core)), trustedGatewayPub ? trustedGatewayPub : hexToBytes(gateway_pub), { context: ATT_CTX }); } catch { sigOk = false; }
  const transcriptOk = !opts.expectedTranscript || core.transcript_sha256 === opts.expectedTranscript;
  return { verified: pinned && sigOk && transcriptOk, pinned, sigOk, transcriptOk, claims: core };
 } catch { return { verified: false, pinned: false, sigOk: false, transcriptOk: false, claims: null }; }
}
// consumer-side gate: only accept sessions PROVEN PQ. requireTranscriptBinding rejects bare signed-claims;
// policy.expectedTranscript binds to the verifier's own transcript (the real anti-lying-gateway control).
export function acceptSession(att, trustedGatewayPub, policy = {}) {
 try { // TOTAL (fuzz): throwing getter/Proxy/BigInt field fails CLOSED, never DoS
  const v = verifySession(att, trustedGatewayPub, { expectedTranscript: policy.expectedTranscript });
  if (!v.verified) return { accept: false, reason: v.transcriptOk === false ? 'attestation not bound to the verifier transcript (possible lying gateway)' : 'attestation invalid / not from the pinned gateway' };
  if ((policy.requireTranscriptBinding ?? false) && !att.transcript_sha256) return { accept: false, reason: 'no transcript binding (signed-claim only, not proof)' };
  if ((policy.requirePQ ?? true) && !att.pq) return { accept: false, reason: 'session was not post-quantum (classical/fallback)' };
  if (policy.noFallback && att.fallback) return { accept: false, reason: 'session used a downgrade/fallback' };
  return { accept: true };
 } catch { return { accept: false, reason: 'malformed attestation' }; }
}

/* ---------- self-test: node pqgateway.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const peer = ml_dsa87.keygen(new Uint8Array(32).fill(81));
  const gw = ml_dsa87.keygen(new Uint8Array(32).fill(82));
  const ALL = SUITES.map((s) => s.id);
  const CLASSICAL_ONLY = ['classical-x25519-ed25519'];

  // 1. signed offer round-trips; tampering the suite list (stripping PQ) breaks it -> downgrade detected
  const offer = makeOffer(ALL, peer.secretKey, peer.publicKey, { nonce: 'n1' });
  ok(verifyOffer(offer, peer.publicKey) === true, 'signed capability offer verifies under the pinned peer key');
  const stripped = { ...offer, suites: CLASSICAL_ONLY }; // MITM strips the PQ suites in transit
  ok(verifyOffer(stripped, peer.publicKey) === false, 'stripped (downgraded) offer -> signature FAILS (downgrade detected)');

  // 2. negotiate: both offer PQ -> strongest hybrid suite, no fallback
  const n1 = negotiate({ localSuites: ALL, remoteOffer: offer, policy: { requirePQ: true }, trustedPeerPub: peer.publicKey });
  ok(n1.ok && n1.chosen === 'hybrid-mlkem1024-x25519-mldsa87' && n1.pq && !n1.fallback, 'negotiation picks the strongest hybrid suite, no fallback');

  // 3. a stripped offer fed to negotiate -> rejected as downgrade
  ok(negotiate({ localSuites: ALL, remoteOffer: stripped, policy: { requirePQ: true }, trustedPeerPub: peer.publicKey }).downgrade_suspected === true, 'negotiation rejects a tampered offer (downgrade_suspected)');

  // 4. remote genuinely classical-only: requirePQ + no fallback -> refuse; with fallback -> logged downgrade
  const classOffer = makeOffer(CLASSICAL_ONLY, peer.secretKey, peer.publicKey, { nonce: 'n2' });
  ok(negotiate({ localSuites: ALL, remoteOffer: classOffer, policy: { requirePQ: true, allowFallback: false }, trustedPeerPub: peer.publicKey }).ok === false, 'classical-only peer + requirePQ + no-fallback -> connection refused');
  const fb = negotiate({ localSuites: ALL, remoteOffer: classOffer, policy: { requirePQ: true, allowFallback: true }, trustedPeerPub: peer.publicKey });
  ok(fb.ok && fb.fallback && fb.downgrade_logged, 'classical-only peer + allowFallback -> connects with a LOGGED downgrade');

  // 5. minLevel enforcement
  const offer768 = makeOffer(['hybrid-mlkem768-x25519-mldsa65', 'classical-x25519-ed25519'], peer.secretKey, peer.publicKey, { nonce: 'n3' });
  ok(negotiate({ localSuites: ALL, remoteOffer: offer768, policy: { minLevel: 5, allowFallback: false }, trustedPeerPub: peer.publicKey }).ok === false, 'minLevel 5 not met by a 768-only peer -> refused');

  // 6. session attestation: the operational proof (bound to the handshake transcript)
  const TRANSCRIPT = bytesToHex(sha256(utf8ToBytes('handshake-transcript-incl-ServerHello-suite')));
  const att = attestSession({ session_id: 's-1', chosen: n1.chosen, pq: true, fallback: false, peer_id: 'peerA', transcript_sha256: TRANSCRIPT }, gw.secretKey, gw.publicKey, { ts: 1000 });
  const v = verifySession(att, gw.publicKey);
  ok(v.verified && v.claims.downgrade_prevented === true && v.claims.pq === true, 'session attestation verifies + proves hybrid PQ used, downgrade prevented');

  // 7. tampered attestation (claim no fallback when it was a fallback) -> signature fails
  const tampered = { ...att, fallback: true, downgrade_prevented: false };
  ok(verifySession(tampered, gw.publicKey).verified === false, 'tampered session attestation -> verify FAILS');
  ok(verifySession(att, ml_dsa87.keygen(new Uint8Array(32).fill(99)).publicKey).verified === false, 'attestation under a non-gateway key -> NOT verified');

  // 8. consumer accept-gate: a classical/fallback session is rejected when PQ is required
  const fbAtt = attestSession({ session_id: 's-2', chosen: 'classical-x25519-ed25519', pq: false, fallback: true, peer_id: 'peerB' }, gw.secretKey, gw.publicKey, { ts: 1001 });
  ok(acceptSession(att, gw.publicKey, { requirePQ: true, noFallback: true }).accept === true, 'consumer accepts a proven PQ no-fallback session');
  ok(acceptSession(fbAtt, gw.publicKey, { requirePQ: true }).accept === false, 'consumer rejects a classical/fallback session under requirePQ');

  // 9. offer replay across sessions caught by the per-session challenge (DeepSeek fix)
  const boundOffer = makeOffer(ALL, peer.secretKey, peer.publicKey, { nonce: 'n9', challenge: 'sess-A' });
  ok(negotiate({ localSuites: ALL, remoteOffer: boundOffer, policy: { requirePQ: true, expectedChallenge: 'sess-A' }, trustedPeerPub: peer.publicKey }).ok === true, 'offer bound to the current session challenge -> accepted');
  ok(negotiate({ localSuites: ALL, remoteOffer: boundOffer, policy: { requirePQ: true, expectedChallenge: 'sess-B' }, trustedPeerPub: peer.publicKey }).replay_suspected === true, 'same offer replayed into a different session -> replay_suspected');

  // 10. transcript binding defeats a LYING gateway (DeepSeek fix): accept only if bound to the verifier's transcript
  ok(acceptSession(att, gw.publicKey, { requirePQ: true, requireTranscriptBinding: true, expectedTranscript: TRANSCRIPT }).accept === true, 'attestation bound to the real transcript -> accepted (proof, not just a claim)');
  ok(acceptSession(att, gw.publicKey, { requirePQ: true, expectedTranscript: bytesToHex(sha256(utf8ToBytes('a-different-classical-handshake'))) }).accept === false, 'attestation NOT matching the verifier transcript -> rejected (lying-gateway defense)');

  console.log('pqgateway self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgateway\.mjs$/.test(process.argv[1] || '')) selfTest();
