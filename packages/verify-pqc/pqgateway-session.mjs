/*!
 * pqgateway-session — no-forklift PQC gateway, WIRED CLIENT↔GATEWAY LEG: signed offer → negotiate → REAL hybrid
 * handshake → transcript-bound session attestation (+ optional client countersignature) (reference, DRAFT).
 *
 * Closes the loop the council asked for: pqgateway gives the policy/negotiation/attestation core, pqtransport gives
 * the real mutually-authenticated hybrid X25519+ML-KEM-1024 / ML-DSA-87 handshake. Here they're wired so the
 * gateway's SESSION ATTESTATION binds the ACTUAL handshake transcript hash (th) — not an opaque/fabricated value.
 *
 * WHAT THE EVIDENCE PROVES (honest, per Grok review):
 *  - A handshake PARTICIPANT (the client) verifies the attestation against the th IT independently derived → it
 *    cannot be fooled by a gateway that signs pq:true over a classical handshake (participant-verifiable).
 *  - A PASSIVE AUDITOR who did NOT run the handshake canNOT recompute th, so a bare gateway attestation is NOT
 *    transferable proof to them. For TRANSFERABLE evidence, the client adds a COUNTERSIGNATURE over the same th
 *    (`clientCountersign`/`verifyMutualAttestation`): two independently-pinned parties signed the SAME transcript,
 *    which an auditor can check. This still does NOT defend client+gateway COLLUSION.
 *  - SCOPE: this attests the CLIENT↔GATEWAY leg ONLY. The gateway terminates the hybrid-PQ TLS and sees plaintext;
 *    the gateway↔backend leg is a SEPARATE session with its own (possibly classical) posture. NOT end-to-end PQ.
 *
 * Trust model: client and gateway each use ONE ML-DSA-87 identity for the capability offer + handshake auth +
 * attestation, domain-separated by distinct signing contexts (OFFER/AUTH_I/AUTH_R/ATT/CLIENT_ATT). Contexts are the
 * floor; production SHOULD use a separate attestation key per role. Pin peer identities for downgrade protection.
 * The attested offer_sha256 folds the specific offer into the attestation (anti-splice). HONEST LIMIT: pqtransport
 * implements only the hybrid-1024 suite, so the wiring requires the negotiated suite to map to it. Self-test: node pqgateway-session.mjs
 */
import * as gw from './pqgateway.mjs';
import * as tp from './pqtransport.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const CLIENT_ATT_CTX = utf8ToBytes('trelyan-gateway-client-countersig-v1');
const offerFingerprint = (offer) => bytesToHex(sha256(utf8ToBytes(offer.sig))); // the offer signature uniquely fingerprints the signed offer

// the gateway suite id the negotiation selects -> the transport suite actually implemented
export const SUITE_MAP = { 'hybrid-mlkem1024-x25519-mldsa87': tp.SUITE_ID };

// CLIENT (initiator): signed capability offer (bound to the gateway's session challenge) + handshake msg1
export function clientStart(clientId, suiteIds, opts = {}) {
  const offer = gw.makeOffer(suiteIds, clientId.secretKey, clientId.publicKey, { challenge: opts.challenge, nonce: opts.nonce, ts: opts.ts });
  const { state, msg1 } = tp.initiatorStart(clientId, opts);
  return { offer, msg1, istate: state };
}

// GATEWAY (responder): verify+negotiate the offer, then run the real handshake response (msg2)
export function gatewayRespond({ offer, msg1 }, gatewayId, { localSuites, policy = {}, trustedClientPub } = {}) {
  const neg = gw.negotiate({ localSuites, remoteOffer: offer, policy, trustedPeerPub: trustedClientPub });
  if (!neg.ok) return { ok: false, neg };
  if (SUITE_MAP[neg.chosen] !== tp.SUITE_ID) return { ok: false, neg, reason: 'negotiated suite ' + neg.chosen + ' has no PQ transport implementation (gateway speaks ' + tp.SUITE_ID + ')' };
  const { state, msg2 } = tp.responderRespond(msg1, gatewayId);
  return { ok: true, neg, msg2, rstate: state, offer_sha256: offerFingerprint(offer) };
}

// CLIENT: finish the handshake (auth + pin the gateway), obtaining the transcript hash th + session keys
export function clientFinish(msg2, istate, clientId, expectedGatewayPubHex) {
  return tp.initiatorFinish(msg2, istate, clientId, expectedGatewayPubHex); // -> { msg3, session, th, R_auth_ok, ... }
}

// GATEWAY: finish the handshake (auth + pin the client), then SIGN the session attestation bound to the real th
export function gatewayFinishAndAttest(msg3, rstate, neg, gatewayId, expectedClientPubHex, meta = {}, opts = {}) {
  const fin = tp.responderFinish(msg3, rstate, expectedClientPubHex); // -> { session, th, I_auth_ok, ... }
  if (!fin.I_auth_ok) return { ok: false, fin, reason: 'client authentication failed in the handshake' };
  const att = gw.attestSession(
    { session_id: meta.session_id ?? null, chosen: neg.chosen, pq: neg.pq, fallback: !!neg.fallback, peer_id: meta.peer_id ?? null, transcript_sha256: fin.th, offer_sha256: meta.offer_sha256 ?? null },
    gatewayId.secretKey, gatewayId.publicKey, { nonce: opts.nonce, ts: opts.ts });
  return { ok: true, fin, att };
}

// CLIENT/auditor: accept ONLY if the attestation is bound to the transcript THIS party independently derived (th)
export function clientAccept(att, gatewayPub, clientTh, policy = {}) {
  return gw.acceptSession(att, gatewayPub, { requirePQ: policy.requirePQ ?? true, noFallback: policy.noFallback ?? true, requireTranscriptBinding: true, expectedTranscript: clientTh });
}

// CLIENT countersignature -> TRANSFERABLE evidence: the client signs the same th the gateway attested. Returns a
// bundle {att, client_pub, client_sig} (kept SEPARATE from att so the gateway signature still verifies).
export function clientCountersign(att, clientId) {
  const sig = ml_dsa87.sign(utf8ToBytes(att.transcript_sha256 ?? ''), clientId.secretKey, { context: CLIENT_ATT_CTX });
  return { att, client_pub: bytesToHex(clientId.publicKey), client_sig: bytesToHex(sig) };
}
// AUDITOR: verify BOTH the gateway attestation and the client countersignature over the SAME th. Two independently-
// pinned parties agreeing on the transcript = transferable evidence a lying gateway alone cannot forge.
export function verifyMutualAttestation(bundle, gatewayPub, clientPub, opts = {}) {
  const g = gw.verifySession(bundle.att, gatewayPub, { expectedTranscript: opts.expectedTranscript });
  const clientPinned = !clientPub || bundle.client_pub.toLowerCase() === bytesToHex(clientPub).toLowerCase();
  let clientSigOk = false;
  try { clientSigOk = ml_dsa87.verify(hexToBytes(bundle.client_sig), utf8ToBytes(bundle.att.transcript_sha256 ?? ''), clientPub ? clientPub : hexToBytes(bundle.client_pub), { context: CLIENT_ATT_CTX }); } catch { clientSigOk = false; }
  return { verified: g.verified && clientPinned && clientSigOk, gateway: g, clientSigOk, clientPinned,
    note: 'transferable vs a LYING gateway (two pinned parties signed the same th); does NOT defend client+gateway COLLUSION; covers the CLIENT↔GATEWAY leg ONLY (not gateway↔backend).' };
}

// convenience: run the full in-process exchange (reference / self-test)
export function runAttestedSession({ clientId, gatewayId, localSuites, clientSuites, policy = {}, challenge, meta = {} }) {
  const c1 = clientStart(clientId, clientSuites, { challenge });
  const g1 = gatewayRespond({ offer: c1.offer, msg1: c1.msg1 }, gatewayId, { localSuites, policy: { ...policy, expectedChallenge: challenge }, trustedClientPub: clientId.publicKey });
  if (!g1.ok) return { ok: false, stage: 'negotiate', detail: g1 };
  const c2 = clientFinish(g1.msg2, c1.istate, clientId, bytesToHex(gatewayId.publicKey));
  if (!c2.R_auth_ok) return { ok: false, stage: 'client-auth', detail: c2 };
  const g2 = gatewayFinishAndAttest(c2.msg3, g1.rstate, g1.neg, gatewayId, bytesToHex(clientId.publicKey), { ...meta, offer_sha256: g1.offer_sha256 });
  if (!g2.ok) return { ok: false, stage: 'gateway-attest', detail: g2 };
  const accepted = clientAccept(g2.att, gatewayId.publicKey, c2.th, policy);
  const bundle = clientCountersign(g2.att, clientId); // transferable mutual attestation
  return { ok: true, neg: g1.neg, client_th: c2.th, gateway_th: g2.fin.th, att: g2.att, bundle, accepted, offer_sha256: g1.offer_sha256, sessionKeysAgree: bytesToHex(c2.session.i2r) === bytesToHex(g2.fin.session.i2r) };
}

/* ---------- self-test: node pqgateway-session.mjs ---------- */
function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const client = tp.generateIdentity(new Uint8Array(32).fill(11));
  const gateway = tp.generateIdentity(new Uint8Array(32).fill(22));
  const ALL = gw.SUITES.map((s) => s.id);

  // 1. happy path: end-to-end attested PQ session
  const r = runAttestedSession({ clientId: client, gatewayId: gateway, localSuites: ALL, clientSuites: ALL, policy: { requirePQ: true }, challenge: 'sess-XYZ', meta: { session_id: 's1', peer_id: 'clientA' } });
  ok(r.ok && r.neg.chosen === 'hybrid-mlkem1024-x25519-mldsa87' && r.neg.pq, 'end-to-end negotiates the strongest hybrid suite');
  ok(r.sessionKeysAgree === true, 'client and gateway derive identical session keys (real handshake ran)');
  ok(r.client_th === r.gateway_th, 'both parties independently derive the SAME transcript hash th');
  ok(r.accepted.accept === true, 'client accepts: attestation is PROVEN-bound to the transcript it derived (real PQ)');
  ok(r.att.transcript_sha256 === r.client_th && r.att.pq === true && r.att.downgrade_prevented === true, 'attestation binds the real th + proves PQ + downgrade prevented');
  ok(r.att.offer_sha256 === r.offer_sha256 && r.offer_sha256, 'the specific signed offer is folded into the attestation (anti-splice)');

  // 1b. TRANSFERABLE mutual attestation: an AUDITOR verifies BOTH gateway + client signatures over the same th
  const m = verifyMutualAttestation(r.bundle, gateway.publicKey, client.publicKey, { expectedTranscript: r.client_th });
  ok(m.verified === true && m.clientSigOk && m.gateway.verified, 'auditor verifies mutual attestation (gateway + client both signed the same th) — transferable evidence');
  const forgedBundle = { ...r.bundle, client_sig: r.bundle.client_sig.slice(0, -2) + (r.bundle.client_sig.endsWith('00') ? '11' : '00') };
  ok(verifyMutualAttestation(forgedBundle, gateway.publicKey, client.publicKey, { expectedTranscript: r.client_th }).verified === false, 'a gateway alone cannot forge the client countersignature -> mutual attestation FAILS');

  // 2. LYING gateway: attest a fabricated (classical) transcript instead of the real th -> client rejects
  const c1 = clientStart(client, ALL, { challenge: 'sess-LIE' });
  const g1 = gatewayRespond({ offer: c1.offer, msg1: c1.msg1 }, gateway, { localSuites: ALL, policy: { requirePQ: true, expectedChallenge: 'sess-LIE' }, trustedClientPub: client.publicKey });
  const c2 = clientFinish(g1.msg2, c1.istate, client, bytesToHex(gateway.publicKey));
  const fakeTh = bytesToHex(sha256(utf8ToBytes('a-classical-handshake-the-gateway-never-ran')));
  const lyingAtt = gw.attestSession({ session_id: 's-lie', chosen: 'hybrid-mlkem1024-x25519-mldsa87', pq: true, fallback: false, peer_id: 'x', transcript_sha256: fakeTh }, gateway.secretKey, gateway.publicKey, { ts: 1 });
  ok(clientAccept(lyingAtt, gateway.publicKey, c2.th, { requirePQ: true }).accept === false, 'LYING gateway (attestation not bound to the client transcript) -> REJECTED');

  // 3. downgrade: MITM strips PQ suites from the offer in transit -> gateway negotiation detects it, no session
  const c1d = clientStart(client, ALL, { challenge: 'sess-DG' });
  const strippedOffer = { ...c1d.offer, suites: ['classical-x25519-ed25519'] };
  const gd = gatewayRespond({ offer: strippedOffer, msg1: c1d.msg1 }, gateway, { localSuites: ALL, policy: { requirePQ: true, expectedChallenge: 'sess-DG' }, trustedClientPub: client.publicKey });
  ok(gd.ok === false && gd.neg.downgrade_suspected === true, 'MITM-stripped offer -> gateway detects downgrade, refuses to proceed');

  // 4. MITM identity: a fake gateway answers; client pins the REAL gateway -> handshake auth fails
  const fakeGw = tp.generateIdentity(new Uint8Array(32).fill(99));
  const c1m = clientStart(client, ALL, { challenge: 'sess-MITM' });
  const gm = gatewayRespond({ offer: c1m.offer, msg1: c1m.msg1 }, fakeGw, { localSuites: ALL, policy: { requirePQ: true, expectedChallenge: 'sess-MITM' }, trustedClientPub: client.publicKey });
  const c2m = clientFinish(gm.msg2, c1m.istate, client, bytesToHex(gateway.publicKey)); // client pins the real gateway
  ok(c2m.R_auth_ok === false, 'MITM gateway with the wrong identity -> client handshake auth FAILS (pin mismatch)');

  // 5. replayed offer (wrong session challenge) -> rejected
  const c1r = clientStart(client, ALL, { challenge: 'sess-A' });
  const gr = gatewayRespond({ offer: c1r.offer, msg1: c1r.msg1 }, gateway, { localSuites: ALL, policy: { requirePQ: true, expectedChallenge: 'sess-B' }, trustedClientPub: client.publicKey });
  ok(gr.ok === false && gr.neg.replay_suspected === true, 'offer replayed into a different session challenge -> rejected');

  console.log('pqgateway-session self-test: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /pqgateway-session\.mjs$/.test(process.argv[1] || '')) selfTest();
