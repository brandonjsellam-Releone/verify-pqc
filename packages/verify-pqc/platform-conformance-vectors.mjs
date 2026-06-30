/*!
 * platform-conformance-vectors — KAT / conformance vectors for the 4 platform engines (audit artifact, Sept+ audit).
 *
 * Same discipline as conformance-vectors.mjs: ML-DSA/SLH signing is HEDGED, so signature BYTES are NOT pinned — what
 * IS pinned (and reproducible by an independent party from the fixed seeds + inputs below) are the DETERMINISTIC
 * input-derived values: ids (monitor/gate/principal/agent/merchant/payer), the policy_id + cert_id, the monitor
 * ledger head hash, and the delegation parent_ref. (The flow genesis entry_hash is NOT pinned — it binds the hedged
 * auth signature, so it varies per run; only its deterministic ids are pinned.) Signature integrity is covered by
 * round-trip verify + negatives. Self-test: node platform-conformance-vectors.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import * as M from './pqmonitor.mjs';
import * as S from './pqshield.mjs';
import * as G from './pqgate.mjs';
import * as A from './pqadmit.mjs';
import * as F from './pqflow.mjs';
import * as P from './pqpay.mjs';
import * as D from './pqdelegate.mjs';
import * as C from './pqcap.mjs';

const ks = (e, m) => ({ ed: { secretKey: new Uint8Array(32).fill(e), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(e)) }, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(m)) });
const pub = (k) => ({ ed: k.ed.publicKey, mldsa: k.mldsa.publicKey });
const FW = new Uint8Array(64).fill(0x33);

const KAT = {
  mon_id: 'monitor:trelyan:b3c719bdcfbd87ce1d73743504bb423df85a131071852d1ff44dd9c5995ea8b2',
  mon_ledger_head: '9a71da1d02e3349660f5a66e1dbcf95a2296d9e11636d227499798ea91323db9',
  gate_id: 'gate:trelyan:6c8993672eff0978cfb60cee7335e76bd36ed2f278c2ce5865ffd68dc45a6f44',
  gate_policy_id: 'abd38909365b541bdd30c6eb765f426241e54fe33471c06761730d80e856175f',
  gate_cert_id: 'bf28c09018e75fb4567c98fe95328c0e6ae26bbe2766ae825fd7fa0f9855e8a1',
  flow_payer: 'pay:trelyan:50446b3b06114920187f7fe288b1ee154992966a64ce8a09c3fc8126f6ade8f2',
  flow_merchant: 'merchant:trelyan:7e17096c91c7a0f3622545792defcb9abb5fd44bfaff2ae00fcc29cda4a57108',
  del_principal: 'cap:trelyan:principal:v1:9d741effdfe44752edb20616e573d20aee0cd1ebe47e25cbac8429061ef721c7',
  del_agentA: 'cap:trelyan:agent:v1:c5a3462efe8dc4d30a00a489423fe56fa06fd5345eb52fe70f40f97532cf9673',
  del_parent_ref: '149b30fef9ffc8410389eb81039213c065f39ab6085dd6eb6571e340b9493bd0',
};

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // pqmonitor
  const mon = ks(1, 2), iss = ks(3, 4);
  const rep = S.createShieldReport({ issuerKeys: iss, target: 'kat', assets: [{ label: 'a', algorithm: 'RSA-2048', internet_facing: true }], generatedAt: 100 });
  const L = M.createLedger(); M.appendSnapshot(L, rep, pub(iss), { at: 100 });
  ok(M.makeMonitorId(mon) === KAT.mon_id, 'pqmonitor monitor id matches KAT');
  ok(M.verifyLedger(L).head_hash === KAT.mon_ledger_head && M.verifyLedger(L).intact === true, 'pqmonitor ledger head matches KAT + intact');
  const dg = M.signPostureDigest({ ledger: L, monitorKeys: mon, at: 100 });
  ok(M.verifyPostureDigest(dg, pub(mon), { ledger: L }).verified === true, 'pqmonitor digest round-trip verifies (recompute)');
  { const t = JSON.parse(JSON.stringify(L)); t.entries[0].snapshot.grade = 'A'; ok(M.verifyLedger(t).intact === false, 'pqmonitor negative: tampered ledger → not intact'); }

  // pqgate
  const gate = ks(5, 6), cIss = ks(7, 8), pAuth = ks(9, 10);
  const cert = A.issueAppCert({ issuerKeys: cIss, app: 'acme/api', version: '2.0.0', artifactBytes: FW, certLevel: 'SOVEREIGN_GOLD', checks: { cbom_pass: true, cve_pass: true, opa_pass: true, pqc_pass: true } });
  const pol = G.signPolicy({ authorityKeys: pAuth, app: 'acme/api', minCertLevel: 'SOVEREIGN_PLUS', minVersion: '1.0.0', at: 1 });
  ok(G.makeGateId(gate) === KAT.gate_id, 'pqgate gate id matches KAT');
  ok(pol.policy_id === KAT.gate_policy_id && cert.cert_id === KAT.gate_cert_id, 'pqgate policy_id + cert_id match KAT');
  const dec = G.admit({ cert, certIssuer: pub(cIss), policy: pol, policyAuthority: pub(pAuth), artifactBytes: FW, gateKeys: gate, now: 1 });
  ok(dec.allow === true && G.verifyDecision(dec, pub(gate), { cert, certIssuer: pub(cIss), policy: pol, policyAuthority: pub(pAuth), artifactBytes: FW, now: 1 }).verified === true, 'pqgate decision round-trip recompute-verifies');
  ok(G.verifyPolicy(pol, pub(gate)).verified === false, 'pqgate negative: policy under a wrong authority → not verified');

  // pqflow
  const merch = ks(11, 12), payer = ks(13, 14);
  const auth = P.createAuthorization({ payerKeys: payer, id: 'pay-kat', payee: 'm', amount: 10000, currency: 'USD', nonce: 'kat-n' });
  const led = P.makeNonceLedger();
  const flow = F.openFlow({ auth, payerPub: pub(payer), merchantKeys: merch, at: 1, seenNonces: led });
  ok(P.makePayerId(payer) === KAT.flow_payer && F.makeMerchantId(merch) === KAT.flow_merchant, 'pqflow payer + merchant ids match KAT');
  ok(flow.auth_id === 'pay-kat' && flow.transitions[0].type === 'authorize', 'pqflow genesis binds the auth id (entry_hash is NOT pinned — it binds the hedged auth signature)');
  ok(F.verifyFlow(flow, pub(merch), pub(payer)).verified === true, 'pqflow round-trip verifies');
  { let dbl = false; try { F.openFlow({ auth, payerPub: pub(payer), merchantKeys: merch, at: 2, seenNonces: led }); } catch { dbl = true; } ok(dbl, 'pqflow negative: re-opening the same auth (consumed nonce) → refused (no double-spend)'); }

  // pqdelegate
  const prin = ks(15, 16), agA = ks(17, 18), agB = ks(19, 20);
  const root = C.issueCapability({ issuerKeys: prin, agent: pub(agA), tool: 'DatabaseQuery', caveats: { arg_in: { op: ['select'] } }, audience: 'orch', nonce: 'kat-root' });
  const dlg = D.delegate({ delegatorKeys: agA, parent: root, delegatee: pub(agB), tool: 'DatabaseQuery', addedCaveats: { arg_max: { limit: 10 } }, audience: 'orch', nonce: 'kat-d' });
  ok(C.makePrincipalId(prin) === KAT.del_principal && C.makeAgentId(pub(agA)) === KAT.del_agentA, 'pqdelegate principal + agent ids match KAT');
  ok(dlg.parent_ref === KAT.del_parent_ref, 'pqdelegate parent_ref matches KAT');
  ok(D.verifyDelegationChain([root, dlg], pub(prin), { request: { tool: 'DatabaseQuery', args: { op: 'select', limit: 5 } }, now: 1, audience: 'orch' }).verified === true, 'pqdelegate chain round-trip verifies an in-bounds request');
  ok(D.verifyDelegationChain([root, dlg], pub(prin), { request: { tool: 'DatabaseQuery', args: { op: 'select', limit: 50 } }, now: 1, audience: 'orch' }).verified === false, 'pqdelegate negative: limit 50 > delegated 10 → rejected (attenuation)');

  console.log('platform-conformance-vectors: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /platform-conformance-vectors\.mjs$/.test(process.argv[1] || '')) selfTest();
