/*!
 * conformance-vectors — KAT / conformance vectors for the Wave-2 signed cores (audit artifact, for the Sept+ audit).
 *
 * @noble's ed25519 is deterministic, but ML-DSA-87 and SLH-DSA signing are HEDGED (randomized) — so signature BYTES
 * are intentionally non-reproducible and are NOT pinned. What IS deterministic — and IS pinned here as known-answer
 * vectors an independent party reproduces from the same fixed seeds + inputs — are the input-derived values: the
 * issuer/vendor/agent/authority/subject/payer IDs, the did:trelyan, and the derived commitments (assets_hash, grade,
 * cert_id, receipt_id, anchor_commitment, artifact_sha256). Signature integrity is covered by ROUND-TRIP verify +
 * NEGATIVE cases (a freshly-signed artifact must verify; a tampered one must not).
 *
 * Reproduce: same seeds (ed=fill(n), mldsa=keygen(fill(n+1))) + same inputs → identical IDs/commitments below.
 * Self-test: node conformance-vectors.mjs
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import * as S from './pqshield.mjs';
import * as F from './pqfirmware.mjs';
import * as V from './pqvc.mjs';
import * as C from './pqcap.mjs';
import * as A from './pqadmit.mjs';
import * as N from './pqconsent.mjs';
import * as P from './pqpay.mjs';

const ks = (e, m) => ({ ed: { secretKey: new Uint8Array(32).fill(e), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(e)) }, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(m)) });
const pub = (k) => ({ ed: k.ed.publicKey, mldsa: k.mldsa.publicKey });
const ASSETS = [{ label: 'a', algorithm: 'RSA-2048', internet_facing: true, sensitive: true }, { label: 'b', algorithm: 'AES-256' }]; // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
const FW = new Uint8Array(256).fill(0x7a);

// ── pinned known-answer values (reproduced from the fixed seeds + inputs above) ──
const KAT = {
  shield_issuer: 'shield:trelyan:bf86430e5ad55ee23ce787ec470b260cf989f4f914367445cd31d6ce49d74dbc',
  shield_assets_hash: '180e9eb9bdb64bd5058ccf1f71072b20397262bbc31730877601fbe559d59fd1',
  shield_anchor: '90cef24a9c50559b2e60a58871e0de28fccdba02febf711949435d5370b3d754',
  shield_grade: 'F', shield_risk: 55, shield_red: 1, shield_green: 1,
  fw_vendor: 'vendor:trelyan:af45d87733eee2c051aa11b09d768db7ddf5d616b087c73238403c17ff546c6e',
  fw_artifact_sha256: 'fcc0108770388f352679507ffcf73b79716e81ff5c20f9bf5257af737d001514',
  vc_did: 'did:trelyan:fe142a0ec4614c4e10c06f2c992902a1c425331289348dbc47d8620e4b2072a3',
  cap_principal: 'cap:trelyan:principal:v1:ce1ec8b9a75635f74c2644ae88652c0e962cfe1b0fa438d4a0e42896bbd98209',
  cap_agent: 'cap:trelyan:agent:v1:3a9db6aa075f53b7cad3feb8feaf3f115be701366a613d88724cb0f3b903c29f',
  admit_authority: 'admit:trelyan:authority:v1:47d041938f9ab06b1a8e09d225a8b7c5c700d7dcb9c12fed3dd1808257986064',
  admit_cert_id: 'a373c9e9e12c8defb52544159c13b60f1aa5e443850dffc028e400bd59f5759f',
  admit_anchor: '671f6ae064d9b29cf5c7b84de88049e40b50131e5ce0f2eadacedf55190c0ab4',
  consent_subject: 'consent:trelyan:subject:v1:de8911889c5929486e03e31adf82e485e270fd8b025d1957f8fb5ed0d790c7e2',
  consent_receipt_id: '2fabf9f6d43dc5eff045c7eaae61cdbb51b3df6e39c91e8735b4b6d246fb58d7',
  pay_payer: 'pay:trelyan:be463b6ec611b2593e07cf948721fcb6d4e96fea9bf799fe9f66918b2eccb3ff',
};

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // pqshield
  const si = ks(1, 2);
  const rep = S.createShieldReport({ issuerKeys: si, target: 'kat', assets: ASSETS, generatedAt: 1000 });
  ok(S.makeIssuerId(si) === KAT.shield_issuer, 'pqshield issuer id matches KAT');
  ok(rep.assets_hash === KAT.shield_assets_hash && rep.anchor_commitment === KAT.shield_anchor, 'pqshield assets_hash + anchor match KAT');
  ok(rep.grade === KAT.shield_grade && rep.risk_index === KAT.shield_risk && rep.red === KAT.shield_red && rep.green === KAT.shield_green, 'pqshield grade/risk/counts match KAT');
  ok(S.verifyShieldReport(rep, pub(si)).verified === true, 'pqshield round-trip verifies');
  const sT = JSON.parse(JSON.stringify(rep)); sT.grade = 'A';
  ok(S.verifyShieldReport(sT, pub(si)).verified === false, 'pqshield negative: forged grade rejected');

  // pqfirmware
  const fv = ks(11, 12);
  const man = F.signFirmware({ vendorKeys: fv, deviceModel: 'M', version: 7, buildId: 'b7', artifactBytes: FW });
  ok(F.makeVendorId(fv) === KAT.fw_vendor, 'pqfirmware vendor id matches KAT');
  ok(man.artifact_sha256 === KAT.fw_artifact_sha256, 'pqfirmware artifact_sha256 matches KAT');
  ok(F.verifyFirmware(man, pub(fv), { artifactBytes: FW, currentVersion: 6, deviceModel: 'M' }).verified === true, 'pqfirmware round-trip verifies');
  ok(F.verifyFirmware(man, pub(fv), { artifactBytes: new Uint8Array(256).fill(9), currentVersion: 6 }).verified === false, 'pqfirmware negative: tampered binary rejected');

  // pqvc
  const vi = ks(21, 22), vsub = ks(23, 24);
  ok(V.makeDid(vi) === KAT.vc_did, 'pqvc issuer did matches KAT');
  const { vc } = V.issueCredential({ issuerKeys: vi, subjectDid: V.makeDid(vsub), claims: { role: 'supplier' }, id: 'vc-kat' });
  ok(V.verifyCredential(vc, pub(vi)).verified === true, 'pqvc round-trip verifies');
  const vT = JSON.parse(JSON.stringify(vc)); vT.subject = 'did:trelyan:ffff';
  ok(V.verifyCredential(vT, pub(vi)).verified === false, 'pqvc negative: tampered subject rejected');

  // pqcap
  const cp = ks(31, 32), ca = ks(33, 34);
  ok(C.makePrincipalId(cp) === KAT.cap_principal && C.makeAgentId(ca) === KAT.cap_agent, 'pqcap principal + agent ids match KAT');
  const cap = C.issueCapability({ issuerKeys: cp, agent: pub(ca), tool: 'T', caveats: { arg_in: { op: ['read'] } }, nonce: 'kat-cap' });
  ok(C.verifyCapability(cap, pub(cp), { request: { tool: 'T', args: { op: 'read' } } }).verified === true, 'pqcap round-trip verifies an in-scope request');
  ok(C.verifyCapability(cap, pub(cp), { request: { tool: 'T', args: { op: 'write' } } }).verified === false, 'pqcap negative: out-of-scope request rejected');

  // pqadmit
  const aa = ks(41, 42);
  const cert = A.issueAppCert({ issuerKeys: aa, app: 'acme/api', version: '2.0.0', artifactBytes: FW, certLevel: 'SOVEREIGN_GOLD', checks: { cbom_pass: true, cve_pass: true, opa_pass: true, pqc_pass: true } });
  ok(A.makeAuthorityId(aa) === KAT.admit_authority, 'pqadmit authority id matches KAT');
  ok(cert.cert_id === KAT.admit_cert_id && cert.anchor_commitment === KAT.admit_anchor, 'pqadmit cert_id + anchor match KAT');
  ok(A.verifyAdmission(cert, pub(aa), { artifactBytes: FW }).verified === true, 'pqadmit round-trip admits');
  ok(A.verifyAdmission(cert, pub(aa), { artifactBytes: new Uint8Array(256).fill(9) }).verified === false, 'pqadmit negative: swapped artifact rejected');

  // pqconsent
  const ns = ks(51, 52);
  const rcpt = N.grantConsent({ subjectKeys: ns, controller: 'vh', purposes: ['p1'], categories: ['c1'], legalBasis: 'GDPR-Art-9-2-a', nonce: 'kat-n' });
  ok(N.makeSubjectId(ns) === KAT.consent_subject, 'pqconsent subject id matches KAT');
  ok(rcpt.receipt_id === KAT.consent_receipt_id, 'pqconsent receipt_id matches KAT');
  ok(N.verifyConsent(rcpt, { purpose: 'p1', category: 'c1' }).verified === true, 'pqconsent round-trip verifies in-scope');
  ok(N.verifyConsent(rcpt, { purpose: 'p2' }).verified === false, 'pqconsent negative: ungranted purpose rejected');

  // pqpay
  const pp = ks(61, 62);
  ok(P.makePayerId(pp) === KAT.pay_payer, 'pqpay payer id matches KAT');
  const auth = P.createAuthorization({ payerKeys: pp, id: 'pay-kat', payee: 'm', amount: 100, currency: 'USD', nonce: 'kat-pay' });
  ok(P.verifyAuthorization(auth, pub(pp), { allowUnmeteredCheck: true }).verified === true, 'pqpay round-trip verifies');

  console.log('conformance-vectors: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /conformance-vectors\.mjs$/.test(process.argv[1] || '')) selfTest();
