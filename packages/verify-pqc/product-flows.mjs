/*!
 * product-flows — end-to-end product lifecycles through the real cores (integration evidence + runnable docs).
 *
 * Unit self-tests prove each core in isolation; this proves the cores DELIVER THE PRODUCT when composed — the
 * TRELYANShield, ThrondarAgent, SovereignMarket, and VaultHealth flows, each run start-to-finish with assertions on
 * the happy path AND the security-critical failure path. It is also the reference for how a product wires the cores.
 * No network, no keys on disk (in-memory test keys). Self-test: node product-flows.mjs
 */
import * as pqshield from './pqshield.mjs';
import * as pqcap from './pqcap.mjs';
import * as pqadmit from './pqadmit.mjs';
import * as pqconsent from './pqconsent.mjs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';

// in-memory hybrid keyset helper (TEST ONLY — never write secret keys to disk in production)
let _n = 0;
function keyset(withSlh) {
  _n += 2;
  const ks = { ed: { secretKey: new Uint8Array(32).fill(_n), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(_n)) }, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(_n + 1)) };
  if (withSlh) ks.slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(_n));
  return ks;
}
const pub = (ks) => ({ ed: ks.ed.publicKey, mldsa: ks.mldsa.publicKey, ...(ks.slh ? { slh: ks.slh.publicKey } : {}) });

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  /* ── FLOW 1 · TRELYANShield — Evidence Pack: scan → signed graded report → independently verify → migrate → re-score ── */
  {
    const issuer = keyset(true); const tIss = pub(issuer);
    const cbomBefore = [
      { label: 'edge-tls', algorithm: 'RSA-2048', internet_facing: true, sensitive: true }, // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
      { label: 'vpn', algorithm: 'ECDH-P256', internet_facing: true }, // pqcbom-ignore: self-test fixture string (scanned at runtime, not crypto use)
      { label: 'data-at-rest', algorithm: 'AES-256' },
      { label: 'svc-mesh', algorithm: 'Ed25519', internet_facing: true },
    ];
    const r1 = pqshield.createShieldReport({ issuerKeys: issuer, target: 'acme-bank/prod', assets: cbomBefore, standards: ['DORA', 'NIS2'], generatedAt: 100 });
    const v1 = pqshield.verifyShieldReport(r1, tIss);
    ok(v1.verified && (r1.grade === 'F' || r1.grade === 'D') && r1.red >= 2, 'Shield: a quantum-vulnerable estate scores high-risk (D/F) and the signed report independently verifies');
    ok(typeof r1.anchor_commitment === 'string' && pqshield.verifyShieldReport(r1, tIss, { expectedAnchor: r1.anchor_commitment }).verified, 'Shield: report is dual-anchor-ready (anchor_commitment binds + pins)');
    // a forged-clean grade over the SAME bad estate must not verify (the apex property, end-to-end)
    const forged = JSON.parse(JSON.stringify(r1)); forged.grade = 'A'; forged.red = 0; forged.risk_index = 3;
    ok(pqshield.verifyShieldReport(forged, tIss).verified === false, 'Shield: a forged clean grade over the same CBOM is REJECTED (grade is recomputed)');
    // migrate the vulnerable assets → re-score should improve (this is the product VALUE: measurable migration progress)
    const cbomAfter = cbomBefore.map((a) => a.algorithm.startsWith('AES') ? a : { ...a, algorithm: 'HYBRID-X25519-ML-KEM-768' });
    const r2 = pqshield.createShieldReport({ issuerKeys: issuer, target: 'acme-bank/prod', assets: cbomAfter, generatedAt: 200 });
    ok(pqshield.verifyShieldReport(r2, tIss).verified && (r2.grade === 'A' || r2.grade === 'B') && r2.red === 0, 'Shield: after migrating to hybrid-PQ, the re-scored report grades A/B with 0 RED — measurable progress');
  }

  /* ── FLOW 2 · ThrondarAgent — least-privilege tool authorization: mint capability → authorize in-scope, deny the rest ── */
  {
    const principal = keyset(); const agent = keyset(); const tIss = pub(principal);
    const cap = pqcap.issueCapability({ issuerKeys: principal, agent: pub(agent), tool: 'DatabaseQuery',
      caveats: { arg_prefix: { table: 'public.' }, arg_max: { limit: 100 }, arg_in: { op: ['select'] }, deny_unlisted: true },
      expiresAt: 1000, maxUses: 5, audience: 'orch-1', nonce: 'flow-cap' });
    const chal = 'req-001'; const pop = pqcap.proveHolder(agent, chal);
    const led = pqcap.makeUseLedger();
    const okReq = { tool: 'DatabaseQuery', args: { table: 'public.users', op: 'select', limit: 50 } };
    ok(pqcap.verifyAndConsume(cap, tIss, led, { request: okReq, now: 1, audience: 'orch-1', requireHolderProof: true, challenge: chal, holderProof: pop }).verified === true, 'Agent: an in-scope tool call by the bound holder is AUTHORIZED');
    ok(pqcap.verifyCapability(cap, tIss, { request: { tool: 'DatabaseQuery', args: { table: 'secret.creds', op: 'select', limit: 10 } }, now: 1, audience: 'orch-1', allowUnmeteredCheck: true }).verified === false, 'Agent: a request outside the table scope is DENIED');
    ok(pqcap.verifyCapability(cap, tIss, { request: { tool: 'DatabaseQuery', args: { table: 'public.users', op: 'select', limit: 50, raw_sql: 'DROP TABLE x' } }, now: 1, audience: 'orch-1', allowUnmeteredCheck: true }).verified === false, 'Agent: an extra unconstrained arg (raw_sql) is DENIED (no ambient-authority escalation)');
    ok(pqcap.verifyCapability(cap, tIss, { request: { tool: 'CodeExecutor', args: {} }, now: 1, audience: 'orch-1', allowUnmeteredCheck: true }).verified === false, 'Agent: the DatabaseQuery capability cannot authorize a different tool');
    const stolen = pqcap.proveHolder(keyset(), chal); // a thief who has the token but not the agent key
    ok(pqcap.verifyCapability(cap, tIss, { request: okReq, now: 1, audience: 'orch-1', requireHolderProof: true, challenge: chal, holderProof: stolen, allowUnmeteredCheck: true }).verified === false, 'Agent: a stolen token without the holder key is DENIED (holder PoP)');
  }

  /* ── FLOW 3 · SovereignMarket — app lifecycle: certify → admit the right build → block swap/rollback → revoke → deny ── */
  {
    const authority = keyset(true); const tAuth = pub(authority);
    const img_v2 = new Uint8Array(2048).fill(0x22);
    const cert = pqadmit.issueAppCert({ issuerKeys: authority, app: 'acme/api', version: '2.0.0', artifactBytes: img_v2, certLevel: 'SOVEREIGN_GOLD', checks: { cbom_pass: true, cve_pass: true, opa_pass: true, pqc_pass: true }, expiresAt: 1000 });
    ok(pqadmit.verifyAdmission(cert, tAuth, { artifactBytes: img_v2, now: 1, minCertLevel: 'SOVEREIGN_PLUS', minVersion: '1.9.0' }).verified === true, 'Market: the certified build at/above the policy floor is ADMITTED');
    ok(pqadmit.verifyAdmission(cert, tAuth, { artifactBytes: new Uint8Array(2048).fill(0x99), now: 1 }).verified === false, 'Market: a swapped binary (not the attested digest) is BLOCKED');
    ok(pqadmit.verifyAdmission(cert, tAuth, { artifactBytes: img_v2, now: 1, minVersion: '2.1.0' }).verified === false, 'Market: a rollback below the version floor is BLOCKED');
    const rev = pqadmit.revokeCert({ issuerKeys: authority, certId: cert.cert_id, reason: 'cve-2026-1', revokedAt: 5 });
    const denySet = new Set([pqadmit.verifyRevocation(rev, tAuth).cert_id]);
    ok(pqadmit.verifyAdmission(cert, tAuth, { artifactBytes: img_v2, now: 1, revoked: denySet }).verified === false, 'Market: once revoked, the same build is DENIED admission');
  }

  /* ── FLOW 4 · VaultHealth — consent lifecycle: subject grants scope → controller honors it → subject revokes → denied ── */
  {
    const patient = keyset(true);
    const receipt = pqconsent.grantConsent({ subjectKeys: patient, controller: 'vaulthealth', purposes: ['ai_coaching', 'doctor_share'], categories: ['HEART_RATE', 'SLEEP'], legalBasis: 'GDPR-Art-9-2-a-explicit', jurisdiction: 'EU', expiresAt: 1000, nonce: 'flow-consent' });
    ok(pqconsent.verifyConsent(receipt, { now: 1, controller: 'vaulthealth', purpose: 'doctor_share', category: 'HEART_RATE' }).verified === true, 'Health: the controller may process a granted (purpose × category) for the consenting subject');
    ok(pqconsent.verifyConsent(receipt, { now: 1, purpose: 'ad_targeting' }).verified === false, 'Health: an ungranted purpose (ad_targeting) is DENIED (deny-by-default)');
    const rev = pqconsent.revokeConsent({ subjectKeys: patient, receiptId: receipt.receipt_id, revokedAt: 5 });
    const denySet = new Set([pqconsent.verifyConsentRevocation(rev, receipt).receipt_id]);
    ok(pqconsent.verifyConsent(receipt, { now: 6, revoked: denySet, purpose: 'doctor_share', category: 'HEART_RATE' }).verified === false, 'Health: after the subject withdraws consent, processing is DENIED');
  }

  console.log('product-flows: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /product-flows\.mjs$/.test(process.argv[1] || '')) selfTest();
