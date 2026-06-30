/*!
 * tamper-binding — demonstrates SIGNATURE COVERAGE for every signing verifier (audit artifact; test evidence, not a formal proof).
 *
 * The council's convergent crypto-soundness question was "is every signed field actually BOUND, or is there a
 * signed-vs-checked mismatch (a field the guard reads but the signature does NOT cover)?" This harness answers it
 * MECHANICALLY, the way an auditor does:
 *   1. build a VALID signed object  -> assert it verifies TRUE.
 *   2. for EVERY leaf in the object, flip one byte/char/number and re-verify:
 *        - if the field is inside the signed core -> verification MUST become FALSE (the field is bound).
 *        - if the field is intentionally OUTSIDE the signed core (documented) -> verification stays TRUE, and the
 *          harness RECORDS it explicitly so an unsigned field can never hide silently / regress unnoticed.
 *   3. KEY-BINDING: swap the embedded public key to a DIFFERENT key -> verification MUST become FALSE.
 * No mutation may turn an INVALID object valid (that's the fuzz harness's job); here every mutation starts from VALID.
 * Self-test: node tamper-binding.mjs
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import * as pqmarket from './pqmarket.mjs';
import * as pqpki from './pqpki.mjs';
import * as pqindex from './pqindex.mjs';
import * as pqgateway from './pqgateway.mjs';
import * as pqtsa from './pqtsa.mjs';
import * as pqx3dh from './pqx3dh.mjs';
import * as pqsign from './pqsign.mjs';
import * as pqcbom from './pqcbom.mjs';
import * as pqcbomReport from './pqcbom-report.mjs';
import * as pqseal from './pqseal.mjs';
import { ed25519 } from '@noble/curves/ed25519.js';
import * as pqcompliance from './pqcompliance.mjs';
import * as pqkt from './pqkt.mjs';
import * as pqclaimgate from './pqclaimgate.mjs';
import * as pqshield from './pqshield.mjs';
import * as pqmonitor from './pqmonitor.mjs';
import * as pqgate from './pqgate.mjs';
import * as pqadmit from './pqadmit.mjs';
import * as pqcap from './pqcap.mjs';
import * as pqconsent from './pqconsent.mjs';
import * as pqpay from './pqpay.mjs';
import * as pqvc from './pqvc.mjs';
import * as pqfirmware from './pqfirmware.mjs';
import * as pqflow from './pqflow.mjs';
import * as pqdelegate from './pqdelegate.mjs';

const seed = (n) => new Uint8Array(32).fill(n);
// flip one leaf to a DIFFERENT same-typed value (hex-safe for hex strings)
const mutate = (v) => {
  if (typeof v === 'string') return v.length ? (v[0] === '0' ? 'f' : '0') + v.slice(1) : 'x';
  if (typeof v === 'number') return v + 1;
  if (typeof v === 'boolean') return !v;
  if (v === null) return 'tampered';
  return v;
};
// every leaf path (string/number/boolean/null) in an object, as a dotted path
function leafPaths(v, base = '') {
  if (v === null || typeof v !== 'object') return base ? [base] : [];
  const out = [];
  for (const k of Object.keys(v)) out.push(...leafPaths(v[k], base ? base + '.' + k : k));
  return out;
}
function setAt(obj, path, val) {
  const parts = path.split('.'); let o = obj;
  for (let i = 0; i < parts.length - 1; i++) o = o[parts[i]];
  o[parts[parts.length - 1]] = val;
}
function getAt(obj, path) { return path.split('.').reduce((o, p) => (o == null ? o : o[p]), obj); }

// scenario: { label, obj, verify(obj)->truthy=accept, unbound: Set<path> EXPECTED to stay valid when tampered (documented), skipPaths }
function runScenario(s, ok) {
  ok(!!s.verify(s.obj), s.label + ': VALID object verifies TRUE (baseline)');
  const paths = leafPaths(s.obj).filter((p) => !(s.skipPaths || []).some((sp) => p === sp || p.startsWith(sp + '.')));
  let bound = 0, documentedUnbound = 0;
  for (const p of paths) {
    const clone = structuredClone(s.obj);
    const orig = getAt(clone, p);
    setAt(clone, p, mutate(orig));
    const stillValid = !!s.verify(clone);
    if (s.unbound && s.unbound.has(p)) {
      ok(stillValid, s.label + ': "' + p + '" is DOCUMENTED-unsigned and stays valid when tampered (recorded, not silent)');
      documentedUnbound++;
    } else {
      ok(!stillValid, s.label + ': tampering signed field "' + p + '" -> verification FALSE (field is bound)');
      bound++;
    }
  }
  console.log('  ' + s.label + ': ' + bound + ' signed fields proven bound' + (documentedUnbound ? ', ' + documentedUnbound + ' documented-unsigned' : ''));
}

function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

  // 1) pqmarket capability listing — every non-sig field is in the signed core; agent_pub also binds agent_id
  const agent = pqmarket.generateAgent(seed(11));
  const listing = pqmarket.publishCapability({ agent, capabilities: ['pq-sign', 'attest'], claims: { region: 'eu' } }, { ts: 100, validFrom: 0, expiresAt: 1e9 });
  runScenario({ label: 'pqmarket.verifyListing', obj: listing, verify: (o) => pqmarket.verifyListing(o, agent.publicKey), skipPaths: ['sig'] }, ok);
  // KEY-BINDING: a different agent key must not verify this listing under the original pin
  const other = pqmarket.generateAgent(seed(12));
  ok(!pqmarket.verifyListing({ ...listing, agent_pub: bytesToHex(other.publicKey), agent_id: pqmarket.agentIdOf(other.publicKey) }, agent.publicKey), 'pqmarket.verifyListing: swapped agent key -> FALSE (key binding)');

  // 2) pqpki hybrid cert — the whole tbs is signed (ML-DSA + Ed25519); signatures must also match
  const ca = pqpki.generateIdentity(seed(21));
  const subj = pqpki.generateIdentity(seed(22));
  const cert = pqpki.issueCert({ subject: 'cn=subject', subjectPub: pqpki.pubOf(subj), ca, caCert: null, serial: 'sn-1', notBefore: 0, notAfter: 1e9, isCA: false });
  runScenario({ label: 'pqpki.verifyCert', obj: cert, verify: (o) => pqpki.verifyCert(o, pqpki.pubOf(ca), { at: 10 }).verified }, ok);

  // 3) pqindex signed shard — SHARD_CORE binds {merkle_root,tree_size,version,term_range}; terms bind via root recompute
  const idx = ml_dsa87.keygen(seed(31));
  const shard = pqindex.buildSignedShard({ term_range: ['a', 'z'], terms: [{ term: 'alpha', postings: [1, 2] }, { term: 'beta', postings: [3] }], version: 1 }, idx.secretKey, idx.publicKey);
  runScenario({ label: 'pqindex.verifyShard', obj: shard, verify: (o) => pqindex.verifyShard(o, idx.publicKey).verified, skipPaths: ['sig'] }, ok);

  // 4) pqgateway session attestation — every claim in core is signed; gateway_pub is the verify key
  const gw = ml_dsa87.keygen(seed(41));
  const att = pqgateway.attestSession({ session_id: 's1', chosen: 'hybrid-mlkem1024-x25519-mldsa87', pq: true, fallback: false, peer_id: 'peer', transcript_sha256: 'aa'.repeat(32), offer_sha256: 'bb'.repeat(32) }, gw.secretKey, gw.publicKey);
  runScenario({ label: 'pqgateway.verifySession', obj: att, verify: (o) => pqgateway.verifySession(o, gw.publicKey).verified, skipPaths: ['sig'] }, ok);

  // 5) pqtsa timestamp token — core (content/serial/nonce/policy/time) signed; tsa_pub is the verify key, cosigs excluded
  const tsa = ml_dsa87.keygen(seed(51));
  const tst = pqtsa.timestamp({ content_sha256: 'cc'.repeat(32), serial: 'tsn-1', nonce: 'dd'.repeat(16), policy: 'p1' }, tsa.secretKey, tsa.publicKey, { ts: 1000 });
  runScenario({ label: 'pqtsa.verifyTimestamp', obj: tst, verify: (o) => pqtsa.verifyTimestamp(o, tsa.publicKey).verified, skipPaths: ['sig', 'cosigs'] }, ok);

  // 6) pqx3dh prekey bundle — bundle_sig now covers ALL prekeys incl. the one-time KEM/DH prekeys (this harness CAUGHT
  //    them unsigned; fixed to match Signal PQXDH — under HNDL an active attacker could substitute an unsigned one-time
  //    PQ prekey and defeat the PQ leg). ik_sig_pub is the verify key (tamper -> wrong-key verify fails => also bound).
  const id = pqx3dh.generateIdentity(seed(61));
  const { bundle } = pqx3dh.publishPrekeyBundle(id, { oneTimeKem: true, oneTime: true });
  runScenario({ label: 'pqx3dh.verifyPrekeyBundle', obj: bundle, verify: (o) => pqx3dh.verifyPrekeyBundle(o) === true, skipPaths: ['bundle_sig'] }, ok);

  // 7) pqsign full bundle — the transparency SPINE: att (signer-signed) + inclusion proof (recomputed) + STH (log-signed)
  const signer = ml_dsa87.keygen(seed(71)), logKp = ml_dsa87.keygen(seed(72));
  const sAtt = pqsign.signArtifact(utf8ToBytes('artifact-payload'), signer.secretKey, { project: 'p1' }, { ts: 100 });
  const log = new pqsign.PQTransparencyLog(); const li = log.append(sAtt);
  const sth = log.signedTreeHead(logKp.secretKey, { ts: 200 });
  const spineBundle = { att: sAtt, inclusion: log.inclusion(li), sth };
  runScenario({ label: 'pqsign.verifyBundle (SPINE)', obj: spineBundle, verify: (o) => pqsign.verifyBundle(o, signer.publicKey, logKp.publicKey).verified }, ok);

  // 8) pqgateway capability offer — every negotiated field is signed (downgrade protection)
  const peer = ml_dsa87.keygen(seed(81));
  const offer = pqgateway.makeOffer(['hybrid-mlkem1024-x25519-mldsa87', 'classical-x25519-ed25519'], peer.secretKey, peer.publicKey, { nonce: 'n1', challenge: 'sess-A', ts: 100 });
  runScenario({ label: 'pqgateway.verifyOffer', obj: offer, verify: (o) => pqgateway.verifyOffer(o, peer.publicKey) === true, skipPaths: ['sig'] }, ok);

  // 9) pqcbom-report EVIDENCE PACK (the PAID deliverable) — evidenceCore binds {kind,report_version,meta,grade,summary,
  //    findings,cbom_sha512,markdown_sha512}. The pre-ship review CAUGHT `markdown` (the human-readable report) unsigned
  //    — it could be altered while still "verifying"; now bound via markdown_sha512. verify also recomputes the risk
  //    tallies + grade FROM the findings (a forged clean summary over bad findings is caught). Only `signature.alg`
  //    (cosmetic label; verify uses ML-DSA regardless) is intentionally outside the signed core — recorded, not silent.
  const cbomSigner = ml_dsa87.keygen(seed(91));
  const scan = pqcbom.scanFiles([{ name: 'legacy.js', text: 'RSA-2048; ECDSA secp256k1; AES-128; MD5; ml_kem1024; ml_dsa87; SHA-512;' }]);
  const pack = pqcbomReport.signEvidencePack(pqcbomReport.buildEvidencePack({ scan, meta: { org: 'org-7f', scope: 'TLS', generated_ts: 1000 } }), cbomSigner.secretKey, cbomSigner.publicKey);
  runScenario({ label: 'pqcbom-report.verifyEvidencePack (PAID)', obj: pack, verify: (o) => pqcbomReport.verifyEvidencePack(o, cbomSigner.publicKey).verified, skipPaths: ['signature.sig_hex'], unbound: new Set(['signature.alg']) }, ok);

  // 9b) HYBRID Evidence Pack (apex / AND-composition: ML-DSA-87 ∧ SLH-DSA-256f). The SLH pubkey is bound INTO the
  //     ML-DSA core (anti-downgrade); both signatures + the bound key are tamper-evident. signature{,_slh}.alg are
  //     cosmetic labels (verify ignores them); the two sig_hex fields are the signatures themselves (skip).
  const slhSigner = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(92));
  const hyPack = pqcbomReport.signEvidencePack(pqcbomReport.buildEvidencePack({ scan, meta: { org: 'org-hy', scope: 'TLS', generated_ts: 1000 } }), cbomSigner.secretKey, cbomSigner.publicKey, { slhdsa: slhSigner });
  runScenario({ label: 'pqcbom-report hybrid (ML-DSA ∧ SLH-DSA)', obj: hyPack, verify: (o) => pqcbomReport.verifyEvidencePack(o, cbomSigner.publicKey, { trustedSlhPub: slhSigner.publicKey }).verified, skipPaths: ['signature.sig_hex', 'signature_slh.sig_hex'], unbound: new Set(['signature.alg', 'signature_slh.alg']) }, ok);

  // 9c) pqseal envelope (the crypto-agility N-leg AND-composition primitive). Only legs[].kind is cosmetic (verify uses
  //     alg); v + suite + payload_sha512 + each leg's alg/pub_hex/sig_hex are all bound. NB: pqattest is NOT field-walked
  //     here — its deeper composite is covered by its own 14-case dedicated binding suite (`node pqattest.mjs`).
  const sealPayload = utf8ToBytes('pqseal tamper-binding payload');
  const psA = ml_dsa87.keygen(new Uint8Array(32).fill(140));
  const psB = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(141));
  const psEsk = new Uint8Array(32).fill(142); const psEpub = ed25519.getPublicKey(psEsk);
  const sealEnv = pqseal.seal(sealPayload, [
    { alg: 'ML-DSA-87', secretKey: psA.secretKey, publicKey: psA.publicKey },
    { alg: 'SLH-DSA-256f', secretKey: psB.secretKey, publicKey: psB.publicKey },
    { alg: 'Ed25519', secretKey: psEsk, publicKey: psEpub },
  ]);
  const sealTrusted = { 'ML-DSA-87': psA.publicKey, 'SLH-DSA-256f': psB.publicKey, 'Ed25519': psEpub };
  runScenario({ label: 'pqseal envelope (N-leg AND-composition)', obj: sealEnv, verify: (o) => pqseal.openSeal(sealPayload, o, { trusted: sealTrusted }).verified, unbound: new Set(['legs.0.kind', 'legs.1.kind', 'legs.2.kind']) }, ok);

  // 10) pqcompliance report — core now binds summary+disclaimer too (this harness caught them unsigned). `signature.alg`
  //     cosmetic; full findings bound via findings_sha512; controls recompute from authenticated findings.
  const compSigner = ml_dsa87.keygen(seed(101));
  const compScan = pqcbom.scanFiles([{ name: 'legacy.js', text: 'RSA.generate(2048); ECDSA secp256k1; MD5; AES-128;' }]);
  const report = pqcompliance.signComplianceReport(pqcompliance.assessCompliance(compScan, { subject: 'acme', generated_ts: 1 }), compSigner.secretKey, compSigner.publicKey);
  runScenario({ label: 'pqcompliance.verifyComplianceReport', obj: report, verify: (o) => pqcompliance.verifyComplianceReport(o, compSigner.publicKey).verified, skipPaths: ['signature.sig_hex'], unbound: new Set(['signature.alg']) }, ok);

  // 11) pqpki CRL — signed revocation list; the whole `tbs` (revoked list + freshness + crl_number) is signed
  const crlCa = pqpki.generateIdentity(seed(111));
  const crl = pqpki.makeCRL({ revoked: ['sn-1', 'sn-2'], number: 3, thisUpdate: 0, nextUpdate: 1e9, ts: 5 }, crlCa);
  runScenario({ label: 'pqpki.checkRevocation (CRL)', obj: crl, verify: (o) => pqpki.checkRevocation(o, pqpki.pubOf(crlCa), 'sn-3', { at: 10 }).crl_valid === true }, ok);

  // 12) pqmarket reviewer attestation — logged + signed; the Merkle leaf binds the WHOLE attestation (incl. its sig)
  const reviewer = pqmarket.generateAgent(seed(121));
  const mLog = new pqsign.PQTransparencyLog();
  const mAtt = pqmarket.makeAttestation({ reviewer, subject_agent_id: 'agent-x', capability: 'cbom-scan', outcome: 'met', evidence_ref: 'job-1' }, { ts: 10 });
  const { index: mIdx } = pqmarket.logAttestation(mLog, mAtt);
  const mLogKey = ml_dsa87.keygen(seed(122));
  const mSth = mLog.signedTreeHead(mLogKey.secretKey, { ts: 100 });
  runScenario({ label: 'pqmarket.verifyAttestationInclusion', obj: { att: mAtt, inclusion: mLog.inclusion(mIdx), sth: mSth }, verify: (o) => pqmarket.verifyAttestationInclusion(o, mLogKey.publicKey).verified === true }, ok);

  // 13) pqkt key-event inclusion — the Merkle leaf binds the WHOLE event (incl. its issuer auth sig)
  const ktKey = ml_dsa87.keygen(seed(131));
  const ktLog = new pqsign.PQTransparencyLog();
  const ktEvent = pqkt.makeBindEvent({ issuer_id: 'issuer:Z', newKey: ktKey, seq: 0, ts: 1000 });
  const { index: ktIdx } = pqkt.appendKeyEvent(ktLog, ktEvent);
  const ktLogKey = ml_dsa87.keygen(seed(132));
  const ktSth = ktLog.signedTreeHead(ktLogKey.secretKey, { ts: 2000 });
  runScenario({ label: 'pqkt.verifyKeyEventInclusion', obj: { event: ktLog.entries[ktIdx], inclusion: ktLog.inclusion(ktIdx), sth: ktSth }, verify: (o) => pqkt.verifyKeyEventInclusion(o, ktLogKey.publicKey).verified === true }, ok);

  // 14) pqclaimgate attested answer (the zero-unflagged-hallucination envelope) — EVERY displayed field must be bound:
  //     query/mode/policy/coverage, each claim's id/claim/status/reason/confidence + evidence/consensus/verifiers (hashed),
  //     bucket membership (verified/abstained/rejected ids), sources, moa, the rendered answer, status, AND the
  //     honesty_note caveat. The 7th code-security sweep CAUGHT honesty_note unsigned here (a MITM could strip/invert
  //     "verified != ground truth, not a certification" on a PQ-'verified' answer) — bound now via honesty_note_sha256,
  //     and this scenario is the regression that mechanically proves NO displayed field escapes the signed manifest.
  //     attestation.sig_hex is the signature itself; signer_pub_hex is matched against the external pin (tamper -> bound).
  const cgOrder = ml_dsa87.keygen(seed(141));
  const cgEnv = {
    query: 'What are the PQC parameter sizes?', mode: 'gated', policy: 'strict', coverage: 0.5,
    emitted: { verified_claims: [{ id: 'A', claim: 'ML-KEM-1024 ciphertext is 1568 bytes.', status: 'verified', confidence: 0.85,
        evidence_refs: [{ ref: 'src:fips203', selector: '1568', grounded: true }],
        consensus: { strength: 0.8, total_considered: 3, dissent: { count: 0 } },
        verifiers: [{ type: 'pqef', verdict: 'PASS', score: 0.85 }] }],
      rendered: 'ML-KEM-1024 ciphertext is 1568 bytes.', status: 'partial' },
    abstained: [{ id: 'B', claim: 'The key was rotated last Tuesday.', status: 'abstained', reason_code: 'NO_EVIDENCE', confidence: 0 }],
    rejected: [{ id: 'C', claim: 'ML-DSA private keys are 12 bytes.', status: 'rejected', reason_code: 'VERIFIER_FAIL', confidence: 0 }],
    sources: [{ ref: 'src:fips203', grounded: true }], moa: { consensus: 'agree' },
    honesty_note: 'verified = passed policy gates, NOT ground truth; this is not a certification.',
  };
  pqclaimgate.attestClaimGate(cgEnv, cgOrder, { ts: 1000 });
  runScenario({ label: 'pqclaimgate.verifyClaimGate (attested answer)', obj: cgEnv, verify: (o) => pqclaimgate.verifyClaimGate(o, cgOrder.publicKey).verified, skipPaths: ['attestation.sig_hex'] }, ok);
  const cgOther = ml_dsa87.keygen(seed(142));
  ok(!pqclaimgate.verifyClaimGate(cgEnv, cgOther.publicKey).verified, 'pqclaimgate.verifyClaimGate: swapped order key -> FALSE (key binding)');

  // ---- platform engines (this session): every field of the signed digest/decision/policy core must be bound ----
  const hk = (a, b) => ({ ed: { secretKey: seed(a), publicKey: ed25519.getPublicKey(seed(a)) }, mldsa: ml_dsa87.keygen(seed(b)) });
  const hpub = (k) => ({ ed: k.ed.publicKey, mldsa: k.mldsa.publicKey });

  // 15) pqmonitor posture digest — digestCore {monitor,target,ledger_head,snapshot_count,seq,current,since,trend,at}
  //     all bound by the hybrid sig; the embedded monitor_pub + slh_signer_pub_hex are informational (verify uses the pinned key).
  const monKs = hk(150, 151), monIss = hk(152, 153);
  const repA = pqshield.createShieldReport({ issuerKeys: monIss, target: 't', assets: [{ label: 'a', algorithm: 'RSA-2048' }], generatedAt: 1 });
  const repB = pqshield.createShieldReport({ issuerKeys: monIss, target: 't', assets: [{ label: 'a', algorithm: 'RSA-2048' }, { label: 'b', algorithm: 'ECDH-P256', internet_facing: true }], generatedAt: 2 });
  const monL = pqmonitor.createLedger(); pqmonitor.appendSnapshot(monL, repA, hpub(monIss), { at: 1 }); pqmonitor.appendSnapshot(monL, repB, hpub(monIss), { at: 2 });
  const monDg = pqmonitor.signPostureDigest({ ledger: monL, monitorKeys: monKs, at: 2 });
  runScenario({ label: 'pqmonitor.verifyPostureDigest', obj: monDg, verify: (o) => pqmonitor.verifyPostureDigest(o, hpub(monKs)).verified, skipPaths: ['ed_sig', 'mldsa_sig'], unbound: new Set(['v', 'monitor_pub.ed', 'monitor_pub.mldsa', 'slh_signer_pub_hex']) }, ok);
  ok(!pqmonitor.verifyPostureDigest(monDg, hpub(hk(158, 159))).verified, 'pqmonitor.verifyPostureDigest: swapped monitor key -> FALSE (key binding)');

  // 16) pqgate decision — decisionCore {gate,app,allow,reason,cert_id,version,cert_level,policy_id,at} bound by sig.
  const gKs = hk(160, 161), gCIss = hk(162, 163), gPAuth = hk(164, 165);
  const gFW = new Uint8Array(64).fill(0x44);
  const gCert = pqadmit.issueAppCert({ issuerKeys: gCIss, app: 'a/b', version: '1.0.0', artifactBytes: gFW, certLevel: 'SOVEREIGN_GOLD', checks: { cbom_pass: true, cve_pass: true, opa_pass: true, pqc_pass: true } });
  const gPol = pqgate.signPolicy({ authorityKeys: gPAuth, app: 'a/b', minCertLevel: 'SOVEREIGN_PLUS', at: 1 });
  const gDec = pqgate.admit({ cert: gCert, certIssuer: hpub(gCIss), policy: gPol, policyAuthority: hpub(gPAuth), artifactBytes: gFW, gateKeys: gKs, now: 1 });
  runScenario({ label: 'pqgate.verifyDecision', obj: gDec, verify: (o) => pqgate.verifyDecision(o, hpub(gKs)).verified, skipPaths: ['ed_sig', 'mldsa_sig'], unbound: new Set(['v', 'gate_pub.ed', 'gate_pub.mldsa', 'slh_signer_pub_hex']) }, ok);

  // 17) pqgate policy — policyCore (rules + policy_id + at) is authority-signed; policy_id binds the rules.
  runScenario({ label: 'pqgate.verifyPolicy', obj: gPol, verify: (o) => pqgate.verifyPolicy(o, hpub(gPAuth)).verified, skipPaths: ['ed_sig', 'mldsa_sig'], unbound: new Set(['v', 'authority_pub.ed', 'authority_pub.mldsa', 'slh_signer_pub_hex']) }, ok);

  // ---- Wave-2 signed cores (this session) — batch 1 ----
  // 18) pqshield posture report — shieldCore bound by sig; assets[] bound via assets_hash recompute; top_critical is
  //     display (skipped); the embedded issuer_pub + carried `v` are informational (verify uses the pinned issuer).
  const shIss = hk(170, 171);
  const shRep = pqshield.createShieldReport({ issuerKeys: shIss, target: 't', assets: [{ label: 'edge', algorithm: 'RSA-2048', internet_facing: true }, { label: 'db', algorithm: 'AES-256' }], generatedAt: 5 });
  runScenario({ label: 'pqshield.verifyShieldReport', obj: shRep, verify: (o) => pqshield.verifyShieldReport(o, hpub(shIss)).verified, skipPaths: ['ed_sig', 'mldsa_sig', 'top_critical'], unbound: new Set(['v', 'issuer_pub.ed', 'issuer_pub.mldsa']) }, ok);
  ok(!pqshield.verifyShieldReport(shRep, hpub(hk(180, 181))).verified, 'pqshield: swapped issuer key -> FALSE (key binding)');

  // 19) pqcap capability token — capCore bound; agent_pub binds the agent id (bound); issuer_pub + `v` informational.
  const capIss = hk(172, 173), capAg = hk(174, 175);
  const capTok = pqcap.issueCapability({ issuerKeys: capIss, agent: hpub(capAg), tool: 'T', caveats: { arg_in: { op: ['read'] } }, nonce: 'tb' });
  runScenario({ label: 'pqcap.verifyCapability', obj: capTok, verify: (o) => pqcap.verifyCapability(o, hpub(capIss), { request: { tool: 'T', args: { op: 'read' } } }).verified, skipPaths: ['ed_sig', 'mldsa_sig'], unbound: new Set(['v', 'issuer_pub.ed', 'issuer_pub.mldsa']) }, ok);

  // 20) pqadmit app cert — certCore bound; cert_id binds the identifying fields; artifact_digest binds the binary.
  const adIss = hk(176, 177); const adImg = new Uint8Array(64).fill(0x55);
  const adCert = pqadmit.issueAppCert({ issuerKeys: adIss, app: 'a/b', version: '1.0.0', artifactBytes: adImg, certLevel: 'SOVEREIGN_GOLD', checks: { cbom_pass: true, cve_pass: true, opa_pass: true, pqc_pass: true } });
  runScenario({ label: 'pqadmit.verifyAdmission', obj: adCert, verify: (o) => pqadmit.verifyAdmission(o, hpub(adIss), { artifactBytes: adImg }).verified, skipPaths: ['ed_sig', 'mldsa_sig'], unbound: new Set(['v', 'issuer_pub.ed', 'issuer_pub.mldsa']) }, ok);

  // 21) pqconsent receipt — self-sovereign: subject_pub binds the subject id (bound, no external pin); only `v` is informational.
  const coSub = hk(178, 179);
  const coRcpt = pqconsent.grantConsent({ subjectKeys: coSub, controller: 'c', purposes: ['p1'], categories: ['c1'], legalBasis: 'GDPR-Art-9-2-a', nonce: 'tb' });
  runScenario({ label: 'pqconsent.verifyConsent', obj: coRcpt, verify: (o) => pqconsent.verifyConsent(o, { purpose: 'p1', category: 'c1' }).verified, skipPaths: ['ed_sig', 'mldsa_sig'], unbound: new Set(['v']) }, ok);

  // ---- Wave-2 signed cores — batch 2 ----
  // 22) pqpay authorization — authCore bound; payer_pub + `v` informational (verify uses the pinned payer).
  const payP = hk(182, 183);
  const payAuth = pqpay.createAuthorization({ payerKeys: payP, id: 'p', payee: 'm', amount: 100, currency: 'USD', nonce: 'tb' });
  runScenario({ label: 'pqpay.verifyAuthorization', obj: payAuth, verify: (o) => pqpay.verifyAuthorization(o, hpub(payP), { allowUnmeteredCheck: true }).verified, skipPaths: ['ed_sig', 'mldsa_sig'], unbound: new Set(['v', 'payer_pub.ed', 'payer_pub.mldsa']) }, ok);

  // 23) pqfirmware manifest — core bound; artifact_sha256 binds the binary; vendor_pub + `v` informational.
  const fwV = hk(184, 185); const fwBin = new Uint8Array(64).fill(0x66);
  const fwMan = pqfirmware.signFirmware({ vendorKeys: fwV, deviceModel: 'M', version: 7, buildId: 'b7', artifactBytes: fwBin });
  runScenario({ label: 'pqfirmware.verifyFirmware', obj: fwMan, verify: (o) => pqfirmware.verifyFirmware(o, hpub(fwV), { artifactBytes: fwBin, currentVersion: 6, deviceModel: 'M' }).verified, skipPaths: ['ed_sig', 'mldsa_sig'], unbound: new Set(['v', 'vendor_pub.ed', 'vendor_pub.mldsa']) }, ok);

  // 24) pqvc verifiable credential — the issuer signs {v, issuer, subject, claims-commitment, id, ...} (all bound).
  //     `proof` is the signature container (skip); `claims_doc` is the holder's selective-disclosure artifact — NOT bound
  //     by the issuer credential (it is committed via claims_root and verified separately at presentation time), so skip
  //     it here; issuer_pub is informational (verify uses the pinned issuer DID key).
  const vcIss = hk(186, 187), vcSub = hk(188, 189);
  const { vc: vcObj } = pqvc.issueCredential({ issuerKeys: vcIss, subjectDid: pqvc.makeDid(hpub(vcSub)), claims: { role: 'x' }, id: 'vc-tb' });
  runScenario({ label: 'pqvc.verifyCredential', obj: vcObj, verify: (o) => pqvc.verifyCredential(o, hpub(vcIss)).verified, skipPaths: ['ed_sig', 'mldsa_sig', 'proof', 'claims_doc'], unbound: new Set(['issuer_pub.ed', 'issuer_pub.mldsa']) }, ok);

  // ---- nested platform-engine chains (this session) ----
  // 25) pqflow genesis — the merchant signs transitionCore (bound); the embedded pqpay auth is bound via auth_sha256
  //     (so every auth.* field is bound); merchant_pub + the top-level flow convenience copies (payer/payee/currency/v,
  //     not re-checked by verifyFlow — the authoritative data is the bound genesis auth) are documented-unsigned.
  const flP = hk(190, 191), flM = hk(192, 193);
  const flAuth = pqpay.createAuthorization({ payerKeys: flP, id: 'p', payee: 'm', amount: 1000, currency: 'USD', nonce: 'tb' });
  const flFlow = pqflow.openFlow({ auth: flAuth, payerPub: hpub(flP), merchantKeys: flM, at: 1, allowUnmeteredOpen: true });
  runScenario({ label: 'pqflow.verifyFlow (genesis)', obj: flFlow, verify: (o) => pqflow.verifyFlow(o, hpub(flM), hpub(flP)).verified, skipPaths: ['transitions.0.ed_sig', 'transitions.0.mldsa_sig'], unbound: new Set(['v', 'payer', 'payee', 'currency', 'transitions.0.v', 'transitions.0.merchant_pub.ed', 'transitions.0.merchant_pub.mldsa', 'transitions.0.slh_signer_pub_hex']) }, ok);

  // 26) pqdelegate chain [root, delegation] — each link's core is bound by its signer; agent/delegator/delegatee pubs
  //     bind their ids (bound); the carried `v` + the root's informational issuer_pub + the (null) slh pub are unsigned.
  const dgPrin = hk(194, 195), dgA = hk(196, 197), dgB = hk(198, 199);
  const dgRoot = pqcap.issueCapability({ issuerKeys: dgPrin, agent: hpub(dgA), tool: 'T', caveats: { arg_in: { op: ['read'] } }, audience: 'aud', nonce: 'r' });
  const dgLink = pqdelegate.delegate({ delegatorKeys: dgA, parent: dgRoot, delegatee: hpub(dgB), tool: 'T', addedCaveats: {}, audience: 'aud', nonce: 'd' });
  runScenario({ label: 'pqdelegate.verifyDelegationChain', obj: [dgRoot, dgLink], verify: (o) => pqdelegate.verifyDelegationChain(o, hpub(dgPrin), { request: { tool: 'T', args: { op: 'read' } }, audience: 'aud' }).verified, skipPaths: ['0.ed_sig', '0.mldsa_sig', '1.ed_sig', '1.mldsa_sig'], unbound: new Set(['0.v', '0.issuer_pub.ed', '0.issuer_pub.mldsa', '1.v', '1.slh_signer_pub_hex']) }, ok);

  console.log('tamper-binding: ' + pass + ' pass, ' + fail + ' fail');
  if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
}
if (typeof process !== 'undefined' && process.argv && /tamper-binding\.mjs$/.test(process.argv[1] || '')) selfTest();
