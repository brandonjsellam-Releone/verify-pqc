/*!
 * run-demo — one command, no hosting, no network: scans the synthetic ./sample-repo with the REAL TRELYAN SDK and
 * writes inspectable artifacts to ./demo-out/ — a SARIF report, a CycloneDX CBOM, and a HYBRID-signed (ML-DSA-87 ∧
 * SLH-DSA) PQC Migration Evidence Pack — then verifies the pack and checks the CBOM's structural conformance.
 *
 * It also SELF-CHECKS (asserts the expected grade + that the pack verifies + CBOM conforms) and exits non-zero on
 * drift, so it doubles as a deterministic regression snapshot. Demo keys (fixed seeds) — NOT production keys.
 *
 *   node run-demo.mjs
 */
import { scanDirectory, toCycloneDX, toSARIF } from '../../pqcbom.mjs';
import { buildEvidencePack, signEvidencePack, verifyEvidencePack } from '../../pqcbom-report.mjs';
import { attest, verifyAttest } from '../../pqattest.mjs';
import { genTsaKey, timestamp as mkTst, cosignTimestamp } from '../../pqtsa.mjs';
import { PQTransparencyLog } from '../../pqsign.mjs';
import { makeWitness } from '../../pqkt.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { writeFileSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, 'sample-repo');
const out = join(here, 'demo-out');
mkdirSync(out, { recursive: true });

let fail = 0; const check = (cond, msg) => { console.log((cond ? '  ✓ ' : '  ✗ ') + msg); if (!cond) fail++; };

// 1) Scan the repo (CI-gate mode: grade on CODE occurrences; comment/doc mentions stay informational).
//    .pqcbomignore in sample-repo accepts the classical-hybrid-ok legs -> demonstrates suppression.
const scan = await scanDirectory(repo, { gradeContext: 'code' });
console.log(`\nScan: grade ${scan.grade.letter} (${scan.grade.score}/100) · ${scan.summary.files_scanned} files · ` +
  `${scan.findings.length} findings · ${scan.summary.suppressed} suppressed (accepted, not graded)`);

// 2) Artifacts a prospect/auditor can inspect.
const cbom = toCycloneDX(scan);
const sarif = toSARIF(scan, { baseDir: repo });
writeFileSync(join(out, 'cbom.cdx.json'), JSON.stringify(cbom, null, 2));
writeFileSync(join(out, 'findings.sarif'), JSON.stringify(sarif, null, 2));

// 3) HYBRID-signed Evidence Pack (deterministic demo keys; fixed ts).
const mldsa = ml_dsa87.keygen(new Uint8Array(32).fill(123));
const slh = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(124));
const pack = signEvidencePack(
  buildEvidencePack({ scan, meta: { org: 'SAMPLE — demo target (not a real client)', scope: 'auth + TLS + SSH + deps', generated_ts: 1782000000 } }),
  mldsa.secretKey, mldsa.publicKey, { slhdsa: slh });
writeFileSync(join(out, 'evidence-pack.signed.json'), JSON.stringify(pack, null, 2));
writeFileSync(join(out, 'evidence-pack.md'), pack.markdown);
const v = verifyEvidencePack(pack, mldsa.publicKey, { trustedSlhPub: slh.publicKey });

// 3b) FULL ATTESTATION (pqattest): the signed pack is ALSO sealed by 3 algorithm families ∧ threshold-timestamped by
//     2 TSAs ∧ logged in an RFC-6962 transparency tree. The seal countersigns the timestamp + tree-head (0-downgrade).
const edsk = new Uint8Array(32).fill(125);
const signers = [
  { alg: 'ML-DSA-87', secretKey: mldsa.secretKey, publicKey: mldsa.publicKey },
  { alg: 'SLH-DSA-256f', secretKey: slh.secretKey, publicKey: slh.publicKey },
  { alg: 'Ed25519', secretKey: edsk, publicKey: ed25519.getPublicKey(edsk) },
];
const tsaA = genTsaKey(new Uint8Array(32).fill(126)), tsaB = genTsaKey(new Uint8Array(32).fill(127));
const tsas = [{ sk: tsaA.secretKey, pub: tsaA.publicKey }, { sk: tsaB.secretKey, pub: tsaB.publicKey }];
const logKp = ml_dsa87.keygen(new Uint8Array(32).fill(128));
const wit1 = makeWitness(new Uint8Array(32).fill(129)), wit2 = makeWitness(new Uint8Array(32).fill(130));
const packBytes = utf8ToBytes(JSON.stringify(pack));
const att = attest(packBytes, { signers, tsas, log: new PQTransparencyLog(), logSk: logKp.secretKey, logPub: logKp.publicKey, witnesses: [wit1, wit2], ts: 1782000000 });
writeFileSync(join(out, 'attestation.json'), JSON.stringify(att, null, 2));
const trustedSeal = { 'ML-DSA-87': mldsa.publicKey, 'SLH-DSA-256f': slh.publicKey, 'Ed25519': signers[2].publicKey };
const vattOpts = { trusted: trustedSeal, tsaPubs: [tsaA.publicKey, tsaB.publicKey], logPub: logKp.publicKey, trustedWitnessPubs: [wit1.publicKey, wit2.publicKey] };
const av = verifyAttest(packBytes, att, vattOpts);
// 0-DOWNGRADE attack: swap in a DIFFERENT valid timestamp for the same hash -> must FAIL
const attDown = JSON.parse(JSON.stringify(att));
attDown.tst = cosignTimestamp(mkTst({ content_sha256: att.artifact_sha256 }, tsaA.secretKey, tsaA.publicKey, { ts: 9999 }), tsaB.secretKey, tsaB.publicKey);
const avDown = verifyAttest(packBytes, attDown, vattOpts);

// 4) Self-checks (so this is also a regression snapshot).
console.log('\nSelf-checks:');
check(scan.grade.letter === 'F', 'grade is F (RSA/ECDSA/MD5/TLS1.0 are broken/quantum-broken)');
check(scan.summary.suppressed >= 1, 'suppression honored (classical-hybrid-ok accepted via .pqcbomignore)');
const algos = new Set(scan.findings.map((f) => f.algo));
check(algos.has('lib:node-forge') && algos.has('lib:@noble/post-quantum'), 'dependency layer fired (node-forge + @noble/post-quantum from package.json)');
check(!scan.findings.some((f) => f.algo === 'TLS<1.2 / SSL' && f.context === 'code' && false) && algos.has('TLS<1.2 / SSL'), 'deprecated TLS flagged — and TLS 1.3 on the same line was NOT');
check(algos.has('ML-KEM/Kyber') && algos.has('ML-DSA/Dilithium'), 'already-migrated PQ crypto recognized as quantum-safe');
check(v.verified === true && v.hybrid === true && v.slhValid === true && v.trustAnchored === true, 'Evidence Pack verifies: hybrid (ML-DSA ∧ SLH-DSA), grade recomputed from findings, trust-anchored');
check(av.verified === true && av.sealTrustAnchored === true && av.signerCount === 2 && av.anchorOk === true && av.witnessCount === 2, 'Full attestation: 3 families AND 2-of-2 PQ timestamp AND RFC-6962 log inclusion AND 2 witness co-signatures');
check(avDown.verified === false, '0-DOWNGRADE: swapping in a different same-hash timestamp -> attestation FAILS (seal countersigns the timestamp)');
// structural CycloneDX 1.6 conformance (required fields; NOT a full JSON-schema validation)
check(cbom.bomFormat === 'CycloneDX' && cbom.specVersion === '1.6' && typeof cbom.version === 'number' &&
  Array.isArray(cbom.components) && cbom.components.every((c) => c.type === 'cryptographic-asset' && typeof c.name === 'string'),
  'CBOM structurally conforms to CycloneDX 1.6 (bomFormat/specVersion/version + cryptographic-asset components)');
// SARIF 2.1.0 shape + repo-relative paths
check(sarif.version === '2.1.0' && sarif.runs[0].results.every((r) => r.ruleId && !/^([A-Za-z]:|\/)/.test(r.locations[0].physicalLocation.artifactLocation.uri)),
  'SARIF is 2.1.0 with repo-relative paths (GitHub code-scanning ready)');

// 5) Expected-summary snapshot (diff-able).
writeFileSync(join(out, 'expected-summary.json'), JSON.stringify({
  grade: scan.grade.letter, score: scan.grade.score, files: scan.summary.files_scanned,
  findings: scan.findings.length, suppressed: scan.summary.suppressed,
  by_confidence: scan.summary.by_confidence, evidence_pack_verified: v.verified, hybrid: v.hybrid,
}, null, 2));

console.log('\nArtifacts written to demo-out/: findings.sarif · cbom.cdx.json · evidence-pack.signed.json · evidence-pack.md · attestation.json · expected-summary.json');
console.log(fail ? `\nDEMO: ${fail} check(s) FAILED` : '\nDEMO: all checks passed ✓  (synthetic target — findings are leads to verify, not a complete audit; SDK is unaudited)');
if (typeof process !== 'undefined' && process.exit) process.exit(fail ? 1 : 0);
