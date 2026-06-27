import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { buildEvidencePack, signEvidencePack, verifyEvidencePack } from './pqcbom-report.mjs';
import { scanFiles } from './pqcbom.mjs';

const signer = ml_dsa87.keygen(new Uint8Array(32).fill(61));
const slhA = slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(73));
const scan = scanFiles([{ name: 'legacy.js', text: 'RSA-2048; MD5; ml_dsa87;' }]);
const pack = buildEvidencePack({ scan, meta: { org: 'x', generated_ts: 1000 } });
const hy = signEvidencePack(pack, signer.secretKey, signer.publicKey, { slhdsa: slhA });

console.log('E2 reqHybrid+reqPinned no SLH pin:', verifyEvidencePack(hy, signer.publicKey, { requireHybrid: true, requirePinned: true }).verified, '(expect false)');

const bolt = JSON.parse(JSON.stringify(signEvidencePack(pack, signer.secretKey, signer.publicKey)));
bolt.signature_slh = JSON.parse(JSON.stringify(hy.signature_slh));
const bv = verifyEvidencePack(bolt, signer.publicKey);
console.log('E3 bolted:', bv.verified, 'hybrid:', bv.hybrid, 'slhConsistent:', bv.slhConsistent, '(expect false/true/false)');

const strip = JSON.parse(JSON.stringify(hy)); delete strip.signature_slh;
const sv = verifyEvidencePack(strip, signer.publicKey);
console.log('E4 stripped:', sv.verified, 'hybrid:', sv.hybrid, 'slhConsistent:', sv.slhConsistent, '(expect false/true/false)');

const mm = JSON.parse(JSON.stringify(hy)); mm.signature_slh.signer_pub_hex = 'deadbeef';
console.log('E5 s2 pubkey != bound:', verifyEvidencePack(mm, signer.publicKey).verified, '(expect false)');

const cleanScan = scanFiles([{ name: 'clean.js', text: 'no crypto here just text' }]);
const cleanPack = buildEvidencePack({ scan: cleanScan, meta: { org: 'x', generated_ts: 1 } });
const cleanSigned = signEvidencePack(cleanPack, signer.secretKey, signer.publicKey);
console.log('E6 clean verifies:', verifyEvidencePack(cleanSigned, signer.publicKey).verified, 'grade:', cleanPack.grade.letter, '(expect true / A)');
