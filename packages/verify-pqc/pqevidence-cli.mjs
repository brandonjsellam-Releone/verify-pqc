#!/usr/bin/env node
/*!
 * pqevidence-cli — "Evidence Pack Express": point it at a repo, get a hybrid-signed PQC Migration Evidence Pack
 * (the PAID deliverable). Reference, DRAFT. Wires the reviewed pipeline: scanDirectory → buildEvidencePack →
 * signEvidencePack (ML-DSA-87 [∧ SLH-DSA-256f]) → rendered report + CBOM, then self-verifies (grade recomputed
 * from findings, so a forged grade is caught).
 *
 *   node pqevidence-cli.mjs keygen --out signer [--slh]
 *   node pqevidence-cli.mjs pack   <repo-dir> --keys signer.keys.json [--org "Acme Inc"] [--scope "TLS + signing"] [--ts <int>] [--out <dir>]
 *   node pqevidence-cli.mjs verify <evidence-pack.json> --pub signer.pub.json [--require-hybrid] [--require-pinned]
 *
 * ⚠️ KEY HANDLING: `keygen` writes SECRET keys to a JSON file for DEV/TEST only — production signing keys belong in
 *    an HSM/KMS, never a plaintext file (see KEY_HANDLING.md). Unaudited reference tool. Self-test: --selftest
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { scanDirectory } from './pqcbom.mjs';
import { buildEvidencePack, signEvidencePack, verifyEvidencePack } from './pqcbom-report.mjs';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';

const HELP = `pqevidence — Evidence Pack Express (reference, unaudited)

  keygen --out <prefix> [--slh]                     ML-DSA-87 signer (+ SLH-DSA-256f hybrid leg with --slh)
  pack   <repo-dir> --keys <signer.keys.json> [--org <name>] [--scope <text>] [--ts <int>] [--out <dir>]
  verify <evidence-pack.json> --pub <signer.pub.json> [--require-hybrid] [--require-pinned]

pack writes (to --out, default ./evidence-pack/): evidence-pack.json (hybrid-signed), evidence-pack.md (the report a
buyer reads — bound into the signature), cbom.cdx.json. It then SELF-VERIFIES under the signer's own key.
⚠️ keygen writes SECRET keys to disk for DEV/TEST ONLY — production keys belong in an HSM/KMS. Unaudited reference tool.`;

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (k) => { const i = argv.indexOf('--' + k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null; };
const has = (k) => argv.includes('--' + k);
const positional = argv.slice(1).find((a) => !a.startsWith('--') && argv[argv.indexOf(a) - 1] !== '--keys' && argv[argv.indexOf(a) - 1] !== '--pub' && argv[argv.indexOf(a) - 1] !== '--out' && argv[argv.indexOf(a) - 1] !== '--org' && argv[argv.indexOf(a) - 1] !== '--scope' && argv[argv.indexOf(a) - 1] !== '--ts');
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

// signer keyset { mldsa:{secretKey,publicKey}, slh?:{secretKey,publicKey} }
const serializeSecret = (k) => ({ mldsa: { secretKey: bytesToHex(k.mldsa.secretKey), publicKey: bytesToHex(k.mldsa.publicKey) }, ...(k.slh ? { slh: { secretKey: bytesToHex(k.slh.secretKey), publicKey: bytesToHex(k.slh.publicKey) } } : {}) });
const loadSecret = (o) => ({ mldsa: { secretKey: hexToBytes(o.mldsa.secretKey), publicKey: hexToBytes(o.mldsa.publicKey) }, ...(o.slh ? { slh: { secretKey: hexToBytes(o.slh.secretKey), publicKey: hexToBytes(o.slh.publicKey) } } : {}) });
const pubOf = (k) => ({ mldsa: bytesToHex(k.mldsa.publicKey), ...(k.slh ? { slh: bytesToHex(k.slh.publicKey) } : {}) });

function signWith(pack, k) { return signEvidencePack(pack, k.mldsa.secretKey, k.mldsa.publicKey, k.slh ? { slhdsa: k.slh } : {}); }

async function run() {
  if (!cmd || cmd === '--help' || cmd === '-h') { console.log(HELP); process.exit(0); }
  if (cmd === '--selftest') return selfTest();

  if (cmd === 'keygen') {
    const out = flag('out'); if (!out) { console.error('keygen: --out <prefix> required'); process.exit(2); }
    if (existsSync(out + '.keys.json')) { console.error('refusing to overwrite ' + out + '.keys.json'); process.exit(2); }
    const k = { mldsa: ml_dsa87.keygen(randomBytes(32)), ...(has('slh') ? { slh: slh_dsa_sha2_256f.keygen(randomBytes(96)) } : {}) };
    writeFileSync(out + '.keys.json', JSON.stringify(serializeSecret(k), null, 2));
    writeFileSync(out + '.pub.json', JSON.stringify(pubOf(k), null, 2));
    console.error('⚠️  ' + out + '.keys.json contains SECRET keys — dev/test only; use an HSM/KMS in production.');
    console.log('wrote ' + out + '.keys.json (secret) + ' + out + '.pub.json (public)' + (k.slh ? '  [ML-DSA-87 ∧ SLH-DSA-256f hybrid]' : '  [ML-DSA-87]'));
    process.exit(0);
  }

  if (cmd === 'pack') {
    const repo = positional, keysF = flag('keys');
    if (!repo || !keysF) { console.error('pack: <repo-dir> --keys <signer.keys.json> required'); process.exit(2); }
    const k = loadSecret(readJson(keysF));
    const report = await scanDirectory(repo);
    const ts = flag('ts') != null ? Number(flag('ts')) : Date.now();
    const pack = buildEvidencePack({ scan: report, meta: { org: flag('org') || 'CONFIDENTIAL', scope: flag('scope') || repo, generated_ts: ts } });
    const signed = signWith(pack, k);
    const outDir = flag('out') || 'evidence-pack';
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    writeFileSync(outDir + '/evidence-pack.json', JSON.stringify(signed, null, 2));
    writeFileSync(outDir + '/evidence-pack.md', signed.markdown);
    writeFileSync(outDir + '/cbom.cdx.json', JSON.stringify(signed.cbom, null, 2));
    const v = verifyEvidencePack(signed, k.mldsa.publicKey, k.slh ? { trustedSlhPub: k.slh.publicKey } : {});
    console.log('Evidence Pack — grade ' + signed.grade.letter + ' (' + signed.grade.score + '/100) · ' + report.summary.files_scanned + ' files · ' + (k.slh ? 'ML-DSA-87 ∧ SLH-DSA-256f' : 'ML-DSA-87') + '-signed');
    console.log((v.verified && v.trustAnchored ? '✓ self-verifies' : '✗ self-verify FAILED') + ' (verified=' + v.verified + ', trustAnchored=' + v.trustAnchored + ', gradeConsistent=' + v.gradeConsistent + ')');
    console.log('wrote ' + outDir + '/{evidence-pack.json, evidence-pack.md, cbom.cdx.json}');
    process.exit(v.verified && v.trustAnchored ? 0 : 1);
  }

  if (cmd === 'verify') {
    const packF = positional, pubF = flag('pub');
    if (!packF || !pubF) { console.error('verify: <evidence-pack.json> --pub <signer.pub.json> required'); process.exit(2); }
    const pub = readJson(pubF);
    const opts = { ...(pub.slh ? { trustedSlhPub: hexToBytes(pub.slh) } : {}), ...(has('require-hybrid') ? { requireHybrid: true } : {}), ...(has('require-pinned') ? { requirePinned: true } : {}) };
    const v = verifyEvidencePack(readJson(packF), hexToBytes(pub.mldsa), opts);
    if (v.verified) { console.log('✓ VERIFIED — grade is recomputed from findings + report bound' + (v.trustAnchored ? '; trust-anchored to the pinned key' : '; NOTE trustAnchored=false') + (v.hybrid ? '; hybrid ML-DSA∧SLH' : '')); process.exit(0); }
    console.error('✗ NOT VERIFIED — verified=false (gradeConsistent=' + v.gradeConsistent + ', sigOk=' + v.sigOk + ', slhValid=' + v.slhValid + ')'); process.exit(1);
  }

  console.error('unknown command: ' + cmd + '\n\n' + HELP); process.exit(2);
}

/* ---------- self-test: node pqevidence-cli.mjs --selftest ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { scanFiles } = await import('./pqcbom.mjs');
  const scan = scanFiles([{ name: 'legacy.js', text: 'RSA-2048; ECDSA secp256k1; MD5; ml_kem1024;' }]);
  const pack = buildEvidencePack({ scan, meta: { org: 'st', scope: 'unit', generated_ts: 1000 } });

  // keyfile round-trip (the CLI's value-add over the module) — ML-DSA only
  const k = { mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(61)) };
  const rt = loadSecret(serializeSecret(k));
  const signed = signWith(pack, rt);
  ok(verifyEvidencePack(signed, rt.mldsa.publicKey).verified === true, 'keyfile round-trip → sign → verify under the pinned signer');
  ok(verifyEvidencePack(signed, ml_dsa87.keygen(new Uint8Array(32).fill(9)).publicKey).verified === false, 'wrong signer key → NOT verified');
  ok(signed.grade.letter === 'F' && /Evidence Pack/.test(signed.markdown), 'pack carries grade F + the rendered report');

  // hybrid keyfile round-trip — ML-DSA ∧ SLH
  const kh = { mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(62)), slh: slh_dsa_sha2_256f.keygen(new Uint8Array(96).fill(63)) };
  const rth = loadSecret(serializeSecret(kh));
  const hy = signWith(pack, rth);
  const hv = verifyEvidencePack(hy, rth.mldsa.publicKey, { trustedSlhPub: rth.slh.publicKey });
  ok(hv.verified === true && hv.hybrid === true && hv.slhValid === true, 'hybrid keyfile round-trip → dual-sign → verify under BOTH pinned keys');
  ok(verifyEvidencePack(signed, rt.mldsa.publicKey, { requireHybrid: true }).verified === false, 'requireHybrid rejects the ML-DSA-only pack');

  // anti grade-forgery survives the keyfile path
  const forged = JSON.parse(JSON.stringify(signed)); forged.grade = { letter: 'A', score: 100, label: 'x', badge: 'x' };
  ok(verifyEvidencePack(forged, rt.mldsa.publicKey).verified === false, 'forged grade A over F findings → verify FAILS (grade recomputed)');

  console.log('pqevidence-cli self-test: ' + pass + ' pass, ' + fail + ' fail');
  process.exit(fail ? 1 : 0);
}
run().catch((e) => { console.error('✗ ERROR — ' + String((e && e.message) || e)); process.exit(2); });
