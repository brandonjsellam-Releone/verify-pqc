#!/usr/bin/env node
/*!
 * pqvc-cli — QuantumDNA: issue + verify post-quantum verifiable credentials from the command line (reference, DRAFT).
 *
 *   node pqvc-cli.mjs keygen  --out <prefix> [--slh]          → <prefix>.keys.json (SECRET) + <prefix>.pub.json + its did:trelyan
 *   node pqvc-cli.mjs did     --pub <f> | --keys <f>          → print the did:trelyan for a key/pub file
 *   node pqvc-cli.mjs issue   --keys issuer.keys.json --subject <did> --claims '<json>' [--id <id>] [--expires <iso>] [--out vc.json]
 *   node pqvc-cli.mjs verify  --vc vc.json --pub issuer.pub.json
 *
 * ⚠️ KEY HANDLING: `keygen` writes SECRET keys to a JSON file for DEV/TEST only — production keys belong in an HSM/KMS,
 *    never a plaintext file (see KEY_HANDLING.md). Unaudited reference tool.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { makeDid, issueCredential, verifyCredential } from './pqvc.mjs';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';

const HELP = `pqvc — QuantumDNA verifiable-credential CLI

  keygen --out <prefix> [--slh]                         generate a hybrid keyset + its did:trelyan
  did    --pub <f> | --keys <f>                         print the did:trelyan for a key/pub file
  issue  --keys <issuer.keys.json> --subject <did> --claims '<json>' [--id <id>] [--expires <iso>] [--out vc.json]
  verify --vc <vc.json> --pub <issuer.pub.json>

⚠️ keygen writes SECRET keys to disk for DEV/TEST ONLY — production keys belong in an HSM/KMS, never a file.
Unaudited reference tool.`;

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (k) => { const i = argv.indexOf('--' + k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null; };
const has = (k) => argv.includes('--' + k);

function keyset(withSlh) {
  const eds = randomBytes(32);
  const ks = { ed: { secretKey: eds, publicKey: ed25519.getPublicKey(eds) }, mldsa: ml_dsa87.keygen(randomBytes(32)) };
  if (withSlh) ks.slh = slh_dsa_sha2_256f.keygen(randomBytes(96));
  return ks;
}
const pubOf = (ks) => ({ ed: bytesToHex(ks.ed.publicKey), mldsa: bytesToHex(ks.mldsa.publicKey), ...(ks.slh ? { slh: bytesToHex(ks.slh.publicKey) } : {}) });
const serializeSecret = (ks) => ({ ed: { secretKey: bytesToHex(ks.ed.secretKey), publicKey: bytesToHex(ks.ed.publicKey) }, mldsa: { secretKey: bytesToHex(ks.mldsa.secretKey), publicKey: bytesToHex(ks.mldsa.publicKey) }, ...(ks.slh ? { slh: { secretKey: bytesToHex(ks.slh.secretKey), publicKey: bytesToHex(ks.slh.publicKey) } } : {}) });
const loadSecret = (o) => ({ ed: { secretKey: hexToBytes(o.ed.secretKey), publicKey: hexToBytes(o.ed.publicKey) }, mldsa: { secretKey: hexToBytes(o.mldsa.secretKey), publicKey: hexToBytes(o.mldsa.publicKey) }, ...(o.slh ? { slh: { secretKey: hexToBytes(o.slh.secretKey), publicKey: hexToBytes(o.slh.publicKey) } } : {}) });
const loadPub = (o) => ({ ed: hexToBytes(o.ed), mldsa: hexToBytes(o.mldsa), ...(o.slh ? { slh: hexToBytes(o.slh) } : {}) });
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

function run() {
  if (!cmd || cmd === '--help' || cmd === '-h') { console.log(HELP); process.exit(0); }

  if (cmd === 'keygen') {
    const out = flag('out'); if (!out) { console.error('keygen: --out <prefix> required'); process.exit(2); }
    if (existsSync(out + '.keys.json')) { console.error('refusing to overwrite ' + out + '.keys.json'); process.exit(2); }
    const ks = keyset(has('slh'));
    writeFileSync(out + '.keys.json', JSON.stringify(serializeSecret(ks), null, 2));
    writeFileSync(out + '.pub.json', JSON.stringify(pubOf(ks), null, 2));
    console.error('⚠️  ' + out + '.keys.json contains SECRET keys — dev/test only; use an HSM/KMS in production.');
    console.log('did: ' + makeDid(loadPub(pubOf(ks))));
    console.log('wrote ' + out + '.keys.json (secret) + ' + out + '.pub.json (public)');
    process.exit(0);
  }

  if (cmd === 'did') {
    const f = flag('pub') || flag('keys'); if (!f) { console.error('did: --pub <f> or --keys <f> required'); process.exit(2); }
    const o = readJson(f);
    const pub = o.ed && typeof o.ed === 'object' ? loadPub(pubOf(loadSecret(o))) : loadPub(o);  // accept a keyfile or a pubfile
    console.log(makeDid(pub)); process.exit(0);
  }

  if (cmd === 'issue') {
    const keysF = flag('keys'), subject = flag('subject'), claimsRaw = flag('claims');
    if (!keysF || !subject || !claimsRaw) { console.error("issue: --keys --subject <did> --claims '<json>' required"); process.exit(2); }
    let claims; try { claims = JSON.parse(claimsRaw); } catch (e) { console.error('issue: --claims must be JSON: ' + e.message); process.exit(2); }
    const { vc, holder } = issueCredential({ issuerKeys: loadSecret(readJson(keysF)), subjectDid: subject, claims, id: flag('id') || ('vc-' + bytesToHex(randomBytes(6))), expirationDate: flag('expires') || undefined });
    const out = flag('out') || 'vc.json';
    const holderOut = out.replace(/\.json$/, '') + '.holder.json';
    writeFileSync(out, JSON.stringify(vc, null, 2));                  // publishable credential
    writeFileSync(holderOut, JSON.stringify(holder, null, 2));        // PRIVATE — the holder keeps this for selective disclosure (present)
    console.log('issued credential ' + vc.id + ' → ' + out + '  (subject ' + subject.slice(0, 28) + '…, claims: ' + Object.keys(claims).join(', ') + ')  [+ ' + holderOut + ' kept by the holder]');
    process.exit(0);
  }

  if (cmd === 'verify') {
    const vcF = flag('vc'), pubF = flag('pub');
    if (!vcF || !pubF) { console.error('verify: --vc <f> --pub <issuer.pub.json> required'); process.exit(2); }
    const r = verifyCredential(readJson(vcF), loadPub(readJson(pubF)));
    if (r && r.verified) { console.log('✓ VERIFIED — issuer + validity confirmed; claim VALUES are checked on disclosure (present → verifyPresentation)' + (r.subject ? '  · subject ' + String(r.subject).slice(0, 28) + '…' : '')); process.exit(0); }
    console.error('✗ REJECTED — ' + ((r && r.reason) || 'invalid credential')); process.exit(1);
  }

  console.error('unknown command: ' + cmd + '\n\n' + HELP); process.exit(2);
}
run();
