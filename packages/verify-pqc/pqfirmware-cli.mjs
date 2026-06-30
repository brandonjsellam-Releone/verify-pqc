#!/usr/bin/env node
/*!
 * pqfirmware-cli — QuantumShield: sign firmware + verify-before-flash from the command line (reference, DRAFT).
 *
 *   node pqfirmware-cli.mjs keygen   --out vendor [--slh]
 *   node pqfirmware-cli.mjs sign     <firmware-file> --keys vendor.keys.json --model M --version N --build B [--min-version K] [--out manifest.json]
 *   node pqfirmware-cli.mjs verify   <firmware-file> --manifest manifest.json --pub vendor.pub.json [--current-version N] [--model M]
 *
 * ⚠️ KEY HANDLING: `keygen` writes the vendor SECRET keys to a JSON file for DEV/TEST convenience only. In production,
 *    vendor signing keys belong in an HSM / KMS / hardware token — NEVER a plaintext file. (See KEY_HANDLING.md.)
 * Unaudited reference tool. Self-test: node pqfirmware-cli.mjs --selftest
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { signFirmware, verifyFirmware, makeVendorId } from './pqfirmware.mjs';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';

const HELP = `pqfirmware — QuantumShield firmware signing CLI

  keygen --out <prefix> [--slh]        generate a vendor hybrid keyset → <prefix>.keys.json (SECRET) + <prefix>.pub.json
  sign <firmware> --keys <f> --model <m> --version <n> --build <b> [--min-version <k>] [--out <manifest.json>]
  verify <firmware> --manifest <f> --pub <f> [--current-version <n>] [--model <m>]

⚠️ keygen writes SECRET keys to disk for DEV/TEST ONLY — production keys belong in an HSM/KMS, never a file.
Unaudited reference tool.`;

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (k) => { const i = argv.indexOf('--' + k); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null; };
const has = (k) => argv.includes('--' + k);
// robust positional extraction: a token is positional unless it is a flag (--x) or the value of a NON-boolean flag.
function positionals(args) {
  const BOOL = new Set(['slh', 'selftest']);
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) continue;
    const prev = args[i - 1];
    if (prev && prev.startsWith('--') && !BOOL.has(prev.slice(2))) continue;
    out.push(args[i]);
  }
  return out;
}
const positional = positionals(argv.slice(1));

function keyset(withSlh) {
  const eds = randomBytes(32);
  const ks = { ed: { secretKey: eds, publicKey: ed25519.getPublicKey(eds) }, mldsa: ml_dsa87.keygen(randomBytes(32)) };
  if (withSlh) ks.slh = slh_dsa_sha2_256f.keygen(randomBytes(96));
  return ks;
}
const pubOf = (ks) => ({ ed: bytesToHex(ks.ed.publicKey), mldsa: bytesToHex(ks.mldsa.publicKey), ...(ks.slh ? { slh: bytesToHex(ks.slh.publicKey) } : {}) });
function serializeSecret(ks) {
  return { ed: { secretKey: bytesToHex(ks.ed.secretKey), publicKey: bytesToHex(ks.ed.publicKey) },
    mldsa: { secretKey: bytesToHex(ks.mldsa.secretKey), publicKey: bytesToHex(ks.mldsa.publicKey) },
    ...(ks.slh ? { slh: { secretKey: bytesToHex(ks.slh.secretKey), publicKey: bytesToHex(ks.slh.publicKey) } } : {}) };
}
function loadSecret(o) {
  return { ed: { secretKey: hexToBytes(o.ed.secretKey), publicKey: hexToBytes(o.ed.publicKey) },
    mldsa: { secretKey: hexToBytes(o.mldsa.secretKey), publicKey: hexToBytes(o.mldsa.publicKey) },
    ...(o.slh ? { slh: { secretKey: hexToBytes(o.slh.secretKey), publicKey: hexToBytes(o.slh.publicKey) } } : {}) };
}
const loadPub = (o) => ({ ed: hexToBytes(o.ed), mldsa: hexToBytes(o.mldsa), ...(o.slh ? { slh: hexToBytes(o.slh) } : {}) });
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

function run() {
  if (!cmd || cmd === '--help' || cmd === '-h') { console.log(HELP); process.exit(0); }

  if (cmd === '--selftest') {   // exercises the CLI's own serialize↔load + IO layer (the value-add over the module)
    let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
    const ks = keyset(true);
    const rt = loadSecret(serializeSecret(ks));                 // round-trip the keyfile format
    const pub = loadPub(pubOf(ks));
    const fw = new Uint8Array(512).fill(7);
    const m = signFirmware({ vendorKeys: rt, deviceModel: 'X', version: 5, buildId: 'b', artifactBytes: fw });
    ok(verifyFirmware(m, pub, { artifactBytes: fw, currentVersion: 4, deviceModel: 'X' }).verified === true, 'keyfile roundtrip → sign → verify-before-flash');
    ok(verifyFirmware(m, pub, { artifactBytes: new Uint8Array(512).fill(9), currentVersion: 4 }).verified === false, 'tampered binary rejected');
    ok(verifyFirmware(m, pub, { artifactBytes: fw, currentVersion: 6 }).verified === false, 'rollback (installed >= manifest) rejected');
    ok(verifyFirmware(m, pub, { artifactBytes: fw, currentVersion: 4, deviceModel: 'Y' }).verified === false, 'wrong model rejected');
    console.log('pqfirmware-cli self-test: ' + pass + ' pass, ' + fail + ' fail'); process.exit(fail ? 1 : 0);
  }

  if (cmd === 'keygen') {
    const out = flag('out'); if (!out) { console.error('keygen: --out <prefix> required'); process.exit(2); }
    const ks = keyset(has('slh'));
    if (existsSync(out + '.keys.json')) { console.error('refusing to overwrite ' + out + '.keys.json'); process.exit(2); }
    writeFileSync(out + '.keys.json', JSON.stringify(serializeSecret(ks), null, 2));
    writeFileSync(out + '.pub.json', JSON.stringify(pubOf(ks), null, 2));
    console.error('⚠️  ' + out + '.keys.json contains SECRET keys — dev/test only; use an HSM/KMS in production.');
    console.log('vendor id: ' + makeVendorId({ ed: ks.ed.publicKey, mldsa: ks.mldsa.publicKey, ...(ks.slh ? { slh: ks.slh.publicKey } : {}) }));
    console.log('wrote ' + out + '.keys.json (secret) + ' + out + '.pub.json (public)');
    process.exit(0);
  }

  if (cmd === 'sign') {
    const fw = positional[0], keysF = flag('keys'), model = flag('model'), version = flag('version'), build = flag('build');
    if (!fw || !keysF || !model || version == null || !build) { console.error('sign: <firmware> --keys --model --version --build required'); process.exit(2); }
    const ks = loadSecret(readJson(keysF));
    const manifest = signFirmware({ vendorKeys: ks, deviceModel: model, version: Number(version), buildId: build, artifactBytes: readFileSync(fw), minVersion: flag('min-version') != null ? Number(flag('min-version')) : undefined });
    const out = flag('out') || 'manifest.json';
    writeFileSync(out, JSON.stringify(manifest, null, 2));
    console.log('signed ' + fw + ' → ' + out + '  (model=' + model + ' version=' + version + ' build=' + build + ', sha256=' + manifest.artifact_sha256.slice(0, 16) + '…)');
    process.exit(0);
  }

  if (cmd === 'verify') {
    const fw = positional[0], manF = flag('manifest'), pubF = flag('pub');
    if (!fw || !manF || !pubF) { console.error('verify: <firmware> --manifest --pub required'); process.exit(2); }
    const r = verifyFirmware(readJson(manF), loadPub(readJson(pubF)), { artifactBytes: readFileSync(fw), currentVersion: flag('current-version') != null ? Number(flag('current-version')) : undefined, deviceModel: flag('model') || undefined });
    if (r.verified) { console.log('✓ VERIFIED — safe to flash  (version ' + r.version + ', model ' + r.device_model + ')'); process.exit(0); }
    console.error('✗ REJECTED — ' + (r.reason || (r.rollback ? 'rollback' : r.wrongModel ? 'wrong model' : !r.artifactOk ? 'binary != signed digest' : 'invalid')) + ' — DO NOT FLASH'); process.exit(1);
  }

  console.error('unknown command: ' + cmd + '\n\n' + HELP); process.exit(2);
}
run();
