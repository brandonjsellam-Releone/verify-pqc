#!/usr/bin/env node
/*!
 * qiv-cli — Quantum IP Vault command line (reference, DRAFT). Thin wrapper over qiv.mjs; adds NO crypto.
 *
 *   node qiv-cli.mjs keygen  --out keys.json [--seed <hex>]         generate a 3-family signer set + TSA + custody keys
 *   node qiv-cli.mjs inscribe --artifact <file> --cell <1..1024> --type <patent|trade_secret|...> \
 *                             --title "<t>" [--inventors "a,b"] [--jurisdiction US] [--ipfs <uri>] \
 *                             --keys keys.json [--ts <int>] [--out record.json]
 *   node qiv-cli.mjs verify  --record record.json --artifact <file> [--keys keys.json] [--lenient]
 *   node qiv-cli.mjs custody --demo                                  build+verify a sample custody chain
 *   node qiv-cli.mjs --selftest
 *
 * A verdict is VALIDITY, not TRUST, until keys are pinned: `verify` pins the pqseal legs + TSA from --keys by default
 * (drop with --lenient). SECRET KEYS in a keyfile are for REFERENCE/DEMO on your own machine — not a KMS. Broadcasting
 * to Algorand + off-chain pinning + any marketplace/value-transfer feature are OWNER-GATED and not performed here.
 */
import { inscribe, verifyInscription, openCustody, appendCustody, verifyCustody, digestArtifact, ALGORAND, IP_TYPES, CELL_STATES } from './qiv.mjs';
import { genTsaKey } from './pqtsa.mjs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { readFileSync, writeFileSync } from 'fs';

const HELP = `qiv — Quantum IP Vault (reference, unaudited, DRAFT)

  node qiv-cli.mjs keygen   --out keys.json [--seed <hex>]
  node qiv-cli.mjs inscribe --artifact <file> --cell <1..1024> --type <${IP_TYPES.join('|')}> --title "<t>"
                            [--inventors "a,b"] [--jurisdiction US] [--ipfs <uri>] --keys keys.json [--ts <int>] [--out record.json]
  node qiv-cli.mjs verify   --record record.json --artifact <file> [--keys keys.json] [--lenient]
  node qiv-cli.mjs custody  --demo
  node qiv-cli.mjs --selftest

Claim hygiene: produces a tamper-evident, PQ-signed, timestamped record of existence-at-time that can SUPPORT (not
constitute) IP evidence. NOT a patent filing. NOT "legally admissible." Marketplace/tokenized shares = securities-gated.`;

function parse(args) {
  const o = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) { const k = a.slice(2); const v = (i + 1 < args.length && !args[i + 1].startsWith('--')) ? args[++i] : true; o[k] = v; }
    else o._.push(a);
  }
  return o;
}
const die = (m) => { console.error(m); process.exit(1); };

// --- deterministic-from-seed or random signer material ---
function genKeys(seed) {
  // accept a hex seed OR any string (hashed to 32 bytes) OR nothing (random) — all deterministic-from-seed.
  const isHex = typeof seed === 'string' && /^[0-9a-fA-F]+$/.test(seed) && seed.length % 2 === 0;
  const base = !seed ? randomBytes(32) : (isHex ? hexToBytes(seed) : sha256(utf8ToBytes(seed)));
  const d = (tag, len = 32) => { const b = new Uint8Array(len); const s = utf8ToBytes(tag); for (let i = 0; i < len; i++) b[i] = base[i % base.length] ^ (s[i % s.length]); return b; };
  const ed = (() => { const sk = d('ed'); return { secretKey: bytesToHex(sk), publicKey: bytesToHex(ed25519.getPublicKey(sk)) }; })();
  const ml = (() => { const k = ml_dsa87.keygen(d('mldsa')); return { secretKey: bytesToHex(k.secretKey), publicKey: bytesToHex(k.publicKey) }; })();
  const slh = (() => { const k = slh_dsa_sha2_256f.keygen(d('slh', 96)); return { secretKey: bytesToHex(k.secretKey), publicKey: bytesToHex(k.publicKey) }; })();
  const tsa = (() => { const k = genTsaKey(d('tsa')); return { secretKey: bytesToHex(k.secretKey), publicKey: bytesToHex(k.publicKey) }; })();
  const custody = {
    ed: (() => { const sk = d('c-ed'); return { secretKey: bytesToHex(sk), publicKey: bytesToHex(ed25519.getPublicKey(sk)) }; })(),
    mldsa: (() => { const k = ml_dsa87.keygen(d('c-mldsa')); return { secretKey: bytesToHex(k.secretKey), publicKey: bytesToHex(k.publicKey) }; })(),
    slh: (() => { const k = slh_dsa_sha2_256f.keygen(d('c-slh', 96)); return { secretKey: bytesToHex(k.secretKey), publicKey: bytesToHex(k.publicKey) }; })(),
  };
  return { note: 'QIV reference keys — DEMO ONLY, not a KMS. Keep secret keys private.', ed, mldsa: ml, slh, tsa, custody };
}
const signersFrom = (k) => [
  { alg: 'ML-DSA-87', secretKey: hexToBytes(k.mldsa.secretKey), publicKey: hexToBytes(k.mldsa.publicKey) },
  { alg: 'SLH-DSA-256f', secretKey: hexToBytes(k.slh.secretKey), publicKey: hexToBytes(k.slh.publicKey) },
  { alg: 'Ed25519', secretKey: hexToBytes(k.ed.secretKey), publicKey: hexToBytes(k.ed.publicKey) },
];

function main(argv) {
  const cmd = argv[0];
  const o = parse(argv.slice(1));
  if (!cmd || cmd === '--help' || cmd === '-h') return console.log(HELP);

  if (cmd === 'keygen') {
    if (!o.out) die('keygen: --out <file> required');
    const keys = genKeys(typeof o.seed === 'string' ? o.seed : null);
    writeFileSync(o.out, JSON.stringify(keys, null, 2));
    return console.log(`keygen: wrote ${o.out} (ML-DSA-87 ∧ SLH-DSA-256f ∧ Ed25519 + TSA + custody). Public pins:\n  ML-DSA-87 ${keys.mldsa.publicKey.slice(0, 24)}…\n  SLH-DSA   ${keys.slh.publicKey.slice(0, 24)}…\n  Ed25519   ${keys.ed.publicKey.slice(0, 24)}…`);
  }

  if (cmd === 'inscribe') {
    for (const r of ['artifact', 'cell', 'type', 'title', 'keys']) if (!o[r]) die(`inscribe: --${r} required`);
    const artifactBytes = readFileSync(o.artifact);
    const keys = JSON.parse(readFileSync(o.keys, 'utf8'));
    const ins = inscribe({
      cellId: parseInt(o.cell, 10), ipType: o.type,
      metadata: { title: o.title, inventors: o.inventors ? String(o.inventors).split(',').map((s) => s.trim()) : [], jurisdiction: o.jurisdiction || null },
      artifactBytes,
      offchain: o.ipfs ? { kind: 'ipfs', uri: o.ipfs } : { kind: 'none' },
    }, signersFrom(keys), { secretKey: hexToBytes(keys.tsa.secretKey), publicKey: hexToBytes(keys.tsa.publicKey) },
      { ts: o.ts ? parseInt(o.ts, 10) : undefined });
    const out = o.out || 'qiv-record.json';
    writeFileSync(out, JSON.stringify(ins, null, 2));
    console.log(`inscribe: cell #${ins.record.cell_id} (${ins.record.ip_type}, ${ins.record.cell_state})`);
    console.log(`  artifact SHA-512 : ${ins.record.artifact_sha512.slice(0, 32)}…`);
    console.log(`  record hash      : ${ins.record_hash}`);
    console.log(`  seal suite       : ${ins.seal.suite}`);
    console.log(`  Algorand note    : ${ins.anchor.note_hex.slice(0, 40)}…  (app ${ins.anchor.app_id}, ${ins.anchor.network}, broadcast=${ins.anchor.broadcast})`);
    console.log(`  wrote ${out}`);
    return;
  }

  if (cmd === 'verify') {
    for (const r of ['record', 'artifact']) if (!o[r]) die(`verify: --${r} required`);
    const ins = JSON.parse(readFileSync(o.record, 'utf8'));
    const artifactBytes = readFileSync(o.artifact);
    let opts = {};
    if (o.keys && !o.lenient) {
      const k = JSON.parse(readFileSync(o.keys, 'utf8'));
      opts = { trusted: { 'ML-DSA-87': hexToBytes(k.mldsa.publicKey), 'SLH-DSA-256f': hexToBytes(k.slh.publicKey), 'Ed25519': hexToBytes(k.ed.publicKey) }, requireKinds: ['lattice', 'hash-based', 'classical'], tsaPub: hexToBytes(k.tsa.publicKey) };
    }
    const v = verifyInscription(ins, artifactBytes, opts);
    console.log(`verify: ${v.verified ? 'PASS ✅' : 'FAIL ❌'}  (${v.reason})`);
    console.log(`  artifact digest : ${v.artifactOk ? 'ok' : 'MISMATCH'}`);
    console.log(`  cell/type/state : ${v.cellOk ? 'ok' : 'BAD'}`);
    console.log(`  seal (AND-comp) : ${v.sealOk ? 'ok' : 'BAD'}  kinds=[${(v.seal && v.seal.kinds || []).join(',')}]`);
    console.log(`  timestamp       : ${v.tst}`);
    console.log(`  anchor bytes    : ${v.anchorOk ? 'ok' : 'BAD'}`);
    if (!o.keys) console.log('  (no --keys → VALIDITY only, not TRUST. Pin keys to authenticate the signer.)');
    process.exit(v.verified ? 0 : 1);
  }

  if (cmd === 'custody') {
    if (!o.demo) die('custody: only --demo is implemented in the CLI (use the qiv.mjs API for real chains)');
    const k = genKeys('demoseed');
    const signer = { ed: { secretKey: hexToBytes(k.custody.ed.secretKey), publicKey: hexToBytes(k.custody.ed.publicKey) }, mldsa: { secretKey: hexToBytes(k.custody.mldsa.secretKey), publicKey: hexToBytes(k.custody.mldsa.publicKey) }, slh: { secretKey: hexToBytes(k.custody.slh.secretKey), publicKey: hexToBytes(k.custody.slh.publicKey) } };
    const log = openCustody(1, signer);
    appendCustody(log, { actor: 'inventor', action: 'create', cellState: 'sealed', payload: 'draft', ts: 1_700_000_000 });
    appendCustody(log, { actor: 'vault', action: 'inscribe', cellState: 'inscribed', payload: 'anchored', ts: 1_700_000_100 });
    appendCustody(log, { actor: 'office', action: 'release', cellState: 'released', payload: 'granted', ts: 1_700_000_200 });
    const cv = verifyCustody(log.entries, { ed: signer.ed.publicKey, mldsa: signer.mldsa.publicKey, slh: signer.slh.publicKey });
    console.log(`custody demo: ${cv.n} entries, verified=${cv.verified}, final_state=${cv.final_state}`);
    log.entries.forEach((e) => console.log(`  #${e.seq} ${e.action.padEnd(9)} -> ${e.cell_state.padEnd(9)} by ${e.actor} @${e.ts}`));
    return;
  }

  if (cmd === '--selftest') {
    const k = genKeys('selftestseed');
    const artifact = utf8ToBytes('CLI self-test artifact');
    const ins = inscribe({ cellId: 3, ipType: 'patent', metadata: { title: 'X' }, artifactBytes: artifact }, signersFrom(k), { secretKey: hexToBytes(k.tsa.secretKey), publicKey: hexToBytes(k.tsa.publicKey) }, { ts: 1 });
    const v = verifyInscription(ins, artifact, { trusted: { 'ML-DSA-87': hexToBytes(k.mldsa.publicKey), 'SLH-DSA-256f': hexToBytes(k.slh.publicKey), 'Ed25519': hexToBytes(k.ed.publicKey) }, requireKinds: ['lattice', 'hash-based', 'classical'], tsaPub: hexToBytes(k.tsa.publicKey) });
    const bad = verifyInscription(ins, utf8ToBytes('tampered'), {});
    console.log(`qiv-cli selftest: inscribe+verify=${v.verified}, tamper-rejected=${!bad.verified}, digest=${digestArtifact(artifact).slice(0, 16)}…`);
    process.exit(v.verified && !bad.verified ? 0 : 1);
  }

  die(`unknown command: ${cmd}\n\n${HELP}`);
}

main(process.argv.slice(2));
