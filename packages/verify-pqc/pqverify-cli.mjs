#!/usr/bin/env node
/*!
 * pqverify-cli — verify ANY TRELYAN artifact from the command line (reference, DRAFT). Thin wrapper over the hosted
 * verify-API surface (pqverify-api.mjs): composes the already-reviewed, TOTAL/fail-closed verifiers, adds no crypto.
 *
 *   node pqverify-cli.mjs <type> --artifact <file.json> [pin] [opts]
 *   node pqverify-cli.mjs list                          → print the supported types
 *
 * PIN (trust) — a verdict is VALIDITY, not trust, until you pin the expected key:
 *   Wave-2 hybrid types:  --pub <key.pub.json>   OR   --ed <hex> --mldsa <hex> [--slh <hex>]
 *   evidence-pack:        --signer <hex>          | sign-bundle: --signer <hex> --log <hex>
 *   tst/tst-restamp:      --tsa <hex>             | kt-inclusion: --log <hex>   | pqef: --issuers <hex,hex>
 * Binding / scope opts:   --artifact-bin <file> (bind the actual binary for app-cert/firmware) | --allow-unbound
 *   --current-version <n> --model <m> --min-cert-level <L> --min-version <v> --request '<json>'
 *   --purpose <p> --category <c> --max-amount <n> --payee <s> --currency <c> --revoked <id,id> --now <int>
 *
 * Unaudited reference tool. Self-test: node pqverify-cli.mjs --selftest
 */
import { verify, SUPPORTED } from './pqverify-api.mjs';
import { readFileSync, writeFileSync, unlinkSync } from 'fs';
import { bytesToHex } from '@noble/hashes/utils.js';

const HELP = `pqverify — verify any TRELYAN artifact (reference, unaudited)

  node pqverify-cli.mjs <type> --artifact <file.json> [pin] [opts]
  node pqverify-cli.mjs list

types: ${SUPPORTED.join(', ')}

pin (a verdict is VALIDITY, not trust, until you pin the expected key):
  hybrid (Wave-2):  --pub <key.pub.json>  OR  --ed <hex> --mldsa <hex> [--slh <hex>]
  evidence-pack:    --signer <hex>      sign-bundle: --signer <hex> --log <hex>
  tst:              --tsa <hex>         kt-inclusion: --log <hex>   pqef: --issuers <hex,hex>
opts: --artifact-bin <bin> | --allow-unbound | --current-version <n> | --model <m> | --request '<json>'
      --purpose <p> --category <c> --max-amount <n> --payee <s> --currency <c> --revoked <id,id> --now <n>`;

const argv = process.argv.slice(2);
const cmd = argv[0];
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

// flag/has bound to a given args array (so --selftest can pass synthetic args, not process.argv).
const binder = (args) => ({
  flag: (k) => { const i = args.indexOf('--' + k); return i >= 0 && i + 1 < args.length ? args[i + 1] : null; },
  has: (k) => args.includes('--' + k),
});

// map CLI flags → the verify-API `trust` block. Pure (args in, object out) → unit-testable.
function buildTrust(args) {
  const { flag, has } = binder(args);
  const tr = {};
  const pubF = flag('pub');
  if (pubF) { const p = readJson(pubF); if (p.ed) tr.ed_pub_hex = p.ed; if (p.mldsa) tr.mldsa_pub_hex = p.mldsa; if (p.slh) tr.slh_pub_hex = p.slh; }
  if (flag('ed')) tr.ed_pub_hex = flag('ed');
  if (flag('mldsa')) tr.mldsa_pub_hex = flag('mldsa');
  if (flag('slh')) tr.slh_pub_hex = flag('slh');
  if (flag('signer')) tr.signer_pub_hex = flag('signer');
  if (flag('log')) tr.log_pub_hex = flag('log');
  if (flag('tsa')) tr.tsa_pub_hex = flag('tsa');
  if (flag('issuers')) tr.trustedIssuers = flag('issuers').split(',').filter(Boolean);
  if (flag('artifact-bin')) tr.artifact_hex = bytesToHex(readFileSync(flag('artifact-bin')));
  if (has('allow-unbound')) tr.allowUnboundArtifact = true;
  if (flag('now') != null) tr.now = Number(flag('now'));
  if (flag('current-version') != null) tr.currentVersion = Number(flag('current-version'));
  if (flag('model')) tr.deviceModel = flag('model');
  if (flag('min-cert-level')) tr.minCertLevel = flag('min-cert-level');
  if (flag('min-version')) tr.minVersion = flag('min-version');
  if (flag('purpose')) tr.purpose = flag('purpose');
  if (flag('category')) tr.category = flag('category');
  if (flag('controller')) tr.controller = flag('controller');
  if (flag('max-amount') != null) tr.maxAmount = Number(flag('max-amount'));
  if (flag('payee')) tr.expectedPayee = flag('payee');
  if (flag('currency')) tr.expectedCurrency = flag('currency');
  if (flag('request')) { try { tr.request = JSON.parse(flag('request')); } catch { /* leave unset → token-validity-only */ } }
  if (flag('revoked')) tr.revoked = flag('revoked').split(',').filter(Boolean);
  return tr;
}

async function run() {
  if (!cmd || cmd === '--help' || cmd === '-h') { console.log(HELP); process.exit(0); }
  if (cmd === '--selftest') return selfTest();
  if (cmd === 'list') { console.log(SUPPORTED.join('\n')); process.exit(0); }
  if (!SUPPORTED.includes(cmd)) { console.error('unknown type: ' + cmd + '\nsupported: ' + SUPPORTED.join(', ')); process.exit(2); }
  const { flag } = binder(argv);
  const artF = flag('artifact'); if (!artF) { console.error(cmd + ': --artifact <file.json> required'); process.exit(2); }
  const r = await verify({ type: cmd, artifact: readJson(artF), trust: buildTrust(argv) });
  if (!r.ok) { console.error('✗ ERROR — ' + r.error); process.exit(2); }
  const v = r.verdict;
  if (v && v.verified) {
    console.log('✓ VERIFIED (' + r.type + ')' + (r.pinned ? '  [pinned key checked]' : '  [UNPINNED — cryptographic validity, NOT trust; pin the expected key]'));
    if (v.signer || v.subject || v.issuer) console.log('  signer: ' + String(v.signer || v.subject || v.issuer).slice(0, 48) + '…');
    if (r.caveat) console.log('  ⚠ caveat: ' + r.caveat);
    process.exit(0);
  }
  console.error('✗ NOT VERIFIED (' + r.type + ') — ' + ((v && v.reason) || 'invalid artifact') + (r.caveat ? '\n  ⚠ caveat: ' + r.caveat : ''));
  process.exit(1);
}

/* ---------- self-test: node pqverify-cli.mjs --selftest ---------- */
async function selfTest() {
  let pass = 0, fail = 0; const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
  const { createShieldReport } = await import('./pqshield.mjs');
  const ks = (e, m) => ({ ed: { secretKey: new Uint8Array(32).fill(e), publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(e)) }, mldsa: ml_dsa87.keygen(new Uint8Array(32).fill(m)) });

  // buildTrust flag mapping (the CLI's real value-add) — pure, no IO
  const t1 = buildTrust(['--ed', 'aa', '--mldsa', 'bb', '--current-version', '6', '--allow-unbound', '--request', '{"tool":"T"}', '--issuers', 'x,y']);
  ok(t1.ed_pub_hex === 'aa' && t1.mldsa_pub_hex === 'bb', 'maps --ed/--mldsa → hybrid pin');
  ok(t1.currentVersion === 6 && typeof t1.currentVersion === 'number', 'maps --current-version → number');
  ok(t1.allowUnboundArtifact === true, 'maps --allow-unbound → boolean opt-in');
  ok(t1.request && t1.request.tool === 'T', 'parses --request JSON');
  ok(Array.isArray(t1.trustedIssuers) && t1.trustedIssuers.length === 2, 'splits --issuers CSV');

  // --pub keyfile read
  const k = ks(70, 71);
  const pubPath = '.pqverify-cli-selftest.pub.json';
  writeFileSync(pubPath, JSON.stringify({ ed: bytesToHex(k.ed.publicKey), mldsa: bytesToHex(k.mldsa.publicKey) }));
  try {
    const t2 = buildTrust(['--pub', pubPath]);
    ok(t2.ed_pub_hex === bytesToHex(k.ed.publicKey) && t2.mldsa_pub_hex === bytesToHex(k.mldsa.publicKey), 'reads --pub keyfile → hybrid pin');
  } finally { try { unlinkSync(pubPath); } catch { /* ignore */ } }

  // end-to-end through verify(): a real shield-report verifies under the pinned key, and not under a wrong one
  const rep = createShieldReport({ issuerKeys: k, target: 'cli-st', assets: [{ label: 'x', algorithm: 'RSA-2048', internet_facing: true }] });
  const good = await verify({ type: 'shield-report', artifact: rep, trust: buildTrust(['--ed', bytesToHex(k.ed.publicKey), '--mldsa', bytesToHex(k.mldsa.publicKey)]) });
  ok(good.ok && good.verdict.verified === true && good.pinned === true, 'end-to-end: shield-report verifies under the pinned key');
  const wrong = ks(1, 2);
  const bad = await verify({ type: 'shield-report', artifact: rep, trust: buildTrust(['--ed', bytesToHex(wrong.ed.publicKey), '--mldsa', bytesToHex(wrong.mldsa.publicKey)]) });
  ok(bad.verdict.verified === false, 'end-to-end: shield-report under a wrong pinned key → NOT verified');

  console.log('pqverify-cli self-test: ' + pass + ' pass, ' + fail + ' fail');
  process.exit(fail ? 1 : 0);
}
run().catch((e) => { console.error('✗ ERROR — ' + String((e && e.message) || e)); process.exit(2); });
