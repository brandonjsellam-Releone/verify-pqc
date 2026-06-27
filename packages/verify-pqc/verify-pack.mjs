/*!
 * verify-pack — standalone CLI to independently verify a PQC Migration Evidence Pack, offline. Hand this + a pack to a
 * skeptic; they confirm the signatures, that the grade is recomputed from the findings, and that the rendered report is
 * bound — without trusting us. AUTHENTICITY requires pinning the signer key(s) you obtained out-of-band (--mldsa-pub).
 *
 *   node verify-pack.mjs <pack.json> [--mldsa-pub <hex>] [--slh-pub <hex>] [--require-hybrid] [--require-pinned]
 *
 * Exit 0 if verified, 1 otherwise. Example: node verify-pack.mjs examples/demo/demo-out/evidence-pack.signed.json
 */
import { verifyEvidencePack } from './pqcbom-report.mjs';
import { hexToBytes } from '@noble/hashes/utils.js';
import { readFileSync } from 'fs';

const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : null; };
const has = (name) => args.includes(name);
const packPath = args.find((a) => !a.startsWith('--') && (args.indexOf(a) === 0 || !args[args.indexOf(a) - 1].startsWith('--mldsa-pub') && !args[args.indexOf(a) - 1].startsWith('--slh-pub')));

if (!packPath) {
  console.error('usage: node verify-pack.mjs <pack.json> [--mldsa-pub <hex>] [--slh-pub <hex>] [--require-hybrid] [--require-pinned]');
  process.exit(2);
}

let pack; try { pack = JSON.parse(readFileSync(packPath, 'utf8')); } catch (e) { console.error('cannot read pack: ' + (e && e.message)); process.exit(2); }

const mldsaPubHex = flag('--mldsa-pub');
const slhPubHex = flag('--slh-pub');
const opts = {};
if (slhPubHex) opts.trustedSlhPub = hexToBytes(slhPubHex);
if (has('--require-hybrid')) opts.requireHybrid = true;
if (has('--require-pinned')) opts.requirePinned = true;

const r = verifyEvidencePack(pack, mldsaPubHex ? hexToBytes(mldsaPubHex) : undefined, opts);
const yn = (b) => (b ? 'yes' : 'NO');

console.log('\nPQC Migration Evidence Pack — verification');
console.log('  pack:               ' + packPath);
console.log('  grade (stated):     ' + (pack.grade && pack.grade.letter) + ' (' + (pack.grade && pack.grade.score) + '/100)');
console.log('  signer (ML-DSA-87): ' + ((pack.signature && pack.signature.signer_pub_hex) || '—').slice(0, 24) + '…');
console.log('  hybrid 2nd leg:     ' + (pack.signature_slh ? 'SLH-DSA present (' + pack.signature_slh.signer_pub_hex.slice(0, 16) + '…)' : 'none'));
console.log('  ---');
console.log('  signature valid:    ' + yn(r.sigOk) + (r.hybrid ? ' (ML-DSA) · SLH-DSA valid: ' + yn(r.slhValid) : ''));
console.log('  grade from findings:' + yn(r.gradeConsistent) + '   (grade recomputed from the findings, not trusted)');
console.log('  report bound:       ' + yn(r.sigOk) + '   (markdown hash is inside the signed core)');
console.log('  trust-anchored:     ' + yn(r.trustAnchored) + (r.trustAnchored ? '' : '   (no key pinned → self-consistent only, NOT proof of origin)'));
console.log('  ---');
console.log('  VERIFIED:           ' + (r.verified ? 'YES ✓' : 'NO ✗'));
if (r.verified && !r.trustAnchored) console.log('\n  Note: this proves the pack is internally consistent + self-signed. For AUTHENTICITY, re-run with\n  --mldsa-pub <the signer key you obtained from TRELYAN out-of-band> (and --slh-pub for the hybrid leg).');
process.exit(r.verified ? 0 : 1);
