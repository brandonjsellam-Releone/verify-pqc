// Build step: generate the pinned THRONDAR STH-signer key data (full ML-DSA-87 pubkey,
// NOT a truncated thumbprint) + the SLH-DSA-256s diversity pin + vendor the self-bundled @noble
// so the browser verifier never loads its deciding crypto from a third-party CDN. Run from repo root.
import fs from 'fs';
const PK = fs.readFileSync('C:/mldsatest/pk.txt', 'utf8').trim();
if (PK.length !== 2592 * 2 || !/^[0-9a-f]+$/.test(PK)) throw new Error('bad pubkey: len ' + PK.length);
const KEYID = '0986d89fa3c74566';

// Optional rotation overlap: a previous ML-DSA key during a rotation window. Absent ⇒ pins = [{current}].
let prev = [];
try { prev = JSON.parse(fs.readFileSync('C:/mldsatest/prev-key.json', 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
const pinsLiteral = JSON.stringify(
  [{ key_id: KEYID, pubkey_hex: PK, role: 'current' },
   ...prev.map((p) => ({ key_id: p.key_id, pubkey_hex: p.pubkey_hex, role: 'previous' }))], null, 2);

const data =
`// GENERATED — pinned THRONDAR transparency-log STH-signer public key (ML-DSA-87, FIPS-204, 2592 B).
// This is the ROOT OF TRUST: the in-browser verifier checks signatures against THIS key, NOT the
// key the server sends. If THRONDAR rotates the STH key, regenerate this file (see DEFENSE.md).
export const THRONDAR_STH_KEY_ID = ${JSON.stringify(KEYID)};
export const THRONDAR_STH_PUBKEY_HEX = ${JSON.stringify(PK)};
export const THRONDAR_STH_PINS = ${pinsLiteral};
`;
fs.writeFileSync('packages/verify-pqc/throndar-sth-key.mjs', data); // .mjs: always ESM (package is type:commonjs)
try { fs.unlinkSync('packages/verify-pqc/throndar-sth-key.js'); } catch {}
fs.mkdirSync('web/vendor', { recursive: true });
fs.writeFileSync('web/vendor/throndar-sth-key.js', data); // browser: extension-agnostic (module script)
fs.copyFileSync('C:/mldsatest/mldsa-bundle.js', 'web/vendor/mldsa-bundle.js');

// --- ADDITIVE: SLH-DSA-256s diversity pin (handbook §4.2/§6.2.3). Empty until THRONDAR publishes one. ---
let SLH_PK = '', SLH_KEYID = '';
try {
  SLH_PK = fs.readFileSync('C:/mldsatest/slh-pk.txt', 'utf8').trim();
  if (SLH_PK && (SLH_PK.length !== 64 * 2 || !/^[0-9a-f]+$/.test(SLH_PK))) throw new Error('bad SLH pubkey: len ' + SLH_PK.length);
  SLH_KEYID = fs.existsSync('C:/mldsatest/slh-keyid.txt') ? fs.readFileSync('C:/mldsatest/slh-keyid.txt', 'utf8').trim() : '';
} catch (e) { if (e.code !== 'ENOENT') throw e; }
const slhData =
`// GENERATED — pinned THRONDAR SLH-DSA-256s STH co-signer public key (SLH-DSA, FIPS-205, 64 B).
// ADDITIVE, NON-AUTHORITATIVE diversity leg (handbook §4.2/§6.2.3). Empty until THRONDAR publishes one.
export const THRONDAR_SLH_KEY_ID = ${JSON.stringify(SLH_KEYID)};
export const THRONDAR_SLH_PUBKEY_HEX = ${JSON.stringify(SLH_PK)};
`;
fs.writeFileSync('packages/verify-pqc/throndar-slh-key.mjs', slhData);
fs.writeFileSync('web/vendor/throndar-slh-key.js', slhData);
if (fs.existsSync('C:/mldsatest/slh-bundle.js')) fs.copyFileSync('C:/mldsatest/slh-bundle.js', 'web/vendor/slh-bundle.js');
console.log('pinned ML-DSA pubkey ' + PK.length / 2 + ' B (pins: ' + (1 + prev.length) + ')' + (SLH_PK ? '; + SLH pin ' + SLH_PK.length / 2 + ' B' : '; SLH pin empty'));
