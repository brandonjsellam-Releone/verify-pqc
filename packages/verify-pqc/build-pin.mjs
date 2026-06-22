// Build step: generate the pinned THRONDAR STH-signer key data (full ML-DSA-87 pubkey,
// NOT a truncated thumbprint) + vendor the self-bundled @noble so the browser verifier
// never loads its deciding crypto from a third-party CDN. Run from the repo root.
import fs from 'fs';
const PK = fs.readFileSync('C:/mldsatest/pk.txt', 'utf8').trim();
if (PK.length !== 2592 * 2 || !/^[0-9a-f]+$/.test(PK)) throw new Error('bad pubkey: len ' + PK.length);
const KEYID = '0986d89fa3c74566';
const data =
`// GENERATED — pinned THRONDAR transparency-log STH-signer public key (ML-DSA-87, FIPS-204, 2592 B).
// This is the ROOT OF TRUST: the in-browser verifier checks signatures against THIS key, NOT the
// key the server sends. If THRONDAR rotates the STH key, regenerate this file (see DEFENSE.md).
export const THRONDAR_STH_KEY_ID = ${JSON.stringify(KEYID)};
export const THRONDAR_STH_PUBKEY_HEX = ${JSON.stringify(PK)};
`;
fs.writeFileSync('packages/verify-pqc/throndar-sth-key.mjs', data); // .mjs: always ESM (package is type:commonjs)
try { fs.unlinkSync('packages/verify-pqc/throndar-sth-key.js'); } catch {}
fs.mkdirSync('web/vendor', { recursive: true });
fs.writeFileSync('web/vendor/throndar-sth-key.js', data); // browser: extension-agnostic (module script)
fs.copyFileSync('C:/mldsatest/mldsa-bundle.js', 'web/vendor/mldsa-bundle.js');
console.log('pinned pubkey ' + PK.length / 2 + ' B; wrote throndar-sth-key.js (x2) + web/vendor/mldsa-bundle.js');
