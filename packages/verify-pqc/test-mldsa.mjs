/* Proof for the ML-DSA-87 Layer-1 verifier (verifyThrondarSth). Requires the optional peer
 * deps + network. Run:  npm i @noble/post-quantum @noble/hashes && node test-mldsa.mjs
 *
 * Asserts: (1) the LIVE THRONDAR STH verifies under the PINNED key; (2) an attacker who
 * controls the ENTIRE server response (own keypair + spoofed key_id) is REJECTED; (3) a
 * tampered signature is rejected. (2) is the soundness guarantee the Apex-council review demanded.
 */
import { verifyThrondarSth } from './mldsa.mjs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import https from 'https';
const enc = (s) => new TextEncoder().encode(s), hex = (u) => Buffer.from(u).toString('hex');
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.error('FAIL:', m); } };

https.get('https://throndar.ai/api/transparency/ledger', (res) => {
  let b = ''; res.on('data', (d) => b += d); res.on('end', () => {
    const sth = JSON.parse(b).signed_tree_head, r = sth.receipt;
    ok(verifyThrondarSth(sth).verified === true, 'live STH verifies under the pinned key');

    const kp = ml_dsa87.keygen(new Uint8Array(32).fill(7));
    const canon = enc(JSON.stringify({ v: r.v, model: r.model, answer_sha256: r.answer_sha256, governance_flag: r.governance_flag, ts: Number(r.ts) }));
    const atk = JSON.parse(JSON.stringify(sth));
    atk.receipt.sig = hex(ml_dsa87.sign(canon, kp.secretKey, { context: enc('throndar-sth-v1') }));
    atk.key.public_key_hex = hex(kp.publicKey);
    atk.receipt.key_id = '0986d89fa3c74566'; atk.key.key_id = '0986d89fa3c74566';
    ok(verifyThrondarSth(atk).verified === false, 'attacker keypair + spoofed key_id is REJECTED (pinned key)');

    const t = JSON.parse(JSON.stringify(sth)); t.receipt.sig = '00' + t.receipt.sig.slice(2);
    ok(verifyThrondarSth(t).verified === false, 'tampered signature is rejected');

    console.log(`mldsa: ${pass} pass, ${fail} fail`);
    process.exit(fail ? 1 : 0);
  });
}).on('error', (e) => { console.error('network error:', e.message); process.exit(1); });
