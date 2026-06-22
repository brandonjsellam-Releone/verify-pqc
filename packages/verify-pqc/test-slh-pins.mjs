// Tests for the SLH-DSA diversity leg + array-pin rotation-readiness. Run from the kit dir:
//   npm i @noble/post-quantum @noble/hashes && node test-slh-pins.mjs
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { readFileSync } from 'node:fs';
import { verifyThrondarSth, verifyThrondarStrong, THRONDAR_STH_PINS } from './mldsa.mjs';
import { verifyThrondarSlh, selfTest } from './slhdsa.mjs';

const enc = (s) => new TextEncoder().encode(s);
const CTX = { context: enc('throndar-sth-v1') };
let pass = 0, fail = 0;
const ok = (name, cond) => { (cond ? pass++ : fail++); console.log((cond ? 'PASS ' : 'FAIL ') + name); };

// Build a valid STH signed by a given ML-DSA-87 keypair under a given key_id.
function makeSth(sk, key_id) {
  const signed = 'STH-payload-' + key_id;
  const answer_sha256 = bytesToHex(sha256(enc(signed)));
  const r = { v: 1, model: 'm', answer_sha256, governance_flag: false, ts: 1782083680, context: 'throndar-sth-v1', key_id };
  const canonical = enc(JSON.stringify({ v: r.v, model: r.model, answer_sha256: r.answer_sha256, governance_flag: r.governance_flag, ts: r.ts }));
  r.sig = bytesToHex(ml_dsa87.sign(canonical, sk, CTX));
  return { signed, receipt: r };
}

// --- SLH self-test (pure @noble round-trip) ---
ok('slhdsa.selfTest()', selfTest().ok);

// --- Array-pin: current ---
const cur = ml_dsa87.keygen();
const curPins = [{ key_id: 'cur8', pubkey_hex: bytesToHex(cur.publicKey), role: 'current' }];
const sthCur = makeSth(cur.secretKey, 'cur8');
const vCur = verifyThrondarSth(sthCur, { pins: curPins });
ok('current pin verifies (verified + matchedRole=current)', vCur.verified === true && vCur.matchedRole === 'current');

// --- Array-pin: previous (overlap window) ---
const prevKp = ml_dsa87.keygen();
const overlapPins = [curPins[0], { key_id: 'prev8', pubkey_hex: bytesToHex(prevKp.publicKey), role: 'previous' }];
const sthPrev = makeSth(prevKp.secretKey, 'prev8');
const vPrev = verifyThrondarSth(sthPrev, { pins: overlapPins });
ok('previous pin verifies in overlap (matchedRole=previous)', vPrev.verified === true && vPrev.matchedRole === 'previous');

// --- Soundness: attacker spoofs a RECOGNIZED id but signs with their own key -> rejected ---
const atkKp = ml_dsa87.keygen();
const realId = THRONDAR_STH_PINS[0].key_id;                 // the genuine recognized id
const atk = makeSth(atkKp.secretKey, realId);              // attacker signs under their own key, claims the real id
const vAtk = verifyThrondarSth(atk);                        // DEFAULT pins (real pinned key)
ok('attack rejected (recognized id, foreign key -> verified=false)', vAtk.verified === false && vAtk.sigValid === false && vAtk.keyIdMatches === true);

// --- Unknown id -> rejected before any crypto ---
const unk = makeSth(cur.secretKey, 'ffffffffffffffff');
const vUnk = verifyThrondarSth(unk);
ok('unknown id rejected', vUnk.verified === false && vUnk.keyIdMatches === false && /recognized pin set/.test(vUnk.reason));

// --- SLH leg verifies a real SLH-DSA-256f co-signature (the production signer's algo, @noble) ---
let slhInterop = 'n/a';
{
  const kp = slh_dsa_sha2_256f.keygen();
  const r = { v: 1, model: 'm', answer_sha256: 'ab', governance_flag: false, ts: 1782083680 };
  const canon = enc(JSON.stringify({ v: r.v, model: r.model, answer_sha256: r.answer_sha256, governance_flag: r.governance_flag, ts: r.ts }));
  const slhSig = slh_dsa_sha2_256f.sign(canon, kp.secretKey, { context: enc('throndar-sth-v1') });
  const sth = { signed: 'x', receipt: { ...r, slh_sig: bytesToHex(slhSig) } };
  const vSlh = verifyThrondarSlh(sth, { pubkeyHex: bytesToHex(kp.publicKey) });
  slhInterop = vSlh.slhValid;
  ok('SLH leg verifies a 256f co-signature over the canonical core', vSlh.slhPresent === true && vSlh.slhValid === true);
  const wrongKp = slh_dsa_sha2_256f.keygen();
  const vBad = verifyThrondarSlh(sth, { pubkeyHex: bytesToHex(wrongKp.publicKey) });
  ok('foreign SLH key -> slhValid=false (non-fatal)', vBad.slhValid === false);
}

// --- verifyThrondarStrong: SLH NEVER changes the ML-DSA verdict ---
const strongCur = await verifyThrondarStrong(sthCur, { pins: curPins });
ok('strong.verified === ml verdict (true case)', strongCur.verified === vCur.verified);
const strongAtk = await verifyThrondarStrong(atk);
ok('strong.verified === ml verdict (false case)', strongAtk.verified === false);
// absent SLH pin -> slhPresent false, verdict unchanged
ok('SLH absent is harmless', strongCur.slhdsa.slhPresent === false && strongCur.verified === true);

console.log(`\n${pass} passed, ${fail} failed  (SLH interop: ${slhInterop})`);
process.exit(fail ? 1 : 0);
