/* Unit + live tests for @trelyan/verify-pqc. Run: node test.js */
const F = require('./index.js');
let pass = 0, fail = 0;
function ok(c, m) { if (c) { pass++; } else { fail++; console.error('FAIL:', m); } }

// --- unit: inspect 0xBA deterministic compressed ---
const det = new Uint8Array(1201); det[0] = 0xBA; det.fill(0x11, 1);
const i = F.inspectFalconSig(det);
ok(i.headerHex === '0xba' && i.deterministic && i.fmt === 'compressed' && i.logn === 10 && !i.saltPresent, 'inspect 0xBA');

// --- unit: inspect 0x3A randomized (salt present) ---
const rnd = new Uint8Array(1241); rnd[0] = 0x3A; rnd.fill(0x22, 1);
const j = F.inspectFalconSig(rnd);
ok(!j.deterministic && j.saltPresent && j.bodyLen === 1200, 'inspect 0x3A');

// --- unit: ABI decode (0x04d4 = 1236 = len-2) ---
const abi = new Uint8Array(1238); abi[0] = 0x04; abi[1] = 0xd4; abi[2] = 0xBA;
const dec = F.abiDecodeBytes(abi);
ok(dec.length === 1236 && dec[0] === 0xBA, 'abiDecodeBytes');

// --- unit: compare ---
ok(F.compareSigs(det, det).identical, 'compare identical');
ok(F.compareSigs(det, rnd).diffRegion === 'header', 'compare header diff');

console.log('unit:', pass, 'pass,', fail, 'fail');

// --- live: verify the real on-chain inscription (CI sets PQC_SKIP_LIVE to skip network) ---
if (process.env.PQC_SKIP_LIVE) {
  console.log('live: skipped (PQC_SKIP_LIVE set)');
  console.log(fail === 0 ? 'UNIT TESTS PASS (' + pass + ')' : 'SOME TESTS FAILED (' + fail + ')');
  process.exit(fail === 0 ? 0 : 1);
}
F.verifyOnChain('763809096').then(function (r) {
  console.log('live verifyOnChain(763809096):', JSON.stringify({
    verified: r.verified, header: r.signature && r.signature.headerHex,
    len: r.signature && r.signature.totalLen, box: r.inscriptionBox, pubkey: r.pubkey, txid: r.sigTxid
  }, null, 2));
  ok(r.verified === true, 'live verified');
  ok(r.signature && r.signature.headerHex === '0xba' && r.signature.totalLen === 1236, 'live 0xBA/1236');
  ok(r.inscriptionBox === true && r.pubkey === true, 'live box+pubkey');
  console.log(fail === 0 ? 'ALL SDK TESTS PASS (' + pass + ')' : 'SOME TESTS FAILED (' + fail + ')');
  process.exit(fail === 0 ? 0 : 1);
}).catch(function (e) { console.error('live test error:', e.message); process.exit(1); });
