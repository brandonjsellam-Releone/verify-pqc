#!/usr/bin/env node
/* Conformance gate: fail CI unless an Algorand app has an on-chain Falcon-1024 inscription
 * accepted by falcon_verify. Usage: node conformance-check.js [appId]  (or APP_ID / INDEXER env). */
const path = require('path');
const F = require(path.join(__dirname, '..', 'packages', 'verify-pqc'));

const app = process.argv[2] || process.env.APP_ID || '763809096';
const indexer = process.env.INDEXER || 'https://testnet-idx.algonode.cloud';

F.verifyOnChain(app, { indexer }).then(function (r) {
  console.log(JSON.stringify({
    app: r.appId, verified: r.verified,
    header: r.signature && r.signature.headerHex,
    len: r.signature && r.signature.totalLen,
    pubkey: r.pubkey, box: r.inscriptionBox, txid: r.sigTxid, claim: r.claim
  }, null, 2));
  if (!r.verified) {
    console.error('::error::Falcon inscription not verified on-chain for app ' + app);
    process.exit(1);
  }
  console.log('conformance: PASS');
}).catch(function (e) {
  console.error('::error::' + (e.message || e));
  process.exit(1);
});
