# @trelyan/verify-pqc

Toolkit to verify THRONDAR's **dual post-quantum** provenance in your browser — its **ML-DSA-87 +
SLH-DSA-256f** transparency-log Signed Tree Head (FIPS-204 / FIPS-205) — plus dependency-free inspection
of **Falcon-1024** signatures and verification of **post-quantum inscriptions on Algorand** (the AVM
`falcon_verify` opcode). Works in Node ≥18 and the browser.

```bash
npm install @trelyan/verify-pqc
```

## Verify an on-chain post-quantum inscription

```js
const { verifyOnChain } = require('@trelyan/verify-pqc');

const r = await verifyOnChain('763809096'); // Algorand TestNet app
// {
//   verified: true,
//   signature: { headerHex: '0xba', totalLen: 1236, deterministic: true, fmt: 'compressed', logn: 10, ... },
//   inscriptionBox: true,          // the write-once i_ box exists
//   sigTxid: 'SQEPDOZ4…',
//   claim: 'A Falcon-1024 signature is on chain and a write-once inscription box exists …'
// }
```

In the browser, drop in `index.js` and call `verifyPQC.verifyOnChain(appId)` — it uses the
public algonode indexer (CORS-enabled) by default. Point at any indexer with
`verifyOnChain(appId, { indexer: 'https://…' })`.

## Verify THRONDAR's dual post-quantum signature (in your browser)

THRONDAR signs each transparency-log Signed Tree Head with **two independent post-quantum families**:
**ML-DSA-87** (FIPS-204, the load-bearing gate) plus an additive **SLH-DSA-256f** (FIPS-205, hash-based)
diversity leg. ML-DSA and Falcon are both *lattice* schemes, so the hash-based SLH-DSA leg is the only one
that survives a lattice break. Both are checked against **pinned full public keys** — not the keys the server sends:

```js
import { verifyThrondarStrong } from '@trelyan/verify-pqc/verify';

const j = await (await fetch('https://throndar.ai/api/transparency/ledger')).json();
const v = await verifyThrondarStrong(j.signed_tree_head);
// {
//   verified: true,                       // ← AUTHORITATIVE: the ML-DSA-87 result, ONLY
//   mldsa:  { verified: true, matchedRole: 'current', ... },
//   slhdsa: { slhPresent: true, slhValid: true, reason: 'ok' },
//   diversity: 'ml-dsa + slh-dsa (dual PQC family)'
// }
```

The SLH-DSA leg is **non-authoritative**: `verified` is *exactly* the ML-DSA-87 result — a missing or invalid
SLH co-signature can never flip the verdict either way. Rotation-ready: `THRONDAR_STH_PINS` accepts a
`{current, previous}` overlap set. Peer deps: `@noble/post-quantum` + `@noble/hashes` (the @noble libraries are
independently audited — that audit covers @noble's primitives, NOT this toolkit, which remains unaudited; pure-JS FIPS-204/205). Conformance KAT (deterministic vectors, exact FIPS sizes): `npm run test:kat`.

## Inspect / compare raw signatures

```js
const { inspectFalconSig, abiDecodeBytes, compareSigs } = require('@trelyan/verify-pqc');

inspectFalconSig(sigBytes);
// { headerHex:'0xba', logn:10, deterministic:true, fmt:'compressed', bodyLen:1235, notes:'…' }

abiDecodeBytes(appArgBytes);   // strips the Algorand ABI byte[] 2-byte length prefix
compareSigs(sigA, sigB);       // localizes the first divergence to header / salt / body
```

## Honest framing (please keep it)

`0xBA` = the standard Falcon-1024 compressed header `0x3A` (high-nibble compressed,
low-nibble logn 10) OR'd with a `0x80` bit and a `0x00` version byte that are **trelyan-pq's
deterministic-wrapper convention — not NIST Round-3 Falcon or FIPS-206 (FN-DSA) fields.**
`verifyOnChain` trusts the single indexer you point at and reads the contract's write-once
`i_` box as proof that `falcon_verify` accepted the signature; it does not re-run the opcode
locally. Targets Algorand **TestNet**; the reference system is **unaudited**.

MIT.
