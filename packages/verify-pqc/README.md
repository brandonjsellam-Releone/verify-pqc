# @trelyan/verify-pqc

Dependency-free toolkit to inspect **Falcon-1024** signatures and verify **post-quantum
inscriptions on Algorand** (the AVM `falcon_verify` opcode). Works in Node ≥18 and the browser.

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
