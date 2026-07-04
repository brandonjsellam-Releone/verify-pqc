# @trelyan/verify-pqc

**Post-quantum readiness scanner + verification toolkit.** Find where quantum-vulnerable cryptography lives in your
code (A–F grade + a CycloneDX 1.6 CBOM), build/verify signed **Evidence Packs**, and verify Falcon-1024 / ML-DSA-87
post-quantum signatures. Dependency-free core; Node ≥18 + browser. MIT.

```bash
npm install @trelyan/verify-pqc
```

## Scan a repo for quantum-vulnerable crypto (CLI)

```bash
npx -p @trelyan/verify-pqc pqcbom .        # A–F grade + cbom.cdx.json (CycloneDX 1.6) + SARIF + a report
```

Detects RSA/ECDSA/ECDH/DH (Shor-broken), AES-128/192 + SHA-256 (Grover-weakened), MD5/SHA-1/RC4/3DES/legacy-TLS
(classically broken), and the NIST PQC standards ML-KEM/ML-DSA/SLH-DSA (FIPS 203/204/205) as resistant — and it
flags already-broken PQ candidates (SIKE/SIDH, GeMSS). **Lexical scan — findings are leads to verify, not a complete
inventory, and not a certification.** A scan that examines zero files refuses to grade rather than reporting "A".
Prefer a browser, nothing uploaded? → https://throndar.ai/cbom · CI GitHub Action + a signed Evidence Pack →
https://throndar.ai/evidence

## Sign / verify an Evidence Pack (CLI)

```bash
npx -p @trelyan/verify-pqc pqevidence keygen --out signer --slh
npx -p @trelyan/verify-pqc pqevidence pack ./repo --keys signer.keys.json --org "Acme"   # ML-DSA-87 ∧ SLH-DSA signed
npx -p @trelyan/verify-pqc pqevidence verify evidence-pack.json --pub signer.pub.json --require-hybrid
```

The pack's grade is recomputed from the findings at verify time, so an altered grade fails the signature.

## Verify an on-chain post-quantum inscription

```js
const { verifyOnChain } = require('@trelyan/verify-pqc');
const r = await verifyOnChain('763809096'); // Algorand TestNet app
// { verified: true, signature: { headerHex:'0xba', totalLen:1236, deterministic:true, fmt:'compressed', logn:10 },
//   inscriptionBox: true, sigTxid: 'SQEPDOZ4…' }
```

In the browser, drop in `index.js` and call `verifyPQC.verifyOnChain(appId)` (public CORS-enabled algonode indexer
by default; override with `{ indexer: 'https://…' }`).

## Verify THRONDAR's dual post-quantum signature (in your browser)

THRONDAR signs each transparency-log Signed Tree Head with **two independent PQ families** — **ML-DSA-87** (FIPS-204,
load-bearing) + an additive **SLH-DSA-256f** (FIPS-205, hash-based) diversity leg — checked against **pinned full
public keys**, not the keys the server sends:

```js
import { verifyThrondarStrong } from '@trelyan/verify-pqc/verify';
const j = await (await fetch('https://throndar.ai/api/transparency/ledger')).json();
const v = await verifyThrondarStrong(j.signed_tree_head);
// { verified: true /* ← the ML-DSA-87 result, ONLY */, slhdsa: { slhPresent: true, slhValid: true }, ... }
```

The SLH-DSA leg is **non-authoritative**: `verified` is *exactly* the ML-DSA-87 result — a missing/invalid SLH
co-signature can never flip the verdict. Rotation-ready via `THRONDAR_STH_PINS` (`{current, previous}`). Peer deps:
`@noble/post-quantum` + `@noble/hashes` (independently audited — that audit covers @noble's primitives, NOT this
toolkit, which remains unaudited; pure-JS FIPS-204/205). Conformance KAT: `npm run test:kat`.

## Inspect / compare raw signatures

```js
const { inspectFalconSig, abiDecodeBytes, compareSigs } = require('@trelyan/verify-pqc');
inspectFalconSig(sigBytes);   // { headerHex:'0xba', logn:10, deterministic:true, fmt:'compressed', bodyLen:1235 }
abiDecodeBytes(appArgBytes);  // strips the Algorand ABI byte[] 2-byte length prefix
compareSigs(sigA, sigB);      // localizes the first divergence to header / salt / body
```

## Honest framing (please keep it)

`0xBA` = the standard Falcon-1024 compressed header `0x3A` OR'd with a `0x80` bit and a `0x00` version byte that are
**trelyan-pq's deterministic-wrapper convention — not NIST Round-3 Falcon or FIPS-206 (FN-DSA) fields.**
`verifyOnChain` trusts the single indexer you point at and reads the contract's write-once `i_` box as proof that
`falcon_verify` accepted the signature; it does not re-run the opcode locally. Targets Algorand **TestNet**; the
reference system is **unaudited**. Nothing here is "quantum-safe" or a certification — it's post-quantum tooling you
can read and re-run yourself.

MIT.
