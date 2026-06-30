# TRELYAN PQ — Quickstart (use it in 5 minutes)

How a customer actually *uses* each of the five near-term products. Everything here is **unaudited reference / pilot software** — honestly so: use it to evaluate, integrate, and pilot, not (yet) as a warranted, certified product. An independent cryptographic + side-channel audit is the gate for GA claims (targeted ahead of the Oct-2027 full deploy).

```bash
npm install @trelyan/verify-pqc        # or: git clone github.com/brandonjsellam-Releone/verify-pqc
# Node ≥ 18. Peer deps: @noble/post-quantum + @noble/curves + @noble/hashes (independently audited primitives;
# this toolkit — the composition layer — is unaudited reference).
```

A "keyset" everywhere below is a hybrid key bundle `{ ed, mldsa[, slh] }`:
```js
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
const sk = crypto.getRandomValues(new Uint8Array(32));
const keys = { ed: { secretKey: sk, publicKey: ed25519.getPublicKey(sk) }, mldsa: ml_dsa87.keygen(crypto.getRandomValues(new Uint8Array(32))) };
const pub = { ed: keys.ed.publicKey, mldsa: keys.mldsa.publicKey };   // hand the verifier the PUBLIC half
```

---

## 1 · Quantum-Safe Scanner (free) — *what crypto am I running, and how exposed am I?*
**CLI** (scan a repo → CycloneDX CBOM + an A–F grade + a README badge + a GitHub code-scanning SARIF + a migration plan):
```bash
npx pqcbom ./your-repo --plan --sarif --min-grade=B
# writes: cbom.cdx.json · quantum-readiness-report.md · quantum-safe-badge.json · pqcbom.sarif · migration-plan.md
```
**Or in the browser**: the [PQ Trust Sandbox](https://trelyan.foundation/sandbox) — paste an inventory, get the grade live (nothing leaves your machine). *Lexical scan — findings are leads to verify, not a complete inventory.*

## 2 · PQC Evidence Pack — *the signed assessment you hand a regulator or board*
```js
import { buildEvidencePack, signEvidencePack, verifyEvidencePack } from '@trelyan/verify-pqc/pqcbom-report.mjs';
const pack = buildEvidencePack({ scan, meta: { customer: 'Acme', generated_ts: Date.now() } });    // exec summary + A–F grade + findings + roadmap + crosswalk
const signed = signEvidencePack(pack, keys.mldsa.secretKey, keys.mldsa.publicKey);                  // ML-DSA-87 signed (+ optional SLH leg)
verifyEvidencePack(signed, keys.mldsa.publicKey).verified;   // RECOMPUTES the grade — a forged "grade A" over broken findings fails.
```
The paid deliverable ($7,500 Express). The crosswalk is *informational* ("aligns with CNSA 2.0 / NIS2 / CRA / DORA / PCI"), not a certification.

## 3 · TRELYAN PQ SDK — *verify post-quantum provenance in your app*
```js
import { verifyOnChain } from '@trelyan/verify-pqc';                 // an on-chain Falcon-1024 inscription (Algorand)
const r = await verifyOnChain('763809096');                          // { verified, signature, claim, ... }
import { verifyThrondarStrong } from '@trelyan/verify-pqc/verify';   // a dual-PQ signed tree head, browser-verifiable
```
56 modules; `npm run test:kat` for the conformance vectors. Commercial support license available.

## 4 · QuantumDNA — *issue & verify post-quantum verifiable credentials*
```js
import { makeDid, issueCredential, verifyCredential, present, verifyPresentation } from '@trelyan/verify-pqc/pqvc.mjs';
const subjectDid = makeDid(subjectKeys);                             // did:trelyan, binds all hybrid legs
const vc = issueCredential({ issuerKeys, subjectDid, claims: { role: 'supplier', tier: 'gold' }, id: 'vc-1' });
verifyCredential(vc, issuerPub).verified;                            // true — hybrid-signed, holder-bound, revocation-checkable
// + present(vc, holder, ['role']) → verifyPresentation(vp, issuerPub) for SELECTIVE DISCLOSURE:
//   reveal only 'role', prove 'tier' was in the signed credential, leak nothing about it (+ holder proof-of-possession).
```

## 5 · QuantumShield — *sign firmware; devices verify before they flash*
```js
import { signFirmware, verifyFirmware } from '@trelyan/verify-pqc/pqfirmware.mjs';
const manifest = signFirmware({ vendorKeys, deviceModel: 'Sensor-A', version: 7, buildId: 'b7', artifactBytes: fw });
// on the device, BEFORE flashing — binds the actual binary + refuses a rollback to an older signed version:
verifyFirmware(manifest, vendorPub, { artifactBytes: fw, currentVersion: 6, deviceModel: 'Sensor-A' }).verified; // true
```

---
### Also in the box (same hybrid-signed, fail-closed pattern)
`pqshield` (signed quantum-risk posture report — grade recomputed by the verifier) · `pqcap` (least-privilege agent capability tokens) · `pqadmit` (signed app cert + deploy admission) · `pqconsent` (self-sovereign consent receipts) · `pqpay` (payment-authorization signing — *not* money movement).

**Honest line:** every component is an unaudited reference implementation; claims are tamper-evident/downgrade-detecting **under the declared trust model**, never "unbreakable" or "certified." Verify, don't trust — the primitives are independently checkable, and that's the point.
